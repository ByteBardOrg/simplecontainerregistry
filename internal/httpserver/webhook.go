package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"simplecontainerregistry/internal/db"
	"simplecontainerregistry/internal/domain"
)

const registryWebhookQueueSize = 128

type registryWebhookDispatcher struct {
	store  *db.Store
	logger *slog.Logger
	client *http.Client
	events chan domain.AuditEvent
}

type registryWebhookPayload struct {
	ID          string    `json:"id"`
	Event       string    `json:"event"`
	Group       string    `json:"group"`
	TargetType  string    `json:"targetType"`
	TargetID    string    `json:"targetId"`
	ActorUserID *string   `json:"actorUserId,omitempty"`
	Result      string    `json:"result"`
	IPAddress   string    `json:"ipAddress"`
	UserAgent   string    `json:"userAgent"`
	CreatedAt   time.Time `json:"createdAt"`
}

func newRegistryWebhookDispatcher(store *db.Store, logger *slog.Logger) *registryWebhookDispatcher {
	dispatcher := &registryWebhookDispatcher{
		store:  store,
		logger: logger,
		client: &http.Client{Timeout: 2 * time.Second},
		events: make(chan domain.AuditEvent, registryWebhookQueueSize),
	}
	go dispatcher.run()
	return dispatcher
}

func (d *registryWebhookDispatcher) Enqueue(event domain.AuditEvent) {
	if _, ok := registryWebhookGroup(event.Action); !ok {
		return
	}
	select {
	case d.events <- event:
	default:
		d.logger.Warn("registry webhook queue full; dropping event", "action", event.Action, "target", event.TargetID)
	}
}

func (d *registryWebhookDispatcher) run() {
	for event := range d.events {
		d.deliver(event)
	}
}

func (d *registryWebhookDispatcher) deliver(event domain.AuditEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	settings, err := d.store.RegistryWebhookSettings(ctx)
	if err != nil {
		d.logger.Warn("failed to load registry webhook settings", "error", err)
		return
	}
	if settings.URL == "" {
		return
	}
	group, ok := registryWebhookGroup(event.Action)
	if !ok {
		return
	}
	payload, err := json.Marshal(registryWebhookPayload{
		ID:          event.ID,
		Event:       event.Action,
		Group:       group,
		TargetType:  event.TargetType,
		TargetID:    event.TargetID,
		ActorUserID: event.ActorUserID,
		Result:      event.Result,
		IPAddress:   event.IPAddress,
		UserAgent:   event.UserAgent,
		CreatedAt:   event.CreatedAt,
	})
	if err != nil {
		d.logger.Warn("failed to encode registry webhook payload", "error", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.URL, bytes.NewReader(payload))
	if err != nil {
		d.logger.Warn("failed to create registry webhook request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "simplecontainerregistry-webhook")

	resp, err := d.client.Do(req)
	if err != nil {
		d.logger.Warn("failed to deliver registry webhook", "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		d.logger.Warn("registry webhook returned non-success status", "status", resp.StatusCode)
	}
}

func registryWebhookGroup(action string) (string, bool) {
	switch {
	case action == "repository.deleted":
		return "registry.delete", true
	case strings.HasPrefix(action, "registry.") && strings.HasSuffix(action, ".pulled"):
		return "registry.pull", true
	case strings.HasPrefix(action, "registry.") && strings.HasSuffix(action, ".pushed"):
		return "registry.push", true
	case strings.HasPrefix(action, "registry.") && strings.HasSuffix(action, ".deleted"):
		return "registry.delete", true
	default:
		return "", false
	}
}
