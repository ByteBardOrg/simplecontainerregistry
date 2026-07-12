package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"simplecontainerregistry/internal/domain"
)

func TestStoreUserGrantFlow(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	now := time.Now().UTC().Truncate(time.Second)
	notBefore := now.Add(time.Minute)

	user, err := store.CreateUser(ctx, CreateUserParams{Username: "alice", DisplayName: "Alice", Role: domain.RoleReader, SecretHash: "hash", NotBefore: &notBefore}, now)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if _, err := store.CreateGrant(ctx, CreateGrantParams{SubjectType: "user", SubjectID: user.ID, RepositoryPrefix: "team-a/", Actions: []domain.Action{domain.ActionPull}}, now); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	created, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}
	if created.NotBefore == nil || !created.NotBefore.Equal(notBefore) {
		t.Fatalf("expected notBefore %s, got %#v", notBefore, created.NotBefore)
	}
	grants, err := store.ListGrantsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListGrantsByUser() error = %v", err)
	}
	if len(grants) != 1 || grants[0].RepositoryPrefix != "team-a/" {
		t.Fatalf("unexpected grants: %#v", grants)
	}
}

func TestStoreRepositoryReadModelFlow(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	now := time.Now().UTC().Truncate(time.Second)

	if err := store.UpsertRepositoryTag(ctx, UpsertRepositoryTagParams{
		RepositoryName: "team-a/app",
		Tag:            "latest",
		Digest:         "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		MediaType:      "application/vnd.oci.image.manifest.v1+json",
		SizeBytes:      123,
	}, now); err != nil {
		t.Fatalf("UpsertRepositoryTag() error = %v", err)
	}
	if err := store.UpsertRepositoryTag(ctx, UpsertRepositoryTagParams{
		RepositoryName: "team-a/app",
		Tag:            "stable",
		Digest:         "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		MediaType:      "application/vnd.oci.image.manifest.v1+json",
		SizeBytes:      456,
	}, now.Add(time.Minute)); err != nil {
		t.Fatalf("UpsertRepositoryTag(stable) error = %v", err)
	}
	if err := store.MarkRepositoryPulled(ctx, "team-a/app", "latest", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("MarkRepositoryPulled() error = %v", err)
	}
	if err := store.IncrementUsageCounter(ctx, "team-a/app", domain.ActionPull, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("IncrementUsageCounter(pull) error = %v", err)
	}

	repository, err := store.GetRepository(ctx, "team-a/app")
	if err != nil {
		t.Fatalf("GetRepository() error = %v", err)
	}
	if repository.TagCount != 2 || repository.ManifestCount != 2 || repository.SizeBytes != 579 {
		t.Fatalf("unexpected repository summary: %#v", repository)
	}
	if repository.LastPullAt == nil {
		t.Fatal("expected repository last pull timestamp")
	}

	tags, err := store.ListRepositoryTags(ctx, "team-a/app")
	if err != nil {
		t.Fatalf("ListRepositoryTags() error = %v", err)
	}
	if len(tags) != 2 {
		t.Fatalf("expected two tags, got %d", len(tags))
	}
	if tags[0].Tag != "stable" {
		t.Fatalf("expected newest pushed tag first, got %#v", tags[0])
	}
	if tags[1].Tag != "latest" || tags[1].PulledAt == nil {
		t.Fatalf("expected latest tag with pull timestamp second, got %#v", tags[1])
	}

	summary, err := store.DashboardSummary(ctx, now.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("DashboardSummary() error = %v", err)
	}
	if summary.Repositories != 1 || summary.Tags != 2 || summary.StorageBytes != 579 || summary.Pulls24h != 1 {
		t.Fatalf("unexpected dashboard summary: %#v", summary)
	}

	if err := store.IncrementUsageCounter(ctx, "team-a/app", domain.ActionPush, now.Add(25*time.Hour)); err != nil {
		t.Fatalf("IncrementUsageCounter(push) error = %v", err)
	}
	series, err := store.DailyUsage(ctx, now.Add(26*time.Hour), 7)
	if err != nil {
		t.Fatalf("DailyUsage() error = %v", err)
	}
	if len(series) != 7 {
		t.Fatalf("expected 7 daily usage buckets, got %d", len(series))
	}
	var pulls, pushes int
	for _, day := range series {
		pulls += day.Pulls
		pushes += day.Pushes
	}
	if pulls != 1 || pushes != 1 {
		t.Fatalf("expected one pull and one push in series, got pulls=%d pushes=%d series=%#v", pulls, pushes, series)
	}
}

func TestStoreGCSettings(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	fallback := domain.GCSettings{Enabled: true, Delay: time.Hour, Interval: 24 * time.Hour}

	settings, err := store.GCSettings(ctx, fallback)
	if err != nil {
		t.Fatalf("GCSettings(fallback) error = %v", err)
	}
	if settings != fallback {
		t.Fatalf("expected fallback settings, got %#v", settings)
	}

	updated := domain.GCSettings{Enabled: false, Delay: 30 * time.Minute, Interval: 2 * time.Hour}
	if err := store.UpdateGCSettings(ctx, updated, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateGCSettings() error = %v", err)
	}
	settings, err = store.GCSettings(ctx, fallback)
	if err != nil {
		t.Fatalf("GCSettings(updated) error = %v", err)
	}
	if settings != updated {
		t.Fatalf("expected updated settings, got %#v", settings)
	}
}

func TestStoreRegistryWebhookSettings(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)

	settings, err := store.RegistryWebhookSettings(ctx)
	if err != nil {
		t.Fatalf("RegistryWebhookSettings(default) error = %v", err)
	}
	if settings.URL != "" {
		t.Fatalf("expected empty default webhook URL, got %#v", settings)
	}

	updated := domain.RegistryWebhookSettings{URL: "https://example.com/scr-events"}
	if err := store.UpdateRegistryWebhookSettings(ctx, updated, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateRegistryWebhookSettings() error = %v", err)
	}
	settings, err = store.RegistryWebhookSettings(ctx)
	if err != nil {
		t.Fatalf("RegistryWebhookSettings(updated) error = %v", err)
	}
	if settings != updated {
		t.Fatalf("expected updated settings, got %#v", settings)
	}
}

func openTestStore(t *testing.T, ctx context.Context) *Store {
	t.Helper()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	return store
}
