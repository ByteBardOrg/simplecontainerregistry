package httpserver

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"simplecontainerregistry/internal/auth"
	"simplecontainerregistry/internal/db"
	"simplecontainerregistry/internal/domain"
	"simplecontainerregistry/internal/storage"
)

const adminCookieName = "scr_admin"

var uiTemplates = template.Must(template.New("ui").Funcs(template.FuncMap{
	"time": func(value *time.Time) string {
		if value == nil {
			return "-"
		}
		return value.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"timeValue": func(value time.Time) string {
		return value.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"datetimeLocal": func(value *time.Time) string {
		if value == nil {
			return ""
		}
		return value.UTC().Format("2006-01-02")
	},
	"bytes": func(value int64) string {
		units := []string{"B", "KB", "MB", "GB", "TB"}
		amount := float64(value)
		unit := 0
		for amount >= 1024 && unit < len(units)-1 {
			amount /= 1024
			unit++
		}
		if unit == 0 {
			return fmt.Sprintf("%d %s", value, units[unit])
		}
		return fmt.Sprintf("%.1f %s", amount, units[unit])
	},
	"shortDigest": func(value string) string {
		if len(value) <= 24 {
			return value
		}
		prefix, suffix, ok := strings.Cut(value, ":")
		if !ok || len(suffix) <= 16 {
			return value[:24] + "..."
		}
		return prefix + ":" + suffix[:16] + "..."
	},
	"duration": func(value time.Duration) string { return value.String() },
	"actions": func(actions []domain.Action) string {
		parts := make([]string, 0, len(actions))
		for _, action := range actions {
			parts = append(parts, string(action))
		}
		return strings.Join(parts, ", ")
	},
	"grantPrefix": func(grant *domain.Grant) string {
		if grant == nil {
			return "*"
		}
		return grant.RepositoryPrefix
	},
	"grantHasAction": func(grant *domain.Grant, action string) bool {
		if grant == nil {
			return action == string(domain.ActionPull)
		}
		for _, existing := range grant.Actions {
			if string(existing) == action {
				return true
			}
		}
		return false
	},
	"initials": func(username, displayName string) string {
		name := strings.TrimSpace(displayName)
		if name == "" {
			name = username
		}
		parts := strings.Fields(name)
		if len(parts) == 0 {
			return "?"
		}
		if len(parts) == 1 {
			return strings.ToUpper(string([]rune(parts[0])[0]))
		}
		return strings.ToUpper(string([]rune(parts[0])[0]) + string([]rune(parts[1])[0]))
	},
	"actionIcon": func(action string) string {
		switch {
		case strings.Contains(action, "pushed") || strings.Contains(action, "push"):
			return "cloud_upload"
		case strings.Contains(action, "pulled") || strings.Contains(action, "pull"):
			return "cloud_download"
		case strings.Contains(action, "login") || strings.Contains(action, "token"):
			return "login"
		case strings.Contains(action, "user"):
			return "person"
		case strings.Contains(action, "grant"):
			return "security"
		default:
			return "settings"
		}
	},
	"resultClass": func(result string) string {
		if result == "success" {
			return "badge success"
		}
		return "badge error"
	},
}).Parse(uiTemplateText))

type uiPage struct {
	Title            string
	Active           string
	Error            string
	IssuedUserSecret *issuedUserSecretView
	Summary          domain.DashboardSummary
	Traffic          []trafficDayView
	TrafficTotal     int
	Users            []userAccessView
	Repos            []repositoryView
	SearchQuery      string
	ActionFilter     string
	GCSettings       domain.GCSettings
	AuditEvents      []auditEventView
}

type issuedUserSecretView struct {
	Username  string
	Secret    string
	NotBefore *time.Time
	ExpiresAt *time.Time
}

type userAccessView struct {
	User          domain.User
	Grant         *domain.Grant
	AccessStatus  string
	AccessClass   string
	AccessDetails string
	IsCurrentUser bool
}

type repositoryView struct {
	Repository domain.Repository
	Tags       []domain.RepositoryTag
	Namespace  string
	Name       string
}

type auditEventView struct {
	Event  domain.AuditEvent
	Actor  string
	Target string
}

type trafficDayView struct {
	Label      string
	Pulls      int
	Pushes     int
	PullHeight int
	PushHeight int
}

func (s *Server) handleUIRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/v2/", http.StatusFound)
}

func (s *Server) handleUITrailingSlash(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/ui", http.StatusFound)
}

func (s *Server) handleUILogin(w http.ResponseWriter, r *http.Request) {
	s.renderUI(w, "login", uiPage{Title: "Sign In"})
}

func (s *Server) handleUILoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderUI(w, "login", uiPage{Title: "Sign In", Error: "Invalid form submission"})
		return
	}
	now := time.Now().UTC()
	authenticated, err := s.users.Authenticate(r.Context(), r.FormValue("username"), r.FormValue("password"), now)
	if err != nil || authenticated.User.Role != domain.RoleAdmin {
		if auditErr := s.auditAnonymous(r, "ui.login.denied", "username", r.FormValue("username"), "invalid_credentials"); auditErr != nil {
			s.logger.Error("failed to write audit event", "error", auditErr)
		}
		s.renderUI(w, "login", uiPage{Title: "Sign In", Error: "Invalid admin credentials"})
		return
	}

	token, expiresAt, err := s.tokens.Mint(r.Context(), authenticated.User, nil, now)
	if err != nil {
		s.renderUI(w, "login", uiPage{Title: "Sign In", Error: "Failed to create session"})
		return
	}
	if err := s.auditWithActor(r, auth.Principal{
		UserID:   authenticated.User.ID,
		Username: authenticated.User.Username,
		Role:     authenticated.User.Role,
	}, "ui.login", "user", authenticated.User.ID, "success"); err != nil {
		s.logger.Error("failed to write audit event", "error", err)
		s.renderUI(w, "login", uiPage{Title: "Sign In", Error: "Failed to audit session"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/ui", http.StatusFound)
}

func (s *Server) handleUILogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/ui/login", http.StatusFound)
}

func (s *Server) handleUIDashboard(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	summary, err := s.store.DashboardSummary(r.Context(), now)
	if err != nil {
		s.renderUI(w, "dashboard", uiPage{Title: "Dashboard", Active: "dashboard", Error: "Failed to load dashboard"})
		return
	}
	usage, err := s.store.DailyUsage(r.Context(), now, 7)
	if err != nil {
		s.renderUI(w, "dashboard", uiPage{Title: "Dashboard", Active: "dashboard", Summary: summary, Error: "Failed to load traffic counters"})
		return
	}
	traffic, total := buildTrafficView(usage)
	s.renderUI(w, "dashboard", uiPage{Title: "Dashboard", Active: "dashboard", Summary: summary, Traffic: traffic, TrafficTotal: total})
}

func buildTrafficView(usage []domain.DailyUsage) ([]trafficDayView, int) {
	maxCount := 0
	total := 0
	for _, day := range usage {
		if day.Pulls > maxCount {
			maxCount = day.Pulls
		}
		if day.Pushes > maxCount {
			maxCount = day.Pushes
		}
		total += day.Pulls + day.Pushes
	}
	views := make([]trafficDayView, 0, len(usage))
	for _, day := range usage {
		views = append(views, trafficDayView{
			Label:      day.Date.Format("Mon"),
			Pulls:      day.Pulls,
			Pushes:     day.Pushes,
			PullHeight: trafficHeight(day.Pulls, maxCount),
			PushHeight: trafficHeight(day.Pushes, maxCount),
		})
	}
	return views, total
}

func trafficHeight(value, maxValue int) int {
	if value <= 0 || maxValue <= 0 {
		return 0
	}
	height := value * 100 / maxValue
	if height < 8 {
		return 8
	}
	return height
}

func (s *Server) handleUIRepositories(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	repos, err := s.loadRepositoryViews(r, query)
	if err != nil {
		s.renderUI(w, "repositories", uiPage{Title: "Repositories", Active: "repositories", SearchQuery: query, Error: "Failed to load repositories"})
		return
	}
	s.renderUI(w, "repositories", uiPage{Title: "Repositories", Active: "repositories", Repos: repos, SearchQuery: query})
}

func (s *Server) handleUIRepositoryTagDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderRepositoriesWithError(w, r, "Invalid form submission")
		return
	}
	repository := r.FormValue("repository")
	tag := r.FormValue("tag")
	if repository == "" || tag == "" {
		s.renderRepositoriesWithError(w, r, "Repository and tag are required")
		return
	}
	if err := s.deleteManifestReference(r.Context(), repository, tag); err != nil {
		s.renderRepositoriesWithError(w, r, "Failed to delete tag")
		return
	}
	if err := s.audit(r, "registry.manifest.deleted", "repository", repository, "success"); err != nil {
		s.renderRepositoriesWithError(w, r, "Failed to write audit event")
		return
	}
	http.Redirect(w, r, "/ui/repositories", http.StatusFound)
}

func (s *Server) handleUIRepositoryDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderRepositoriesWithError(w, r, "Invalid form submission")
		return
	}
	repository := r.FormValue("repository")
	if repository == "" {
		s.renderRepositoriesWithError(w, r, "Repository is required")
		return
	}
	tags, err := s.store.ListRepositoryTags(r.Context(), repository)
	if err != nil {
		s.renderRepositoriesWithError(w, r, "Failed to load repository tags")
		return
	}
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		if seen[tag.Digest] {
			continue
		}
		seen[tag.Digest] = true
		if err := s.deleteManifestReference(r.Context(), repository, tag.Digest); err != nil && !errors.Is(err, storage.ErrNotFound) {
			s.renderRepositoriesWithError(w, r, "Failed to delete repository")
			return
		}
	}
	if len(tags) == 0 {
		if err := s.store.DeleteRepository(r.Context(), repository); err != nil && !errors.Is(err, db.ErrNotFound) {
			s.renderRepositoriesWithError(w, r, "Failed to delete repository")
			return
		}
	}
	if err := s.audit(r, "repository.deleted", "repository", repository, "success"); err != nil {
		s.renderRepositoriesWithError(w, r, "Failed to write audit event")
		return
	}
	http.Redirect(w, r, "/ui/repositories", http.StatusFound)
}

func (s *Server) renderRepositoriesWithError(w http.ResponseWriter, r *http.Request, message string) {
	query := strings.TrimSpace(r.FormValue("q"))
	if query == "" {
		query = strings.TrimSpace(r.URL.Query().Get("q"))
	}
	repos, err := s.loadRepositoryViews(r, query)
	if err != nil {
		message = "Failed to load repositories"
	}
	s.renderUI(w, "repositories", uiPage{Title: "Repositories", Active: "repositories", Error: message, Repos: repos, SearchQuery: query})
}

func (s *Server) loadRepositoryViews(r *http.Request, query string) ([]repositoryView, error) {
	repositories, err := s.store.ListRepositories(r.Context())
	if err != nil {
		return nil, err
	}
	query = strings.ToLower(strings.TrimSpace(query))
	views := make([]repositoryView, 0, len(repositories))
	for _, repository := range repositories {
		tags, err := s.store.ListRepositoryTags(r.Context(), repository.Name)
		if err != nil {
			return nil, err
		}
		if query != "" && !repositoryMatchesQuery(repository, tags, query) {
			continue
		}
		namespace, name := splitRepositoryName(repository.Name)
		views = append(views, repositoryView{Repository: repository, Tags: tags, Namespace: namespace, Name: name})
	}
	return views, nil
}

func repositoryMatchesQuery(repository domain.Repository, tags []domain.RepositoryTag, query string) bool {
	if strings.Contains(strings.ToLower(repository.Name), query) {
		return true
	}
	namespace, name := splitRepositoryName(repository.Name)
	if strings.Contains(strings.ToLower(namespace), query) || strings.Contains(strings.ToLower(name), query) {
		return true
	}
	for _, tag := range tags {
		if strings.Contains(strings.ToLower(tag.Tag), query) || strings.Contains(strings.ToLower(tag.Digest), query) {
			return true
		}
	}
	return false
}

func splitRepositoryName(repository string) (string, string) {
	idx := strings.LastIndex(repository, "/")
	if idx < 0 {
		return "", repository
	}
	return repository[:idx], repository[idx+1:]
}

func (s *Server) handleUIUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.loadUserAccess(r)
	if err != nil {
		s.renderUI(w, "users", uiPage{Title: "Users", Active: "users", Error: "Failed to load users"})
		return
	}
	s.renderUI(w, "users", uiPage{Title: "Users", Active: "users", Users: users})
}

func (s *Server) handleUIUsersCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderUsersWithError(w, r, "Invalid form submission")
		return
	}
	role := domain.RoleReader
	notBefore, err := parseOptionalDatetimeLocal(r.FormValue("notBefore"))
	if err != nil {
		s.renderUsersWithError(w, r, "Invalid valid-from timestamp")
		return
	}
	expiresAt, err := parseOptionalDatetimeLocal(r.FormValue("expiresAt"))
	if err != nil {
		s.renderUsersWithError(w, r, "Invalid expiry timestamp")
		return
	}
	if notBefore != nil && expiresAt != nil && !expiresAt.After(*notBefore) {
		s.renderUsersWithError(w, r, "Expires at must be after valid from")
		return
	}
	now := time.Now().UTC()
	user, secret, err := s.users.CreateUser(r.Context(), db.CreateUserParams{
		Username:    r.FormValue("username"),
		DisplayName: r.FormValue("displayName"),
		Role:        role,
		NotBefore:   notBefore,
		ExpiresAt:   expiresAt,
	}, now)
	if err != nil {
		s.renderUsersWithError(w, r, err.Error())
		return
	}
	if err := s.audit(r, "user.created", "user", user.ID, "success"); err != nil {
		s.renderUsersWithError(w, r, "Failed to write audit event")
		return
	}
	grant, err := s.store.ReplaceUserGrant(r.Context(), db.CreateGrantParams{SubjectType: "user", SubjectID: user.ID, RepositoryPrefix: "*", Actions: []domain.Action{domain.ActionPull}}, now)
	if err != nil {
		s.renderUsersWithError(w, r, err.Error())
		return
	}
	if err := s.audit(r, "grant.created", "grant", grant.ID, "success"); err != nil {
		s.renderUsersWithError(w, r, "Failed to write audit event")
		return
	}
	users, err := s.loadUserAccess(r)
	if err != nil {
		s.renderUsersWithError(w, r, "Failed to load users")
		return
	}
	s.renderUI(w, "users", uiPage{
		Title:  "Users",
		Active: "users",
		Users:  users,
		IssuedUserSecret: &issuedUserSecretView{
			Username:  user.Username,
			Secret:    secret,
			NotBefore: user.NotBefore,
			ExpiresAt: user.ExpiresAt,
		},
	})
}

func (s *Server) handleUIUserAccessUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderUsersWithError(w, r, "Invalid form submission")
		return
	}
	userID := r.PathValue("id")
	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if user.Role == domain.RoleAdmin {
		s.renderUsersWithError(w, r, "Admin users are managed outside this user list")
		return
	}
	notBefore, err := parseOptionalDatetimeLocal(r.FormValue("notBefore"))
	if err != nil {
		s.renderUsersWithError(w, r, "Invalid valid-from timestamp")
		return
	}
	expiresAt, err := parseOptionalDatetimeLocal(r.FormValue("expiresAt"))
	if err != nil {
		s.renderUsersWithError(w, r, "Invalid expiry timestamp")
		return
	}
	prefix := strings.TrimSpace(r.FormValue("repositoryPrefix"))
	if prefix == "" {
		s.renderUsersWithError(w, r, "Repository prefix is required")
		return
	}
	actions := selectedGrantActions(r)
	if len(actions) == 0 {
		s.renderUsersWithError(w, r, "Select at least one grant action")
		return
	}
	if err := s.store.UpdateUserValidity(r.Context(), user.ID, notBefore, expiresAt); err != nil {
		s.renderUsersWithError(w, r, err.Error())
		return
	}
	if err := s.audit(r, "user.validity_updated", "user", user.ID, "success"); err != nil {
		s.renderUsersWithError(w, r, "Failed to write audit event")
		return
	}
	grant, err := s.store.ReplaceUserGrant(r.Context(), db.CreateGrantParams{SubjectType: "user", SubjectID: userID, RepositoryPrefix: prefix, Actions: actions}, time.Now().UTC())
	if err != nil {
		s.renderUsersWithError(w, r, err.Error())
		return
	}
	if err := s.audit(r, "grant.updated", "grant", grant.ID, "success"); err != nil {
		s.renderUsersWithError(w, r, "Failed to write audit event")
		return
	}
	http.Redirect(w, r, "/ui/users", http.StatusFound)
}

func selectedGrantActions(r *http.Request) []domain.Action {
	allowed := map[string]domain.Action{"pull": domain.ActionPull, "push": domain.ActionPush, "delete": domain.ActionDelete}
	seen := make(map[domain.Action]bool)
	var actions []domain.Action
	for _, raw := range r.Form["actions"] {
		action, ok := allowed[raw]
		if !ok || seen[action] {
			continue
		}
		seen[action] = true
		actions = append(actions, action)
	}
	return actions
}

func (s *Server) handleUIUserDelete(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	principal, ok := principalFromContext(r.Context())
	if ok && principal.UserID == userID {
		s.renderUsersWithError(w, r, "Cannot delete the currently signed-in admin user")
		return
	}
	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if user.Role == domain.RoleAdmin {
		s.renderUsersWithError(w, r, "Admin users are managed outside this user list")
		return
	}
	if err := s.store.DeleteUser(r.Context(), userID); err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.audit(r, "user.deleted", "user", userID, "success"); err != nil {
		s.renderUsersWithError(w, r, "Failed to write audit event")
		return
	}
	http.Redirect(w, r, "/ui/users", http.StatusFound)
}

func (s *Server) renderUsersWithError(w http.ResponseWriter, r *http.Request, message string) {
	users, err := s.loadUserAccess(r)
	if err != nil {
		message = "Failed to load users"
	}
	s.renderUI(w, "users", uiPage{Title: "Users", Active: "users", Error: message, Users: users})
}

func (s *Server) loadUserAccess(r *http.Request) ([]userAccessView, error) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		return nil, err
	}
	principal, _ := principalFromContext(r.Context())
	now := time.Now().UTC()
	views := make([]userAccessView, 0, len(users))
	for _, user := range users {
		if user.Role == domain.RoleAdmin {
			continue
		}
		view := userAccessView{User: user, IsCurrentUser: principal.UserID == user.ID}
		grants, err := s.store.ListGrantsByUser(r.Context(), user.ID)
		if err != nil {
			return nil, err
		}
		if len(grants) > 0 {
			view.Grant = &grants[0]
		}
		view.AccessStatus, view.AccessClass, view.AccessDetails = accessState(user, now)
		views = append(views, view)
	}
	return views, nil
}

func accessState(user domain.User, now time.Time) (string, string, string) {
	if user.Status != domain.UserStatusActive {
		return "Disabled", "disabled", "User account is disabled"
	}
	if user.NotBefore != nil && user.NotBefore.After(now) {
		return "Pending", "pending", "Valid from " + user.NotBefore.UTC().Format("2006-01-02")
	}
	if user.ExpiresAt != nil && !user.ExpiresAt.After(now) {
		return "Expired", "expired", "Expired " + user.ExpiresAt.UTC().Format("2006-01-02")
	}
	if user.ExpiresAt != nil {
		return "Active", "active", "Expires " + user.ExpiresAt.UTC().Format("2006-01-02")
	}
	return "Active", "active", "No expiry"
}

func parseOptionalDatetimeLocal(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	if parsed, err := time.Parse("2006-01-02", raw); err == nil {
		parsed = parsed.UTC()
		return &parsed, nil
	}
	parsed, err := time.Parse("2006-01-02T15:04", raw)
	if err != nil {
		return nil, err
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func (s *Server) handleUIAudit(w http.ResponseWriter, r *http.Request) {
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	actionFilter := strings.TrimSpace(r.URL.Query().Get("action"))
	events, err := s.store.ListAuditEvents(r.Context(), 100)
	if err != nil {
		s.renderUI(w, "audit", uiPage{Title: "Audit", Active: "audit", SearchQuery: query, ActionFilter: actionFilter, Error: "Failed to load audit events"})
		return
	}
	views := make([]auditEventView, 0, len(events))
	for _, event := range events {
		view := auditEventView{
			Event:  event,
			Actor:  s.auditActorLabel(r, event),
			Target: s.auditTargetLabel(r, event),
		}
		if !auditMatchesAction(view, actionFilter) || !auditMatchesQuery(view, query) {
			continue
		}
		views = append(views, view)
	}
	s.renderUI(w, "audit", uiPage{Title: "Audit", Active: "audit", SearchQuery: query, ActionFilter: actionFilter, AuditEvents: views})
}

func (s *Server) handleUISettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.GCSettings(r.Context(), s.defaultGCSettings())
	if err != nil {
		s.renderUI(w, "settings", uiPage{Title: "Settings", Active: "settings", Error: "Failed to load settings"})
		return
	}
	s.renderUI(w, "settings", uiPage{Title: "Settings", Active: "settings", GCSettings: settings})
}

func (s *Server) handleUIGCSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderSettingsWithError(w, r, "Invalid form submission")
		return
	}
	delay, err := time.ParseDuration(r.FormValue("delay"))
	if err != nil || delay < 0 {
		s.renderSettingsWithError(w, r, "Invalid delete-after duration")
		return
	}
	interval, err := time.ParseDuration(r.FormValue("interval"))
	if err != nil || interval <= 0 {
		s.renderSettingsWithError(w, r, "Invalid run interval")
		return
	}
	settings := domain.GCSettings{Enabled: r.FormValue("enabled") == "on", Delay: delay, Interval: interval}
	if err := s.store.UpdateGCSettings(r.Context(), settings, time.Now().UTC()); err != nil {
		s.renderSettingsWithError(w, r, err.Error())
		return
	}
	if err := s.audit(r, "settings.gc_updated", "settings", "gc", "success"); err != nil {
		s.renderSettingsWithError(w, r, "Failed to write audit event")
		return
	}
	http.Redirect(w, r, "/ui/settings", http.StatusFound)
}

func (s *Server) renderSettingsWithError(w http.ResponseWriter, r *http.Request, message string) {
	settings, err := s.store.GCSettings(r.Context(), s.defaultGCSettings())
	if err != nil {
		settings = s.defaultGCSettings()
	}
	s.renderUI(w, "settings", uiPage{Title: "Settings", Active: "settings", Error: message, GCSettings: settings})
}

func (s *Server) defaultGCSettings() domain.GCSettings {
	return domain.GCSettings{
		Enabled:  s.cfg.Storage.GC,
		Delay:    s.cfg.Storage.GCDelay.Std(),
		Interval: s.cfg.Storage.GCInterval.Std(),
	}
}

func auditMatchesAction(view auditEventView, filter string) bool {
	switch filter {
	case "", "all":
		return true
	case "authentication":
		return strings.Contains(view.Event.Action, "login") || strings.Contains(view.Event.Action, "token")
	case "pull":
		return strings.Contains(view.Event.Action, "pulled") || strings.Contains(view.Event.Action, "pull")
	case "push":
		return strings.Contains(view.Event.Action, "pushed") || strings.Contains(view.Event.Action, "push")
	case "admin":
		return strings.Contains(view.Event.Action, "user.") || strings.Contains(view.Event.Action, "grant.") || strings.Contains(view.Event.Action, "repository.")
	default:
		return view.Event.Action == filter
	}
}

func auditMatchesQuery(view auditEventView, query string) bool {
	if query == "" {
		return true
	}
	fields := []string{
		view.Event.Action,
		view.Event.TargetType,
		view.Event.TargetID,
		view.Event.Result,
		view.Event.IPAddress,
		view.Event.UserAgent,
		view.Actor,
		view.Target,
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

func (s *Server) auditActorLabel(r *http.Request, event domain.AuditEvent) string {
	if event.ActorUserID == nil || *event.ActorUserID == "" {
		return "system"
	}
	user, err := s.store.GetUser(r.Context(), *event.ActorUserID)
	if err != nil {
		return *event.ActorUserID
	}
	return user.Username
}

func (s *Server) auditTargetLabel(r *http.Request, event domain.AuditEvent) string {
	switch event.TargetType {
	case "user":
		user, err := s.store.GetUser(r.Context(), event.TargetID)
		if err == nil {
			return user.Username
		}
	}
	if event.TargetID == "" {
		return "-"
	}
	return event.TargetID
}

func (s *Server) requireUIAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(adminCookieName)
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/ui/login", http.StatusFound)
			return
		}
		principal, err := s.tokens.Validate(r.Context(), cookie.Value)
		if err != nil || principal.Role != domain.RoleAdmin {
			http.Redirect(w, r, "/ui/login", http.StatusFound)
			return
		}
		next(w, r.WithContext(contextWithPrincipal(r.Context(), principal)))
	}
}

func (s *Server) renderUI(w http.ResponseWriter, name string, page uiPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := uiTemplates.ExecuteTemplate(w, name, page); err != nil {
		s.logger.Error("failed to render ui", "template", name, "error", err)
	}
}

const uiTemplateText = `
{{define "shell"}}
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}} - SCR</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700;800;900&family=Inter:wght@400;500;600;700&family=Material+Symbols+Outlined:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root { --background:#faf8ff; --surface:#faf8ff; --surface-low:#f4f3fa; --surface-container:#eeedf4; --surface-high:#e9e7ef; --white:#fff; --ink:#1a1b21; --muted:#444651; --outline:#757682; --line:#c5c5d3; --primary:#00236f; --primary-container:#1e3a8a; --secondary-container:#d0e1fb; --success-bg:#e6f4ea; --success:#137333; --error-bg:#ffdad6; --error:#ba1a1a; --warning-bg:#ffdbcb; --warning:#773205; --radius:8px; --radius-lg:12px; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:var(--background); color:var(--ink); font:14px/1.45 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    a { color:inherit; text-decoration:none; }
    .material-symbols-outlined { font-family:'Material Symbols Outlined'; font-weight:400; font-style:normal; font-size:20px; line-height:1; letter-spacing:normal; text-transform:none; display:inline-block; white-space:nowrap; word-wrap:normal; direction:ltr; -webkit-font-feature-settings:'liga'; -webkit-font-smoothing:antialiased; }
    .sidenav { position:fixed; inset:0 auto 0 0; width:256px; padding:16px; background:var(--surface-low); border-right:1px solid var(--line); display:flex; flex-direction:column; z-index:30; }
    .brand-block { display:flex; align-items:center; gap:8px; padding:8px; margin-bottom:28px; }
    .brand-title { margin:0; color:var(--primary); font:900 24px/1 Geist, sans-serif; }
    .nav-list { display:flex; flex-direction:column; gap:4px; flex:1; }
    .nav-item { display:flex; align-items:center; gap:16px; padding:8px 12px; border-radius:8px; color:var(--muted); font:500 14px/20px Geist, sans-serif; transform:scale(.98); transition:background .12s ease, color .12s ease, transform .12s ease; }
    .nav-item:hover { background:var(--surface-container); color:var(--ink); transform:scale(1); }
    .nav-item.active { background:var(--secondary-container); color:var(--primary); font-weight:700; }
    .main-shell { margin-left:256px; min-height:100vh; background:var(--background); }
    .topbar { position:sticky; top:0; z-index:20; height:64px; display:flex; align-items:center; justify-content:flex-end; gap:16px; padding:0 32px; background:rgba(250,248,255,.88); backdrop-filter:blur(10px); border-bottom:1px solid rgba(197,197,211,.75); }
    .search { position:relative; width:min(520px, 100%); }
    .search .material-symbols-outlined { position:absolute; left:10px; top:50%; transform:translateY(-50%); color:var(--outline); font-size:18px; }
    .search input { width:100%; padding:8px 12px 8px 36px; border:1px solid var(--line); border-radius:999px; background:var(--surface-low); color:var(--ink); font:400 14px/20px Inter, sans-serif; }
    .shell-actions { display:flex; align-items:center; gap:8px; }
    .icon-button, .logout { border:1px solid var(--line); background:var(--white); color:var(--muted); border-radius:8px; min-height:36px; padding:7px 10px; display:inline-flex; align-items:center; gap:8px; cursor:pointer; font:600 12px/16px Geist, sans-serif; }
    .logout:hover, .icon-button:hover { color:var(--primary); border-color:var(--primary); }
    .canvas { max-width:1440px; margin:0 auto; padding:32px; }
    .page-header { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; margin-bottom:24px; }
    .page-title { margin:0; font:600 32px/40px Geist, sans-serif; letter-spacing:-.01em; color:var(--ink); }
    .page-description { margin:4px 0 0; color:var(--muted); font:400 16px/24px Inter, sans-serif; }
    .stat-grid { display:grid; grid-template-columns:repeat(6, minmax(0, 1fr)); gap:16px; margin-bottom:16px; }
    .stat-card, .panel, .table-card { background:var(--surface); border:1px solid var(--line); border-radius:12px; box-shadow:0 4px 12px rgba(0,0,0,.02); }
    .stat-card { padding:16px; min-height:108px; display:flex; flex-direction:column; justify-content:space-between; }
    .stat-head { display:flex; justify-content:space-between; gap:12px; color:var(--muted); font:600 12px/16px Geist, sans-serif; }
    .stat-value { font:500 24px/32px Geist, sans-serif; color:var(--ink); }
    .bento { display:grid; grid-template-columns:2fr 1fr; gap:16px; }
    .panel-head { padding:16px; border-bottom:1px solid rgba(197,197,211,.65); border-radius:12px 12px 0 0; background:var(--surface-low); display:flex; align-items:center; justify-content:space-between; gap:12px; }
    .panel-title { margin:0; font:500 14px/20px Geist, sans-serif; }
    .panel-body { padding:16px; }
    .traffic-bars { height:260px; display:flex; align-items:end; gap:8px; padding-top:24px; }
    .traffic-day { flex:1; display:flex; flex-direction:column; align-items:center; justify-content:end; gap:4px; height:100%; color:var(--muted); font:600 12px/16px Geist, sans-serif; }
    .bar { width:100%; border-radius:4px 4px 0 0; background:var(--primary); min-height:8px; }
    .bar.push { background:var(--secondary-container); }
    .bar.zero { min-height:0; }
    .empty-state { min-height:260px; display:grid; place-items:center; color:var(--muted); text-align:center; }
    .activity-list { display:flex; flex-direction:column; gap:0; }
    .activity-item { display:flex; gap:10px; padding:12px 0; border-bottom:1px solid rgba(197,197,211,.5); }
    .activity-item:last-child { border-bottom:0; }
    .activity-icon { width:28px; height:28px; border-radius:999px; background:var(--surface-high); color:var(--primary); display:grid; place-items:center; flex:0 0 auto; }
    .table-card { overflow:hidden; }
    .table-scroll { overflow-x:auto; }
    table { width:100%; min-width:800px; border-collapse:collapse; text-align:left; }
    thead tr { background:var(--surface-low); border-bottom:1px solid var(--line); }
    th { padding:8px 16px; color:var(--muted); font:600 12px/16px Geist, sans-serif; text-transform:uppercase; letter-spacing:.04em; white-space:nowrap; }
    td { padding:10px 16px; border-bottom:1px solid rgba(197,197,211,.55); vertical-align:middle; min-height:52px; }
    tbody tr:hover { background:rgba(208,225,251,.18); }
    tbody tr:last-child td { border-bottom:0; }
    .mono { font:500 13px/20px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .muted { color:var(--muted); }
    .numeric { text-align:right; color:var(--muted); }
    .user-cell { display:flex; align-items:center; gap:8px; }
    .avatar { width:32px; height:32px; border-radius:999px; display:grid; place-items:center; background:var(--secondary-container); color:var(--primary); font:800 12px/1 Geist, sans-serif; }
    .repo-list { display:flex; flex-direction:column; gap:12px; }
    .repo-card { background:var(--surface); border:1px solid var(--line); border-radius:12px; box-shadow:0 4px 12px rgba(0,0,0,.02); overflow:hidden; }
    .repo-card summary { cursor:pointer; list-style:none; }
    .repo-card summary::-webkit-details-marker { display:none; }
    .repo-summary { display:grid; grid-template-columns:minmax(260px, 1fr) repeat(4, auto); gap:16px; align-items:center; padding:16px; background:var(--surface-low); }
    .repo-name { display:flex; flex-direction:column; gap:2px; }
    .repo-name strong { color:var(--primary); font:700 15px/20px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .repo-namespace { color:var(--outline); font:500 12px/16px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .repo-metric { display:flex; flex-direction:column; gap:2px; min-width:82px; color:var(--muted); font:600 11px/14px Geist, sans-serif; text-transform:uppercase; letter-spacing:.04em; }
    .repo-metric strong { color:var(--ink); font:600 14px/20px Geist, sans-serif; text-transform:none; letter-spacing:0; }
    .repo-body { padding:16px; }
    .repo-body-head { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:12px; }
    .tag-table table { min-width:980px; }
    .tag-table th { cursor:pointer; }
    .tag-table th:hover { color:var(--primary); }
    .tag-name { color:var(--primary); font:700 13px/20px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .tag-delete { width:20px; height:20px; border:0; border-radius:999px; background:var(--error-bg); color:var(--error); cursor:pointer; display:grid; place-items:center; font:700 12px/1 Geist, sans-serif; }
    .grant-list { display:flex; flex-direction:column; gap:8px; min-width:360px; }
    .grant-row { display:flex; align-items:center; justify-content:space-between; gap:8px; padding:8px; border:1px solid var(--line); border-radius:8px; background:var(--white); }
    .grant-prefix { color:var(--primary); font:700 12px/16px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .grant-form { display:grid; grid-template-columns:minmax(140px, 1fr) auto auto; gap:8px; align-items:end; }
    .check-group { display:flex; gap:8px; align-items:center; flex-wrap:wrap; padding-bottom:8px; }
    .check-group label { display:inline-flex; align-items:center; gap:4px; margin:0; }
    .check-group input { width:auto; }
    .user-card-list { display:flex; flex-direction:column; gap:12px; }
    .user-card { background:var(--surface); border:1px solid var(--line); border-radius:12px; box-shadow:0 4px 12px rgba(0,0,0,.02); overflow:hidden; }
    .user-card summary { cursor:pointer; list-style:none; }
    .user-card summary::-webkit-details-marker { display:none; }
    .user-card-summary { display:grid; grid-template-columns:minmax(240px, 1fr) repeat(3, auto); gap:16px; align-items:center; padding:16px; background:var(--surface-low); }
    .user-card-body { padding:16px; }
    .access-grid { display:grid; grid-template-columns:repeat(2, minmax(180px, 1fr)); gap:12px; align-items:end; }
    .access-grid .wide { grid-column:1 / -1; }
    .badge { display:inline-flex; align-items:center; gap:6px; border-radius:999px; padding:2px 8px; font:600 11px/16px Geist, sans-serif; white-space:nowrap; }
    .badge.admin { background:var(--secondary-container); color:var(--primary); }
    .badge.reader { background:var(--surface-container); color:var(--muted); }
    .badge.active, .badge.success { background:var(--success-bg); color:var(--success); }
    .badge.disabled, .badge.expired, .badge.error { background:var(--error-bg); color:var(--error); }
    .badge.pending { background:var(--warning-bg); color:var(--warning); }
    .badge::before { content:""; width:6px; height:6px; border-radius:999px; background:currentColor; }
    .form-card { margin-bottom:16px; padding:16px; background:var(--surface); border:1px solid var(--line); border-radius:12px; box-shadow:0 4px 12px rgba(0,0,0,.02); }
    .form-title { margin:0 0 12px; font:500 16px/24px Geist, sans-serif; }
    .form-grid { display:grid; grid-template-columns:1.2fr 1.2fr .8fr 1fr 1fr auto; gap:12px; align-items:end; }
    label { display:block; margin:0 0 4px; color:var(--muted); font:600 12px/16px Geist, sans-serif; }
    input, select { width:100%; border:1px solid var(--line); border-radius:8px; background:var(--white); color:var(--ink); padding:8px 10px; font:400 14px/20px Inter, sans-serif; }
    input:focus, select:focus { outline:2px solid rgba(0,35,111,.16); border-color:var(--primary); }
    .primary-action, .small-action, .danger-action, .icon-danger-action { border:0; border-radius:8px; color:white; display:inline-flex; align-items:center; justify-content:center; gap:8px; cursor:pointer; font:600 14px/20px Geist, sans-serif; }
    .primary-action, .small-action { background:var(--primary); }
    .danger-action { background:var(--error); padding:8px 12px; min-height:38px; white-space:nowrap; }
    .icon-danger-action { width:38px; min-width:38px; height:38px; background:var(--error); padding:0; }
    .icon-danger-action .material-symbols-outlined { font-size:19px; }
    form:not(#confirm-form)[action="/ui/repositories/delete"] > .danger-action,
    form:not(#confirm-form)[action="/ui/repositories/delete-tag"] > .danger-action,
    form:not(#confirm-form)[action*="/grants/"][action$="/delete"] > .danger-action,
    form:not(#confirm-form)[action^="/ui/users/"][action$="/delete"] > .danger-action { width:38px; min-width:38px; height:38px; padding:0; font-size:0; }
    form:not(#confirm-form)[action="/ui/repositories/delete"] > .danger-action::before,
    form:not(#confirm-form)[action="/ui/repositories/delete-tag"] > .danger-action::before,
    form:not(#confirm-form)[action*="/grants/"][action$="/delete"] > .danger-action::before,
    form:not(#confirm-form)[action^="/ui/users/"][action$="/delete"] > .danger-action::before { content:"delete"; font-family:'Material Symbols Outlined'; font-weight:400; font-size:19px; line-height:1; }
    .primary-action { padding:9px 16px; min-height:40px; }
    .small-action { padding:8px 12px; min-height:38px; white-space:nowrap; }
    .secret-panel { border:1px solid #9ad0a7; background:#eef9f1; border-radius:12px; padding:16px; margin-bottom:16px; }
    .secret-panel h2 { margin:0 0 4px; font:600 18px/28px Geist, sans-serif; }
    .secret-row { display:flex; align-items:stretch; gap:8px; margin:12px 0; }
    .secret { flex:1; min-width:0; display:block; margin:0; padding:12px; background:white; border:1px solid #b8d8c5; border-radius:8px; overflow:auto; font:500 13px/20px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .copy-secret { width:44px; min-width:44px; border:1px solid #b8d8c5; border-radius:8px; background:white; color:var(--primary); cursor:pointer; display:grid; place-items:center; }
    .copy-secret:hover { border-color:var(--primary); background:var(--surface-low); }
    .copy-status { align-self:center; min-width:58px; color:var(--success); font:700 12px/16px Geist, sans-serif; opacity:0; transition:opacity .12s ease; }
    .copy-status.visible { opacity:1; }
    .secret-actions { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .error { margin-bottom:16px; padding:12px 14px; border:1px solid var(--error); background:var(--error-bg); color:var(--error); border-radius:8px; }
    .row-actions { display:flex; gap:8px; align-items:end; flex-wrap:wrap; }
    .filters { display:flex; gap:8px; padding:16px; margin-bottom:16px; background:var(--surface); border:1px solid var(--line); border-radius:12px; }
    .filters .search { width:100%; max-width:none; }
    .modal-backdrop { position:fixed; inset:0; z-index:60; display:none; align-items:center; justify-content:center; padding:16px; background:rgba(26,27,33,.42); }
    .modal-backdrop.open { display:flex; }
    .modal { width:min(460px, 100%); background:var(--white); border:1px solid var(--line); border-radius:16px; box-shadow:0 24px 60px rgba(0,0,0,.22); padding:20px; }
    .modal h2 { margin:0 0 8px; font:700 20px/28px Geist, sans-serif; color:var(--ink); }
    .modal p { margin:0 0 16px; color:var(--muted); }
    .modal-actions { display:flex; justify-content:flex-end; gap:8px; }
    .secondary-action { border:1px solid var(--line); background:var(--white); color:var(--muted); border-radius:8px; padding:8px 12px; min-height:38px; cursor:pointer; font:600 14px/20px Geist, sans-serif; }
    @media (max-width: 1100px) { .stat-grid { grid-template-columns:repeat(3, minmax(0, 1fr)); } .bento { grid-template-columns:1fr; } .form-grid { grid-template-columns:1fr 1fr; } }
    @media (max-width: 800px) { .sidenav { position:static; width:auto; min-height:auto; border-right:0; border-bottom:1px solid var(--line); } .main-shell { margin-left:0; } .topbar { padding:0 16px; } .canvas { padding:16px; } .stat-grid { grid-template-columns:repeat(2, minmax(0, 1fr)); } .page-header { flex-direction:column; } .form-grid { grid-template-columns:1fr; min-width:0; } }
  </style>
</head>
<body>
  <nav class="sidenav">
    <div class="brand-block"><h1 class="brand-title">SCR</h1></div>
    <div class="nav-list">
      <a class="nav-item {{if eq .Active "dashboard"}}active{{end}}" href="/ui"><span class="material-symbols-outlined">dashboard</span>Dashboard</a>
      <a class="nav-item {{if eq .Active "repositories"}}active{{end}}" href="/ui/repositories"><span class="material-symbols-outlined">inventory_2</span>Repositories</a>
      <a class="nav-item {{if eq .Active "users"}}active{{end}}" href="/ui/users"><span class="material-symbols-outlined">group</span>Users</a>
      <a class="nav-item {{if eq .Active "audit"}}active{{end}}" href="/ui/audit"><span class="material-symbols-outlined">history_edu</span>Audit Log</a>
      <a class="nav-item {{if eq .Active "settings"}}active{{end}}" href="/ui/settings"><span class="material-symbols-outlined">settings</span>Settings</a>
    </div>
  </nav>
  <div class="main-shell">
    <header class="topbar">
      <div class="shell-actions"><a class="icon-button" href="/v2/"><span class="material-symbols-outlined">dns</span>Registry API</a><form method="post" action="/ui/logout"><button class="logout" type="submit"><span class="material-symbols-outlined">logout</span>Sign out</button></form></div>
    </header>
    <main class="canvas">
      {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
      {{template "content" .}}
    </main>
  </div>
  <div class="modal-backdrop" id="confirm-modal" aria-hidden="true"><div class="modal" role="dialog" aria-modal="true" aria-labelledby="confirm-title"><h2 id="confirm-title">Are you sure?</h2><p id="confirm-body">This action cannot be undone.</p><form id="confirm-form" method="post"><div id="confirm-fields"></div><div class="modal-actions"><button class="secondary-action" type="button" id="confirm-cancel">Cancel</button><button class="danger-action" type="submit" id="confirm-submit">Delete</button></div></form></div></div>
  <script>
    (() => {
      const modal = document.getElementById('confirm-modal');
      const form = document.getElementById('confirm-form');
      const fields = document.getElementById('confirm-fields');
      const title = document.getElementById('confirm-title');
      const body = document.getElementById('confirm-body');
      const submit = document.getElementById('confirm-submit');
      const cancel = document.getElementById('confirm-cancel');
      if (!modal || !form || !fields || !title || !body || !submit || !cancel) return;

      document.querySelectorAll('form[data-confirm-title]').forEach((source) => {
        source.addEventListener('submit', (event) => {
          event.preventDefault();
          title.textContent = source.dataset.confirmTitle || 'Are you sure?';
          body.textContent = source.dataset.confirmBody || 'This action cannot be undone.';
          submit.textContent = source.dataset.confirmSubmit || 'Delete';
          form.action = source.action;
          form.method = source.method || 'post';
          fields.replaceChildren();
          source.querySelectorAll('input[type="hidden"]').forEach((input) => fields.appendChild(input.cloneNode(true)));
          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
          cancel.focus();
        });
      });

      const close = () => {
        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
        fields.replaceChildren();
      };
      cancel.addEventListener('click', close);
      modal.addEventListener('click', (event) => { if (event.target === modal) close(); });
      document.addEventListener('keydown', (event) => { if (event.key === 'Escape') close(); });
    })();
    (() => {
      document.querySelectorAll('form:not(#confirm-form)[action="/ui/repositories/delete"], form:not(#confirm-form)[action="/ui/repositories/delete-tag"], form:not(#confirm-form)[action*="/grants/"][action$="/delete"], form:not(#confirm-form)[action^="/ui/users/"][action$="/delete"]').forEach((form) => {
        const button = form.querySelector('button.danger-action');
        if (!button) return;
        const label = form.dataset.confirmSubmit || button.textContent.trim() || 'Delete';
        button.title = label;
        button.setAttribute('aria-label', label);
        button.textContent = '';
      });
    })();
    (() => {
      document.querySelectorAll('[data-copy-target]').forEach((button) => {
        button.addEventListener('click', async () => {
          const target = document.querySelector(button.dataset.copyTarget);
          if (!target) return;
          const status = button.parentElement?.querySelector('[data-copy-status]');
          const value = target.textContent.trim();
          try {
            await navigator.clipboard.writeText(value);
            button.title = 'Copied';
            button.setAttribute('aria-label', 'Copied');
            if (status) status.textContent = 'Copied!';
          } catch {
            const range = document.createRange();
            range.selectNodeContents(target);
            const selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
            button.title = 'Selected';
            button.setAttribute('aria-label', 'Selected');
            if (status) status.textContent = 'Selected';
          }
          if (status) status.classList.add('visible');
          setTimeout(() => {
            button.title = 'Copy secret';
            button.setAttribute('aria-label', 'Copy secret');
            if (status) status.classList.remove('visible');
          }, 1600);
        });
      });
    })();
    (() => {
      const parsers = {
        Tag: (value) => value.toLowerCase(),
        Digest: (value) => value.toLowerCase(),
        'Media Type': (value) => value.toLowerCase(),
        Size: (value) => {
          const match = value.match(/^([0-9.]+)\s*(B|KB|MB|GB|TB)$/i);
          if (!match) return 0;
          const units = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 };
          return Number.parseFloat(match[1]) * (units[match[2].toUpperCase()] || 1);
        },
        Pushed: (value) => Date.parse(value) || 0,
        Pulled: (value) => Date.parse(value) || 0,
      };

      document.querySelectorAll('.tag-table table').forEach((table) => {
        const headers = Array.from(table.querySelectorAll('th'));
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        headers.forEach((header, index) => {
          const label = header.textContent.trim();
          if (!parsers[label]) return;
          header.title = 'Sort by ' + label;
          header.addEventListener('click', () => {
            const current = header.dataset.sortDirection || (label === 'Pushed' ? 'desc' : 'asc');
            const next = current === 'asc' ? 'desc' : 'asc';
            headers.forEach((other) => delete other.dataset.sortDirection);
            header.dataset.sortDirection = next;
            const rows = Array.from(tbody.querySelectorAll('tr'));
            rows.sort((left, right) => {
              const leftValue = parsers[label](left.children[index]?.textContent.trim() || '');
              const rightValue = parsers[label](right.children[index]?.textContent.trim() || '');
              if (leftValue < rightValue) return next === 'asc' ? -1 : 1;
              if (leftValue > rightValue) return next === 'asc' ? 1 : -1;
              return 0;
            });
            tbody.replaceChildren(...rows);
          });
        });
      });
    })();
  </script>
</body>
</html>
{{end}}

{{define "login"}}
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign In - SCR</title><link href="https://fonts.googleapis.com/css2?family=Geist:wght@500;600;700;800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet"><style>{{template "login-css"}}</style></head>
<body class="login-page"><form class="login" method="post" action="/ui/login"><h1>SCR</h1><p class="muted">Sign in as an admin user.</p>{{if .Error}}<div class="error">{{.Error}}</div>{{end}}<label for="username">Username</label><input id="username" name="username" autocomplete="username" required autofocus><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button class="primary-action" type="submit">Sign in</button></form></body></html>
{{end}}

{{define "login-css"}}
:root { --background:#faf8ff; --surface:#fff; --ink:#1a1b21; --muted:#444651; --line:#c5c5d3; --primary:#00236f; --error:#ba1a1a; --error-bg:#ffdad6; }
* { box-sizing:border-box; } body { margin:0; font:14px/1.45 Inter, sans-serif; color:var(--ink); } .login-page { min-height:100vh; display:grid; place-items:center; padding:16px; background:linear-gradient(135deg, #faf8ff, #d0e1fb); } .login { width:min(420px, 100%); background:var(--surface); border:1px solid var(--line); border-radius:16px; padding:24px; box-shadow:0 12px 24px rgba(0,0,0,.10); } h1 { margin:0 0 4px; font:700 32px/40px Geist, sans-serif; } .muted { color:var(--muted); margin:0 0 16px; } .error { margin:12px 0; padding:10px 12px; border:1px solid var(--error); background:var(--error-bg); color:var(--error); border-radius:8px; } label { display:block; margin:12px 0 4px; font:600 12px/16px Geist, sans-serif; color:var(--muted); } input { width:100%; border:1px solid var(--line); border-radius:8px; padding:10px; font:inherit; } input:focus { outline:2px solid rgba(0,35,111,.16); border-color:var(--primary); } .primary-action { margin-top:16px; width:100%; min-height:42px; border:0; border-radius:8px; background:var(--primary); color:white; font:700 14px/20px Geist, sans-serif; cursor:pointer; }
{{end}}

{{define "dashboard"}}{{template "shell" .}}{{end}}
{{define "content"}}
  {{if eq .Active "dashboard"}}
    <div class="page-header"><div><h1 class="page-title">Dashboard</h1><p class="page-description">System overview and recent registry activity.</p></div></div>
    <section class="stat-grid">
      <div class="stat-card"><div class="stat-head"><span>Repositories</span><span class="material-symbols-outlined">inventory_2</span></div><div class="stat-value">{{.Summary.Repositories}}</div></div>
      <div class="stat-card"><div class="stat-head"><span>Tags</span><span class="material-symbols-outlined">label</span></div><div class="stat-value">{{.Summary.Tags}}</div></div>
      <div class="stat-card"><div class="stat-head"><span>Storage</span><span class="material-symbols-outlined">hard_drive</span></div><div class="stat-value">{{bytes .Summary.StorageBytes}}</div></div>
      <div class="stat-card"><div class="stat-head"><span>Active Users</span><span class="material-symbols-outlined">group</span></div><div class="stat-value">{{.Summary.ActiveUsers}}</div></div>
      <div class="stat-card"><div class="stat-head"><span>Pulls (24h)</span><span class="material-symbols-outlined">download</span></div><div class="stat-value">{{.Summary.Pulls24h}}</div></div>
      <div class="stat-card"><div class="stat-head"><span>Pushes (24h)</span><span class="material-symbols-outlined">upload</span></div><div class="stat-value">{{.Summary.Pushes24h}}</div></div>
    </section>
    <section class="bento"><div class="panel"><div class="panel-head"><h2 class="panel-title">Network Traffic (7 Days)</h2><span class="muted">Pull and push counters</span></div><div class="panel-body">{{if gt .TrafficTotal 0}}<div class="traffic-bars">{{range .Traffic}}<div class="traffic-day" title="{{.Label}}: {{.Pulls}} pulls, {{.Pushes}} pushes"><div class="bar {{if eq .Pulls 0}}zero{{end}}" style="height:{{.PullHeight}}%"></div><div class="bar push {{if eq .Pushes 0}}zero{{end}}" style="height:{{.PushHeight}}%"></div><span>{{.Label}}</span></div>{{end}}</div>{{else}}<div class="empty-state"><div><strong>No registry traffic yet</strong><br><span>Push or pull an image to populate this chart.</span></div></div>{{end}}</div></div><div class="panel"><div class="panel-head"><h2 class="panel-title">Access Health</h2></div><div class="panel-body activity-list"><div class="activity-item"><div class="activity-icon"><span class="material-symbols-outlined">vpn_key</span></div><div><strong>{{.Summary.UsersExpiringSoon}}</strong> users expiring soon<p class="muted">Next 14 days</p></div></div><div class="activity-item"><div class="activity-icon"><span class="material-symbols-outlined">dns</span></div><div><strong>{{.Summary.Repositories}}</strong> repositories tracked<p class="muted">Read model from registry writes</p></div></div></div></div></section>
  {{else if eq .Active "repositories"}}
    <div class="page-header"><div><h1 class="page-title">Image Repositories</h1><p class="page-description">Browse pushed images, inspect tags, and remove stale image references.</p></div></div>
    <form class="filters" method="get" action="/ui/repositories"><div class="search"><span class="material-symbols-outlined">search</span><input name="q" value="{{.SearchQuery}}" placeholder="Search repositories, namespaces, tags, or digests" aria-label="Search repositories"></div><button class="small-action" type="submit">Search</button>{{if .SearchQuery}}<a class="secondary-action" href="/ui/repositories">Clear</a>{{end}}</form>
    <div class="repo-list">{{range .Repos}}<details class="repo-card"><summary><div class="repo-summary"><div class="repo-name">{{if .Namespace}}<span class="repo-namespace">namespace: {{.Namespace}}</span>{{end}}<strong>{{.Repository.Name}}</strong></div><div class="repo-metric"><span>Tags</span><strong>{{.Repository.TagCount}}</strong></div><div class="repo-metric"><span>Manifests</span><strong>{{.Repository.ManifestCount}}</strong></div><div class="repo-metric"><span>Size</span><strong>{{bytes .Repository.SizeBytes}}</strong></div><div class="repo-metric"><span>Last Push</span><strong>{{time .Repository.LastPushAt}}</strong></div></div></summary><div class="repo-body"><div class="repo-body-head"><div><strong>Tag references</strong><p class="muted">Deleting a tag removes only that tag reference. It does not delete the manifest content; untagged manifests can be cleaned by garbage collection when that exists.</p></div><form method="post" action="/ui/repositories/delete" data-confirm-title="Delete image repository {{.Repository.Name}}?" data-confirm-body="This removes all tag references and tagged manifests for this exact image repository only. It does not delete other image repositories that share the same namespace prefix." data-confirm-submit="Delete image repository"><input type="hidden" name="repository" value="{{.Repository.Name}}"><button class="danger-action" type="submit">Delete image repository</button></form></div>{{if .Tags}}<div class="table-scroll tag-table"><table><thead><tr><th>Tag</th><th>Digest</th><th>Media Type</th><th class="numeric">Size</th><th>Pushed</th><th>Pulled</th><th>Action</th></tr></thead><tbody>{{range .Tags}}<tr><td class="tag-name">{{.Tag}}</td><td class="mono" title="{{.Digest}}">{{shortDigest .Digest}}</td><td class="muted">{{.MediaType}}</td><td class="numeric">{{bytes .SizeBytes}}</td><td class="muted">{{timeValue .PushedAt}}</td><td class="muted">{{time .PulledAt}}</td><td><form method="post" action="/ui/repositories/delete-tag" data-confirm-title="Delete tag {{.Tag}}?" data-confirm-body="This removes only the tag reference {{.RepositoryName}}:{{.Tag}}. It does not delete the manifest content or other tags that point at the same digest." data-confirm-submit="Delete tag"><input type="hidden" name="repository" value="{{.RepositoryName}}"><input type="hidden" name="tag" value="{{.Tag}}"><button class="danger-action" type="submit">Delete tag</button></form></td></tr>{{end}}</tbody></table></div>{{else}}<div class="empty-state"><div><strong>No tag references</strong><br><span>This image repository has no tags in the read model.</span></div></div>{{end}}</div></details>{{else}}<div class="table-card"><div class="empty-state"><div><strong>{{if .SearchQuery}}No repositories match this search{{else}}No repositories yet{{end}}</strong><br><span>{{if .SearchQuery}}Try a different repository, namespace, tag, or digest.{{else}}Push an image to populate this page.{{end}}</span></div></div></div>{{end}}</div>
  {{else if eq .Active "users"}}
    <div class="page-header"><div><h1 class="page-title">Users</h1><p class="page-description">Create and manage registry users. Each user signs in directly with the secret shown at creation time.</p></div></div>
    {{if .IssuedUserSecret}}<section class="secret-panel"><h2>User created: {{.IssuedUserSecret.Username}}</h2><p class="muted">Copy this secret now. It is shown once and only the hash is stored.</p><div class="secret-row"><code class="secret" id="issued-secret">{{.IssuedUserSecret.Secret}}</code><button class="copy-secret" type="button" data-copy-target="#issued-secret" title="Copy secret" aria-label="Copy secret"><span class="material-symbols-outlined">content_copy</span></button><span class="copy-status" data-copy-status aria-live="polite"></span></div><div class="secret-actions"><p class="muted">Username: {{.IssuedUserSecret.Username}} · Valid from: {{if .IssuedUserSecret.NotBefore}}{{time .IssuedUserSecret.NotBefore}}{{else}}immediately{{end}} · Expires: {{if .IssuedUserSecret.ExpiresAt}}{{time .IssuedUserSecret.ExpiresAt}}{{else}}never{{end}}</p></div></section>{{end}}
    <section class="form-card"><h2 class="form-title">Create User</h2><form method="post" action="/ui/users" class="form-grid"><div><label for="username">Username</label><input id="username" name="username" required autocomplete="off"></div><div><label for="displayName">Display Name</label><input id="displayName" name="displayName" autocomplete="off"></div><div><label for="notBefore">Valid From</label><input id="notBefore" name="notBefore" type="date"></div><div><label for="expiresAt">Expires At</label><input id="expiresAt" name="expiresAt" type="date"></div><button class="primary-action" type="submit"><span class="material-symbols-outlined">add</span>Create User</button></form><p class="muted">Creating a user issues one secret and defaults repository access to * pull. Leave dates empty for immediate start or no expiry. Dates start at midnight UTC.</p></section>
    <div class="user-card-list">
      {{range .Users}}
        <details class="user-card">
          <summary><div class="user-card-summary"><div class="user-cell"><div class="avatar">{{initials .User.Username .User.DisplayName}}</div><div><strong>{{.User.Username}}</strong><div class="muted">{{.User.DisplayName}}</div></div></div><div><span class="badge {{.AccessClass}}">{{.AccessStatus}}</span><div class="muted">{{.AccessDetails}}</div></div><div class="repo-metric"><span>Grant</span><strong>{{grantPrefix .Grant}}</strong></div><div class="repo-metric"><span>Created</span><strong>{{timeValue .User.CreatedAt}}</strong></div></div></summary>
          <div class="user-card-body">
              <form id="access-form-{{.User.ID}}" method="post" action="/ui/users/{{.User.ID}}/access" class="access-grid">
                <div><label for="cred-from-{{.User.ID}}">Valid From</label><input id="cred-from-{{.User.ID}}" name="notBefore" type="date" value="{{datetimeLocal .User.NotBefore}}"></div>
                <div><label for="cred-to-{{.User.ID}}">Expires At</label><input id="cred-to-{{.User.ID}}" name="expiresAt" type="date" value="{{datetimeLocal .User.ExpiresAt}}"></div>
                <div class="wide"><label for="grant-prefix-{{.User.ID}}">Repository access</label><input id="grant-prefix-{{.User.ID}}" name="repositoryPrefix" value="{{grantPrefix .Grant}}" placeholder="*, team/, team/service" required><p class="muted">Use * for all repositories, or a prefix like team/ for every image under that namespace.</p></div>
                <div class="check-group wide"><label><input type="checkbox" name="actions" value="pull" {{if grantHasAction .Grant "pull"}}checked{{end}}>Pull</label><label><input type="checkbox" name="actions" value="push" {{if grantHasAction .Grant "push"}}checked{{end}}>Push</label><label><input type="checkbox" name="actions" value="delete" {{if grantHasAction .Grant "delete"}}checked{{end}}>Delete</label></div>
              </form>
              <div class="row-actions"><button class="primary-action" type="submit" form="access-form-{{.User.ID}}">Save access</button>{{if .IsCurrentUser}}<span class="muted">Current user</span>{{else}}<form method="post" action="/ui/users/{{.User.ID}}/delete" data-confirm-title="Delete user {{.User.Username}}?" data-confirm-body="This removes the user and their repository access grant. This action cannot be undone." data-confirm-submit="Delete user"><button class="danger-action" type="submit">Delete</button></form>{{end}}</div>
          </div>
        </details>
      {{else}}
        <div class="table-card"><div class="empty-state"><div><strong>No users yet</strong><br><span>Create a user to issue registry access.</span></div></div></div>
      {{end}}
    </div>
  {{else if eq .Active "audit"}}
    <div class="page-header"><div><h1 class="page-title">Audit Log</h1><p class="page-description">Review system activities, access events, and administrative actions.</p></div></div>
    <form class="filters" method="get" action="/ui/audit"><div class="search"><span class="material-symbols-outlined">filter_list</span><input name="q" value="{{.SearchQuery}}" placeholder="Filter by action, user, target, result, IP, or user agent" aria-label="Filter audit log"></div><select name="action" aria-label="Action filter"><option value="all" {{if or (eq .ActionFilter "") (eq .ActionFilter "all")}}selected{{end}}>All Actions</option><option value="authentication" {{if eq .ActionFilter "authentication"}}selected{{end}}>Authentication</option><option value="pull" {{if eq .ActionFilter "pull"}}selected{{end}}>Image Pull</option><option value="push" {{if eq .ActionFilter "push"}}selected{{end}}>Image Push</option><option value="admin" {{if eq .ActionFilter "admin"}}selected{{end}}>Admin Changes</option></select><button class="small-action" type="submit">Apply</button>{{if or .SearchQuery .ActionFilter}}<a class="secondary-action" href="/ui/audit">Clear</a>{{end}}</form>
    <div class="table-card"><div class="table-scroll"><table><thead><tr><th>Time (UTC)</th><th>Action</th><th>Target / Resource</th><th>Actor / IP Address</th><th>Result</th></tr></thead><tbody>{{range .AuditEvents}}<tr><td class="muted">{{timeValue .Event.CreatedAt}}</td><td><div class="user-cell" style="color:var(--primary)"><span class="material-symbols-outlined">{{actionIcon .Event.Action}}</span><strong>{{.Event.Action}}</strong></div></td><td class="mono">{{.Event.TargetType}} / {{.Target}}</td><td><div><strong>{{.Actor}}</strong><div class="muted">{{.Event.IPAddress}}</div></div></td><td><span class="{{resultClass .Event.Result}}">{{.Event.Result}}</span></td></tr>{{else}}<tr><td colspan="5" class="muted">{{if or .SearchQuery .ActionFilter}}No audit events match this filter.{{else}}No audit events yet.{{end}}</td></tr>{{end}}</tbody></table></div></div>
  {{else if eq .Active "settings"}}
    <div class="page-header"><div><h1 class="page-title">Settings</h1><p class="page-description">Configure registry maintenance behavior.</p></div></div>
    <section class="form-card"><h2 class="form-title">Garbage Collection</h2><form method="post" action="/ui/settings/gc" class="form-grid"><div><label for="gc-enabled">Enabled</label><select id="gc-enabled" name="enabled"><option value="on" {{if .GCSettings.Enabled}}selected{{end}}>Enabled</option><option value="" {{if not .GCSettings.Enabled}}selected{{end}}>Disabled</option></select></div><div><label for="gc-delay">Delete untagged manifests after</label><input id="gc-delay" name="delay" value="{{duration .GCSettings.Delay}}" required></div><div><label for="gc-interval">Run interval</label><input id="gc-interval" name="interval" value="{{duration .GCSettings.Interval}}" required></div><button class="primary-action" type="submit">Save GC Settings</button></form><p class="muted">GC only removes untagged manifest records after the grace period. Blob/layer cleanup is intentionally not enabled yet because blobs can be shared across manifests.</p></section>
  {{end}}
{{end}}

{{define "repositories"}}{{template "shell" .}}{{end}}
{{define "users"}}{{template "shell" .}}{{end}}
{{define "audit"}}{{template "shell" .}}{{end}}
{{define "settings"}}{{template "shell" .}}{{end}}
`
