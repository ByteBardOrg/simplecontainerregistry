package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"simplecontainerregistry/internal/domain"
	"simplecontainerregistry/internal/ids"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

type CreateUserParams struct {
	Username    string
	DisplayName string
	Role        domain.Role
	SecretHash  string
	NotBefore   *time.Time
	ExpiresAt   *time.Time
}

type CreateGrantParams struct {
	SubjectType      string
	SubjectID        string
	RepositoryPrefix string
	Actions          []domain.Action
}

type UpsertRepositoryTagParams struct {
	RepositoryName string
	Tag            string
	Digest         string
	MediaType      string
	SizeBytes      int64
}

const (
	settingGCEnabled          = "gc.enabled"
	settingGCDelay            = "gc.delay"
	settingGCInterval         = "gc.interval"
	settingRegistryWebhookURL = "webhook.registry_url"
)

func Open(ctx context.Context, dsn string) (*Store, error) {
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	if _, err := database.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		database.Close()
		return nil, err
	}
	return &Store{db: database}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) InitSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

func (s *Store) CreateUser(ctx context.Context, params CreateUserParams, now time.Time) (domain.User, error) {
	if params.Username == "" || params.SecretHash == "" {
		return domain.User{}, fmt.Errorf("username and secret hash are required")
	}
	if !domain.ValidRole(params.Role) {
		return domain.User{}, fmt.Errorf("invalid role %q", params.Role)
	}
	if params.NotBefore != nil && params.ExpiresAt != nil && !params.ExpiresAt.After(*params.NotBefore) {
		return domain.User{}, fmt.Errorf("expires at must be after valid from")
	}
	id, err := ids.New("usr")
	if err != nil {
		return domain.User{}, err
	}
	user := domain.User{
		ID:          id,
		Username:    params.Username,
		DisplayName: params.DisplayName,
		Role:        params.Role,
		Status:      domain.UserStatusActive,
		SecretHash:  params.SecretHash,
		NotBefore:   params.NotBefore,
		ExpiresAt:   params.ExpiresAt,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, display_name, role, status, secret_hash, not_before, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Username, user.DisplayName, user.Role, user.Status, user.SecretHash, user.NotBefore, user.ExpiresAt, user.CreatedAt, user.UpdatedAt,
	)
	return user, err
}

func (s *Store) GetUser(ctx context.Context, id string) (domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, display_name, role, status, secret_hash, not_before, expires_at, last_used_at, created_at, updated_at, disabled_at
		FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, display_name, role, status, secret_hash, not_before, expires_at, last_used_at, created_at, updated_at, disabled_at
		FROM users WHERE username = ?`, username)
	return scanUser(row)
}

func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, username, display_name, role, status, secret_hash, not_before, expires_at, last_used_at, created_at, updated_at, disabled_at
		FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) SetUserStatus(ctx context.Context, id string, status domain.UserStatus, now time.Time) error {
	var disabledAt any
	if status == domain.UserStatusDisabled {
		disabledAt = now
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE users SET status = ?, updated_at = ?, disabled_at = ? WHERE id = ?`,
		status, now, disabledAt, id,
	)
	return requireAffected(result, err)
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return requireAffected(result, err)
}

func (s *Store) UpdateUserValidity(ctx context.Context, id string, notBefore, expiresAt *time.Time) error {
	if notBefore != nil && expiresAt != nil && !expiresAt.After(*notBefore) {
		return fmt.Errorf("expires at must be after valid from")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE users SET not_before = ?, expires_at = ?, updated_at = ? WHERE id = ?`, notBefore, expiresAt, time.Now().UTC(), id)
	return requireAffected(result, err)
}

func (s *Store) UpdateUserLastUsed(ctx context.Context, id string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE users SET last_used_at = ? WHERE id = ?`, now, id)
	return requireAffected(result, err)
}

func (s *Store) CreateGrant(ctx context.Context, params CreateGrantParams, now time.Time) (domain.Grant, error) {
	if params.SubjectType != "user" {
		return domain.Grant{}, fmt.Errorf("unsupported subject type %q", params.SubjectType)
	}
	if params.SubjectID == "" || params.RepositoryPrefix == "" {
		return domain.Grant{}, fmt.Errorf("subject id and repository prefix are required")
	}
	if !domain.ValidActions(params.Actions) {
		return domain.Grant{}, fmt.Errorf("invalid actions")
	}
	id, err := ids.New("grnt")
	if err != nil {
		return domain.Grant{}, err
	}
	actionsJSON, err := json.Marshal(params.Actions)
	if err != nil {
		return domain.Grant{}, err
	}
	grant := domain.Grant{
		ID:               id,
		SubjectType:      params.SubjectType,
		SubjectID:        params.SubjectID,
		RepositoryPrefix: params.RepositoryPrefix,
		Actions:          params.Actions,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO grants (id, subject_type, subject_id, repository_prefix, actions, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		grant.ID, grant.SubjectType, grant.SubjectID, grant.RepositoryPrefix, string(actionsJSON), grant.CreatedAt, grant.UpdatedAt,
	)
	return grant, err
}

func (s *Store) ReplaceUserGrant(ctx context.Context, params CreateGrantParams, now time.Time) (domain.Grant, error) {
	if params.SubjectType == "" {
		params.SubjectType = "user"
	}
	if params.SubjectType != "user" {
		return domain.Grant{}, fmt.Errorf("unsupported subject type %q", params.SubjectType)
	}
	if params.SubjectID == "" || params.RepositoryPrefix == "" {
		return domain.Grant{}, fmt.Errorf("subject id and repository prefix are required")
	}
	if !domain.ValidActions(params.Actions) {
		return domain.Grant{}, fmt.Errorf("invalid actions")
	}
	id, err := ids.New("grnt")
	if err != nil {
		return domain.Grant{}, err
	}
	actionsJSON, err := json.Marshal(params.Actions)
	if err != nil {
		return domain.Grant{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Grant{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM grants WHERE subject_type = 'user' AND subject_id = ?`, params.SubjectID); err != nil {
		return domain.Grant{}, err
	}
	grant := domain.Grant{ID: id, SubjectType: "user", SubjectID: params.SubjectID, RepositoryPrefix: params.RepositoryPrefix, Actions: params.Actions, CreatedAt: now, UpdatedAt: now}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO grants (id, subject_type, subject_id, repository_prefix, actions, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		grant.ID, grant.SubjectType, grant.SubjectID, grant.RepositoryPrefix, string(actionsJSON), grant.CreatedAt, grant.UpdatedAt,
	); err != nil {
		return domain.Grant{}, err
	}
	return grant, tx.Commit()
}

func (s *Store) ListGrantsByUser(ctx context.Context, userID string) ([]domain.Grant, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, subject_type, subject_id, repository_prefix, actions, created_at, updated_at
		FROM grants WHERE subject_type = 'user' AND subject_id = ? ORDER BY repository_prefix`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrants(rows)
}

func (s *Store) ListGrants(ctx context.Context) ([]domain.Grant, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, subject_type, subject_id, repository_prefix, actions, created_at, updated_at
		FROM grants ORDER BY repository_prefix`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrants(rows)
}

func (s *Store) DeleteGrant(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE id = ?`, id)
	return requireAffected(result, err)
}

func (s *Store) UpsertRepositoryTag(ctx context.Context, params UpsertRepositoryTagParams, now time.Time) error {
	if params.RepositoryName == "" || params.Tag == "" || params.Digest == "" {
		return fmt.Errorf("repository name, tag, and digest are required")
	}
	if params.SizeBytes < 0 {
		return fmt.Errorf("size bytes cannot be negative")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO repositories (name, last_push_at)
		VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET last_push_at = excluded.last_push_at`,
		params.RepositoryName, now,
	); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO repository_tags (repository_name, tag, digest, media_type, size_bytes, pushed_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(repository_name, tag) DO UPDATE SET
		  digest = excluded.digest,
		  media_type = excluded.media_type,
		  size_bytes = excluded.size_bytes,
		  pushed_at = excluded.pushed_at`,
		params.RepositoryName, params.Tag, params.Digest, params.MediaType, params.SizeBytes, now,
	); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE repositories SET
		  tag_count = (SELECT COUNT(*) FROM repository_tags WHERE repository_name = ?),
		  manifest_count = (SELECT COUNT(DISTINCT digest) FROM repository_tags WHERE repository_name = ?),
		  size_bytes = COALESCE((SELECT SUM(size_bytes) FROM repository_tags WHERE repository_name = ?), 0),
		  last_push_at = ?
		WHERE name = ?`,
		params.RepositoryName, params.RepositoryName, params.RepositoryName, now, params.RepositoryName,
	); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) DeleteRepositoryManifestReference(ctx context.Context, repositoryName, reference, digest string) error {
	if repositoryName == "" || reference == "" || digest == "" {
		return fmt.Errorf("repository name, reference, and digest are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if strings.Contains(reference, ":") {
		if _, err := tx.ExecContext(ctx, `DELETE FROM repository_tags WHERE repository_name = ? AND digest = ?`, repositoryName, digest); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `DELETE FROM repository_tags WHERE repository_name = ? AND tag = ?`, repositoryName, reference); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE repositories SET
		  tag_count = (SELECT COUNT(*) FROM repository_tags WHERE repository_name = ?),
		  manifest_count = (SELECT COUNT(DISTINCT digest) FROM repository_tags WHERE repository_name = ?),
		  size_bytes = COALESCE((SELECT SUM(size_bytes) FROM repository_tags WHERE repository_name = ?), 0)
		WHERE name = ?`,
		repositoryName, repositoryName, repositoryName, repositoryName,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM repositories WHERE name = ? AND tag_count = 0 AND manifest_count = 0`, repositoryName); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) MarkRepositoryPulled(ctx context.Context, repositoryName, reference string, now time.Time) error {
	if repositoryName == "" {
		return fmt.Errorf("repository name is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO repositories (name, last_pull_at)
		VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET last_pull_at = excluded.last_pull_at`,
		repositoryName, now,
	); err != nil {
		return err
	}

	if reference != "" && !strings.Contains(reference, ":") {
		if _, err := tx.ExecContext(ctx, `
			UPDATE repository_tags SET pulled_at = ?
			WHERE repository_name = ? AND tag = ?`,
			now, repositoryName, reference,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) IncrementUsageCounter(ctx context.Context, repositoryName string, action domain.Action, now time.Time) error {
	if repositoryName == "" {
		return fmt.Errorf("repository name is required")
	}
	if action == "" {
		return fmt.Errorf("action is required")
	}
	windowStart := now.Truncate(time.Hour)
	windowEnd := windowStart.Add(time.Hour)
	id := repositoryName + ":" + string(action) + ":" + windowStart.Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO usage_counters (id, repository_name, action, count, window_start, window_end)
		VALUES (?, ?, ?, 1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET count = count + 1`,
		id, repositoryName, action, windowStart, windowEnd,
	)
	return err
}

func (s *Store) ListRepositories(ctx context.Context) ([]domain.Repository, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, tag_count, manifest_count, size_bytes, last_push_at, last_pull_at
		FROM repositories ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repositories []domain.Repository
	for rows.Next() {
		repository, err := scanRepository(rows)
		if err != nil {
			return nil, err
		}
		repositories = append(repositories, repository)
	}
	return repositories, rows.Err()
}

func (s *Store) GetRepository(ctx context.Context, name string) (domain.Repository, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT name, tag_count, manifest_count, size_bytes, last_push_at, last_pull_at
		FROM repositories WHERE name = ?`, name)
	return scanRepository(row)
}

func (s *Store) DeleteRepository(ctx context.Context, name string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM repositories WHERE name = ?`, name)
	return requireAffected(result, err)
}

func (s *Store) ListRepositoryTags(ctx context.Context, repositoryName string) ([]domain.RepositoryTag, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT repository_name, tag, digest, media_type, size_bytes, pushed_at, pulled_at
		FROM repository_tags WHERE repository_name = ? ORDER BY pushed_at DESC, tag`, repositoryName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []domain.RepositoryTag
	for rows.Next() {
		var tag domain.RepositoryTag
		if err := rows.Scan(&tag.RepositoryName, &tag.Tag, &tag.Digest, &tag.MediaType, &tag.SizeBytes, &tag.PushedAt, &tag.PulledAt); err != nil {
			return nil, err
		}
		tags = append(tags, tag)
	}
	return tags, rows.Err()
}

func (s *Store) DashboardSummary(ctx context.Context, now time.Time) (domain.DashboardSummary, error) {
	var summary domain.DashboardSummary
	row := s.db.QueryRowContext(ctx, `
		SELECT
		  (SELECT COUNT(*) FROM repositories),
		  (SELECT COUNT(*) FROM repository_tags),
		  COALESCE((SELECT SUM(size_bytes) FROM repositories), 0),
		  (SELECT COUNT(*) FROM users WHERE status = 'active'),
		  (SELECT COUNT(*) FROM users WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at > ? AND expires_at <= ?),
		  COALESCE((SELECT SUM(count) FROM usage_counters WHERE action = 'pull' AND window_start >= ?), 0),
		  COALESCE((SELECT SUM(count) FROM usage_counters WHERE action = 'push' AND window_start >= ?), 0)`,
		now, now.Add(14*24*time.Hour), now.Add(-24*time.Hour), now.Add(-24*time.Hour),
	)
	if err := row.Scan(&summary.Repositories, &summary.Tags, &summary.StorageBytes, &summary.ActiveUsers, &summary.UsersExpiringSoon, &summary.Pulls24h, &summary.Pushes24h); err != nil {
		return domain.DashboardSummary{}, err
	}
	return summary, nil
}

func (s *Store) DailyUsage(ctx context.Context, now time.Time, days int, repositoryName string) ([]domain.DailyUsage, error) {
	if days <= 0 || days > 31 {
		days = 7
	}
	end := dayStart(now.UTC()).Add(24 * time.Hour)
	start := end.AddDate(0, 0, -days)

	series := make([]domain.DailyUsage, days)
	byDay := make(map[string]int, days)
	for i := range days {
		date := start.AddDate(0, 0, i)
		series[i] = domain.DailyUsage{Date: date}
		byDay[date.Format("2006-01-02")] = i
	}

	query := `
		SELECT action, count, window_start
		FROM usage_counters
		WHERE window_start >= ? AND window_start < ?`
	args := []any{start, end}
	if repositoryName != "" {
		query += ` AND repository_name = ?`
		args = append(args, repositoryName)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var action domain.Action
		var count int
		var windowStart time.Time
		if err := rows.Scan(&action, &count, &windowStart); err != nil {
			return nil, err
		}
		idx, ok := byDay[dayStart(windowStart.UTC()).Format("2006-01-02")]
		if !ok {
			continue
		}
		switch action {
		case domain.ActionPull:
			series[idx].Pulls += count
		case domain.ActionPush:
			series[idx].Pushes += count
		}
	}
	return series, rows.Err()
}

func (s *Store) GCSettings(ctx context.Context, fallback domain.GCSettings) (domain.GCSettings, error) {
	settings := fallback
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM app_settings WHERE key IN (?, ?, ?)`, settingGCEnabled, settingGCDelay, settingGCInterval)
	if err != nil {
		return domain.GCSettings{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return domain.GCSettings{}, err
		}
		switch key {
		case settingGCEnabled:
			settings.Enabled = value == "true"
		case settingGCDelay:
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return domain.GCSettings{}, err
			}
			settings.Delay = parsed
		case settingGCInterval:
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return domain.GCSettings{}, err
			}
			settings.Interval = parsed
		}
	}
	return settings, rows.Err()
}

func (s *Store) UpdateGCSettings(ctx context.Context, settings domain.GCSettings, now time.Time) error {
	if settings.Delay < 0 {
		return fmt.Errorf("gc delay cannot be negative")
	}
	if settings.Interval <= 0 {
		return fmt.Errorf("gc interval must be positive")
	}
	values := map[string]string{
		settingGCEnabled:  fmt.Sprintf("%t", settings.Enabled),
		settingGCDelay:    settings.Delay.String(),
		settingGCInterval: settings.Interval.String(),
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
			key, value, now,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RegistryWebhookSettings(ctx context.Context) (domain.RegistryWebhookSettings, error) {
	row := s.db.QueryRowContext(ctx, `SELECT value FROM app_settings WHERE key = ?`, settingRegistryWebhookURL)
	var settings domain.RegistryWebhookSettings
	if err := row.Scan(&settings.URL); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.RegistryWebhookSettings{}, nil
		}
		return domain.RegistryWebhookSettings{}, err
	}
	return settings, nil
}

func (s *Store) UpdateRegistryWebhookSettings(ctx context.Context, settings domain.RegistryWebhookSettings, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		settingRegistryWebhookURL, settings.URL, now,
	)
	return err
}

func dayStart(value time.Time) time.Time {
	year, month, day := value.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

func (s *Store) InsertAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	if event.ID == "" {
		id, err := ids.New("aud")
		if err != nil {
			return err
		}
		event.ID = id
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events (id, actor_user_id, action, target_type, target_id, result, ip_address, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.ActorUserID, event.Action, event.TargetType, event.TargetID, event.Result, event.IPAddress, event.UserAgent, event.CreatedAt,
	)
	return err
}

func (s *Store) ListAuditEvents(ctx context.Context, limit int) ([]domain.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, actor_user_id, action, target_type, target_id, result, ip_address, user_agent, created_at
		FROM audit_events ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []domain.AuditEvent
	for rows.Next() {
		var event domain.AuditEvent
		if err := rows.Scan(&event.ID, &event.ActorUserID, &event.Action, &event.TargetType, &event.TargetID, &event.Result, &event.IPAddress, &event.UserAgent, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) EnsureActiveSigningKey(ctx context.Context) error {
	_, err := s.ActiveSigningKey(ctx)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	id, err := ids.New("key")
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO signing_keys (id, secret, created_at)
		VALUES (?, ?, ?)`, id, base64.RawStdEncoding.EncodeToString(secret), time.Now().UTC())
	return err
}

func (s *Store) ActiveSigningKey(ctx context.Context) (domain.SigningKey, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, secret, created_at, retired_at
		FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1`)
	var key domain.SigningKey
	var encoded string
	if err := row.Scan(&key.ID, &encoded, &key.CreatedAt, &key.RetiredAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.SigningKey{}, ErrNotFound
		}
		return domain.SigningKey{}, err
	}
	secret, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return domain.SigningKey{}, err
	}
	key.Secret = secret
	return key, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (domain.User, error) {
	var user domain.User
	if err := row.Scan(&user.ID, &user.Username, &user.DisplayName, &user.Role, &user.Status, &user.SecretHash, &user.NotBefore, &user.ExpiresAt, &user.LastUsedAt, &user.CreatedAt, &user.UpdatedAt, &user.DisabledAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.User{}, ErrNotFound
		}
		return domain.User{}, err
	}
	return user, nil
}

func scanRepository(row scanner) (domain.Repository, error) {
	var repository domain.Repository
	if err := row.Scan(&repository.Name, &repository.TagCount, &repository.ManifestCount, &repository.SizeBytes, &repository.LastPushAt, &repository.LastPullAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Repository{}, ErrNotFound
		}
		return domain.Repository{}, err
	}
	return repository, nil
}

func scanGrants(rows *sql.Rows) ([]domain.Grant, error) {
	var grants []domain.Grant
	for rows.Next() {
		var grant domain.Grant
		var actionsJSON string
		if err := rows.Scan(&grant.ID, &grant.SubjectType, &grant.SubjectID, &grant.RepositoryPrefix, &actionsJSON, &grant.CreatedAt, &grant.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(actionsJSON), &grant.Actions); err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func requireAffected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func NormalizeRepositoryPrefix(prefix string) string {
	return strings.TrimPrefix(prefix, "/")
}
