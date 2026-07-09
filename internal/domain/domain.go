package domain

import "time"

type Role string

const (
	RoleReader Role = "reader"
	RoleAdmin  Role = "admin"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
)

type Action string

const (
	ActionPull   Action = "pull"
	ActionPush   Action = "push"
	ActionDelete Action = "delete"
	ActionAdmin  Action = "admin"
)

type User struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"displayName"`
	Role        Role       `json:"role"`
	Status      UserStatus `json:"status"`
	SecretHash  string     `json:"-"`
	NotBefore   *time.Time `json:"notBefore,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	DisabledAt  *time.Time `json:"disabledAt,omitempty"`
}

type Grant struct {
	ID               string    `json:"id"`
	SubjectType      string    `json:"subjectType"`
	SubjectID        string    `json:"subjectId"`
	RepositoryPrefix string    `json:"repositoryPrefix"`
	Actions          []Action  `json:"actions"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type Repository struct {
	Name          string     `json:"name"`
	TagCount      int        `json:"tagCount"`
	ManifestCount int        `json:"manifestCount"`
	SizeBytes     int64      `json:"sizeBytes"`
	LastPushAt    *time.Time `json:"lastPushAt,omitempty"`
	LastPullAt    *time.Time `json:"lastPullAt,omitempty"`
}

type RepositoryTag struct {
	RepositoryName string     `json:"repositoryName"`
	Tag            string     `json:"tag"`
	Digest         string     `json:"digest"`
	MediaType      string     `json:"mediaType"`
	SizeBytes      int64      `json:"sizeBytes"`
	PushedAt       time.Time  `json:"pushedAt"`
	PulledAt       *time.Time `json:"pulledAt,omitempty"`
}

type DashboardSummary struct {
	Repositories      int   `json:"repositories"`
	Tags              int   `json:"tags"`
	StorageBytes      int64 `json:"storageBytes"`
	ActiveUsers       int   `json:"activeUsers"`
	UsersExpiringSoon int   `json:"usersExpiringSoon"`
	Pulls24h          int   `json:"pulls24h"`
	Pushes24h         int   `json:"pushes24h"`
}

type DailyUsage struct {
	Date   time.Time `json:"date"`
	Pulls  int       `json:"pulls"`
	Pushes int       `json:"pushes"`
}

type GCSettings struct {
	Enabled  bool
	Delay    time.Duration
	Interval time.Duration
}

type AuditEvent struct {
	ID          string    `json:"id"`
	ActorUserID *string   `json:"actorUserId,omitempty"`
	Action      string    `json:"action"`
	TargetType  string    `json:"targetType"`
	TargetID    string    `json:"targetId"`
	Result      string    `json:"result"`
	IPAddress   string    `json:"ipAddress"`
	UserAgent   string    `json:"userAgent"`
	CreatedAt   time.Time `json:"createdAt"`
}

type SigningKey struct {
	ID        string     `json:"id"`
	Secret    []byte     `json:"-"`
	CreatedAt time.Time  `json:"createdAt"`
	RetiredAt *time.Time `json:"retiredAt,omitempty"`
}

func ValidRole(role Role) bool {
	return role == RoleReader || role == RoleAdmin
}

func ValidActions(actions []Action) bool {
	if len(actions) == 0 {
		return false
	}
	for _, action := range actions {
		switch action {
		case ActionPull, ActionPush, ActionDelete, ActionAdmin:
		default:
			return false
		}
	}
	return true
}
