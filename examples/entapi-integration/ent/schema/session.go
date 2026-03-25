//go:build ignore

package schema

import (
	"time"

	"entgo.io/contrib/entoas"
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	auth "github.com/tiagoposse/authguard"
)

// Session tracks active user sessions (one per device). The refresh token
// is stored hashed; the access token lives only in entauth's TokenService.
type Session struct {
	ent.Schema
}

func (Session) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable().
			Annotations(entoas.ReadOnly(true)),
		field.UUID("user_id", uuid.UUID{}).
			Immutable(),
		field.String("device_id").
			NotEmpty().
			Comment("Client-generated device identifier"),
		field.String("device_name").
			Optional().
			Comment("Human-readable device name, e.g. 'iPhone 15'"),
		field.String("ip_address").
			Optional(),
		field.String("user_agent").
			Optional(),
		field.String("refresh_token_hash").
			Sensitive().
			Comment("SHA-256 hash of the refresh token"),
		field.Time("expires_at").
			Comment("When the refresh token expires"),
		field.Time("last_active_at").
			Default(time.Now),
		field.Time("revoked_at").
			Optional().
			Nillable(),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Annotations(entoas.ReadOnly(true)),
	}
}

func (Session) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("sessions").
			Field("user_id").
			Required().
			Unique().
			Immutable(),
	}
}

func (Session) Annotations() []schema.Annotation {
	return []schema.Annotation{
		// Sessions are managed via custom handlers, not generated CRUD.
		entoas.CreateOperation(entoas.OperationPolicy(entoas.PolicyExclude)),
		entoas.ReadOperation(entoas.OperationPolicy(entoas.PolicyExclude)),
		entoas.UpdateOperation(entoas.OperationPolicy(entoas.PolicyExclude)),
		entoas.DeleteOperation(entoas.OperationPolicy(entoas.PolicyExclude)),
		entoas.ListOperation(entoas.OperationPolicy(entoas.PolicyExclude)),
		auth.Guards().
			OnRead("requiresAuth").
			OnDelete("requiresAuth"),
	}
}
