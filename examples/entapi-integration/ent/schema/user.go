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

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable().
			Annotations(entoas.ReadOnly(true)),
		field.String("email").
			Unique().
			NotEmpty(),
		field.String("username").
			Unique().
			NotEmpty(),
		field.String("display_name").
			Optional(),
		field.String("password_hash").
			Sensitive(), // excluded from API responses
		field.Enum("role").
			Values("user", "editor", "admin").
			Default("user"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Annotations(entoas.ReadOnly(true)),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("articles", Article.Type),
		edge.To("api_keys", ApiKey.Type),
		edge.To("sessions", Session.Type),
	}
}

func (User) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entoas.CreateOperation(entoas.OperationPolicy(entoas.PolicyExclude)), // use /auth/register
		entoas.ReadOperation(entoas.OperationPolicy(entoas.PolicyExpose)),
		entoas.UpdateOperation(entoas.OperationPolicy(entoas.PolicyExpose)),
		entoas.DeleteOperation(entoas.OperationPolicy(entoas.PolicyExpose)),
		entoas.ListOperation(entoas.OperationPolicy(entoas.PolicyExpose)),
		auth.Guards().
			OnRead("requiresAuth").
			OnUpdate("requiresAuth").
			OnDelete("requiresRole:admin").
			OnList("requiresAuth"),
	}
}
