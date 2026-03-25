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

// Article is an example entity with owner-based guards.
// Create requires auth, update/delete require ownership, list is public.
type Article struct {
	ent.Schema
}

func (Article) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable().
			Annotations(entoas.ReadOnly(true)),
		field.UUID("owner_id", uuid.UUID{}).
			Immutable(),
		field.String("title").
			NotEmpty(),
		field.Text("body"),
		field.Enum("status").
			Values("draft", "published", "archived").
			Default("draft"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Annotations(entoas.ReadOnly(true)),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Annotations(entoas.ReadOnly(true)),
	}
}

func (Article) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("articles").
			Field("owner_id").
			Required().
			Unique().
			Immutable(),
	}
}

func (Article) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entoas.CreateOperation(entoas.OperationPolicy(entoas.PolicyExpose)),
		entoas.ReadOperation(entoas.OperationPolicy(entoas.PolicyExpose)),
		entoas.UpdateOperation(entoas.OperationPolicy(entoas.PolicyExpose)),
		entoas.DeleteOperation(entoas.OperationPolicy(entoas.PolicyExpose)),
		entoas.ListOperation(entoas.OperationPolicy(entoas.PolicyExpose)),
		auth.Guards().
			OnCreate("requiresAuth", "requiresScope:write").
			OnRead("requiresAuth").
			OnUpdate("requiresAuth", "requiresOwner").   // entity-level guard
			OnDelete("requiresAuth", "requiresOwner").   // entity-level guard
			OnList("requiresAuth"),
	}
}
