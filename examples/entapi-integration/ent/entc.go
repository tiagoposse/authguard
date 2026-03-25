//go:build ignore

package main

import (
	"log"

	"entgo.io/contrib/entoas"
	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
	"github.com/ogen-go/ogen"
	"github.com/yourorg/yourapp/internal/entapi"
)

func main() {
	spec := new(ogen.Spec)

	// 1. Configure entoas to generate the OpenAPI spec from Ent schemas.
	oasExt, err := entoas.NewExtension(
		entoas.Spec(spec),
		entoas.SimpleModels(),
		entoas.Mutations(func(graph *gen.Graph, spec *ogen.Spec) error {
			spec.Info.SetTitle("My App API")
			spec.Info.SetVersion("1.0.0")

			// Add Bearer auth security scheme.
			spec.Security = []ogen.SecurityRequirement{
				{"bearerAuth": []string{}},
			}
			if spec.Components == nil {
				spec.Components = &ogen.Components{}
			}
			if spec.Components.SecuritySchemes == nil {
				spec.Components.SecuritySchemes = make(map[string]*ogen.SecurityScheme)
			}
			spec.Components.SecuritySchemes["bearerAuth"] = &ogen.SecurityScheme{
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "JWT",
			}

			// Add custom auth endpoints to the spec.
			addAuthEndpoints(spec)

			return nil
		}),
	)
	if err != nil {
		log.Fatalf("creating entoas extension: %v", err)
	}

	// 2. Configure entapi to generate CRUD handlers with auth guards.
	apiExt, err := entapi.NewExtension(spec,
		entapi.WithOutputDir("internal/api"),
		entapi.WithPackageName("api"),
		entapi.WithBeforeHandlerHook(entapi.AuthGuardHook(
			// Import alias used in generated code.
			`auth "github.com/tiagoposse/entauth"`,
			// Entity-level guards: these fetch the entity and check a field.
			map[string]entapi.EntityGuardTemplate{
				"requiresOwner": {
					FieldName: "OwnerID",
					FuncName:  "requiresOwner",
				},
			},
		)),
		entapi.WithPagination(30),
		entapi.WithFieldFiltering(true),
	)
	if err != nil {
		log.Fatalf("creating entapi extension: %v", err)
	}

	// 3. Run code generation with both extensions.
	err = entc.Generate("./schema", &gen.Config{
		Features: []gen.Feature{
			gen.FeatureUpsert,
		},
	}, entc.Extensions(oasExt, apiExt))
	if err != nil {
		log.Fatalf("running ent codegen: %v", err)
	}
}

// addAuthEndpoints adds login, register, refresh, logout, and API key
// endpoints to the OpenAPI spec. These are hand-written handlers, not
// generated CRUD.
func addAuthEndpoints(spec *ogen.Spec) {
	// POST /auth/login
	spec.AddPathItem("/auth/login", ogen.NewPathItem().
		SetPost(ogen.NewOperation().
			SetOperationID("Login").
			SetSummary("Authenticate with email and password")))

	// POST /auth/register
	spec.AddPathItem("/auth/register", ogen.NewPathItem().
		SetPost(ogen.NewOperation().
			SetOperationID("Register").
			SetSummary("Create a new account")))

	// POST /auth/refresh
	spec.AddPathItem("/auth/refresh", ogen.NewPathItem().
		SetPost(ogen.NewOperation().
			SetOperationID("RefreshToken").
			SetSummary("Refresh an access token")))

	// POST /auth/logout
	spec.AddPathItem("/auth/logout", ogen.NewPathItem().
		SetPost(ogen.NewOperation().
			SetOperationID("Logout").
			SetSummary("Revoke the current token")))

	// POST /auth/logout-all
	spec.AddPathItem("/auth/logout-all", ogen.NewPathItem().
		SetPost(ogen.NewOperation().
			SetOperationID("LogoutAll").
			SetSummary("Revoke all sessions")))

	// POST /auth/admin-elevate
	spec.AddPathItem("/auth/admin-elevate", ogen.NewPathItem().
		SetPost(ogen.NewOperation().
			SetOperationID("AdminElevate").
			SetSummary("Get a short-lived admin elevation token")))

	// API key management
	spec.AddPathItem("/api-keys", ogen.NewPathItem().
		SetPost(ogen.NewOperation().
			SetOperationID("CreateApiKey").
			SetSummary("Create a new API key")).
		SetGet(ogen.NewOperation().
			SetOperationID("ListApiKeys").
			SetSummary("List the user's API keys")))

	spec.AddPathItem("/api-keys/{id}", ogen.NewPathItem().
		SetDelete(ogen.NewOperation().
			SetOperationID("RevokeApiKey").
			SetSummary("Revoke an API key")))

	// Session management
	spec.AddPathItem("/sessions", ogen.NewPathItem().
		SetGet(ogen.NewOperation().
			SetOperationID("ListSessions").
			SetSummary("List active sessions for the current user")))

	spec.AddPathItem("/sessions/{id}", ogen.NewPathItem().
		SetDelete(ogen.NewOperation().
			SetOperationID("RevokeSession").
			SetSummary("Revoke a specific session")))
}
