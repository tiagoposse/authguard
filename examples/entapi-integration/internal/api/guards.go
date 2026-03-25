//go:build ignore

package api

import (
	"context"

	"github.com/google/uuid"
	auth "github.com/tiagoposse/authguard"
)

// requiresOwner checks that the authenticated user is the owner of an entity.
// This function is called by generated handler code for entities annotated with
// the "requiresOwner" guard. entapi's AuthGuardHook generates code like:
//
//	_entity, _err := h.client.Article.Get(ctx, request.Id)
//	if _err != nil { return nil, _err }
//	if _err = requiresOwner(ctx, _entity.OwnerID); _err != nil { return nil, _err }
func requiresOwner(ctx context.Context, ownerID uuid.UUID) error {
	userID, ok := auth.GetUserID(ctx)
	if !ok {
		return auth.ErrNotAuthenticated
	}
	if userID != ownerID {
		return auth.Errorf(403, "only the owner can perform this action")
	}
	return nil
}
