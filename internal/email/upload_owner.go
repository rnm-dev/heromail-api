package email

import "context"

type uploadOwnerKey struct{}

// WithUploadOwner isolates session uploads from other members and API keys.
func WithUploadOwner(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, uploadOwnerKey{}, id)
}
func uploadOwner(ctx context.Context) string {
	id, _ := ctx.Value(uploadOwnerKey{}).(string)
	return id
}
