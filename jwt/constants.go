package jwt

import "errors"

const (
	KeyUserID = "user_id"
	// Jwt AUthentication UUID - UUID generated for the access and refresh tokens.
	// This UUID will be key in Redis.
	KeyUUID = "jau_uuid"
)

const (
	Access  TokenType = "ACCESS"
	Refresh TokenType = "REFRESH"
)

// internalClaims are the claims which are added by the package (and has nothing to do with
// the business logic).
var internalClaims = map[string]bool{
	KeyUUID: true,
}

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrInvalidToken = errors.New("invalid token")
)
