## Authentication in Go

### JWT Auth
Wrapper module for JWT authentication with optional Redis support for token invalidation.

```go
import (
    //...
    "github.com/opxyc/auth-go/pkg/jwt"
    // ...
)

func main() {
	jwtAuth, _ := jwt.NewAuth(&jwtauth.Options{
		{RedisDSN: os.GetEnv("REDIS_DSN")},
	})

	claims := jwt.Claims{
		UserID: "testuser",
		AdditionalClaims: map[string]interface{}{"role": "ADMIN"},
	}

	// create access and refresh tokens
	tokens, _ := jwtAuth.CreateTokens(claims)
	fmt.Printf("Tokens: %+v\n\n", tokens)

	resClaims, _ := jwtAuth.VerifyToken(tokens.AccessToken)
	fmt.Printf("Claims: %+v\n", resClaims)

	// refresh the token
	tokens, _ = jwtAuth.RefreshToken(tokens.RefreshToken)
	fmt.Printf("New tokens: %+v\n", tokens)

	// delete tokens (applicable only if using redis for token expiration)
	_ = jwtAuth.DeleteTokens(tokens.AccessToken)
}
```
