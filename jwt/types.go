package jwt

type Options struct {
	RedisDSN           string
	RedisKeyPrefix     string
	AccessTokenSecret  string
	RefreshTokenSecret string
}

type AdditionalClaims map[string]interface{}

type Claims struct {
	UserID string
	AdditionalClaims
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
}

type TokenType string
