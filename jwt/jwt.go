package jwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v7"
	"github.com/twinj/uuid"
)

type Auth interface {
	CreateTokens(claims Claims) (*Tokens, error)
	VerifyToken(token string) (*Claims, error)
	RefreshToken(token string) (*Tokens, error)
	DeleteTokens(token string) error
}

type auth struct {
	useRedis           bool
	redisClient        *redis.Client
	redisKeyPrefix     string
	accessTokenSecret  string
	refreshTokenSecret string
}

func NewAuth(options *Options) (Auth, error) {
	jauth := &auth{
		accessTokenSecret:  options.AccessTokenSecret,
		refreshTokenSecret: options.RefreshTokenSecret,
	}

	if len(options.RedisDSN) != 0 {
		redisClient := redis.NewClient(&redis.Options{Addr: options.RedisDSN})
		_, err := redisClient.Ping().Result()
		if err != nil {
			return nil, err
		}

		jauth.useRedis = true
		jauth.redisClient = redisClient
		jauth.redisKeyPrefix = options.RedisKeyPrefix
	}

	return jauth, nil
}

// CreateTokens creates access and refresh jWT tokens with the given claims. Expiry time of access
// and refresh tokens are 1 Hour and 7 days respectively.
func (j *auth) CreateTokens(claims Claims) (*Tokens, error) {
	td := &tokenDetails{}
	td.AccessTokenExpiry = time.Now().Add(time.Hour * 1).Unix()
	td.AccessUUID = uuid.NewV4().String()

	td.RefreshTokenExpiry = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUUID = getRefreshUUID(td.AccessUUID)

	var err error
	atClaims := jwt.MapClaims{}
	atClaims[KeyUserID] = claims.UserID
	atClaims[KeyUUID] = td.AccessUUID
	for k, v := range claims.AdditionalClaims {
		atClaims[k] = v
	}

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(j.accessTokenSecret))
	if err != nil {
		return nil, err
	}

	rtClaims := atClaims
	rtClaims[KeyUUID] = td.RefreshUUID

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(j.refreshTokenSecret))
	if err != nil {
		return nil, err
	}

	if j.useRedis {
		j.writeAuthTokensToRedis(claims.UserID, td)
	}

	return &Tokens{
		AccessToken:  td.AccessToken,
		RefreshToken: td.RefreshToken,
	}, nil
}

func (j *auth) VerifyToken(token string) (*Claims, error) {
	return j.verifyToken(token, Access)
}

func (j *auth) verifyToken(token string, tokenType TokenType) (*Claims, error) {
	secret := j.accessTokenSecret
	if tokenType == Refresh {
		secret = j.refreshTokenSecret
	}

	claims, tokenUUID, err := decodeToken(token, secret)
	if err != nil {
		return nil, err
	}

	if j.useRedis {
		s, err := j.fetchAuthTokenFromRedis(&accessDetails{AccessUuid: tokenUUID, UserId: claims.UserID})
		if err != nil {
			return nil, ErrUnauthorized
		}

		if s != claims.UserID {
			return nil, ErrUnauthorized
		}
	}

	return claims, nil
}

func (j *auth) RefreshToken(token string) (*Tokens, error) {
	claims, err := j.verifyToken(token, Refresh)
	if err != nil {
		return nil, err
	}

	// delete existing tokens
	err = j.deleteTokens(token, Refresh)
	if err != nil {
		return nil, err
	}

	// create and return new pair of tokens
	return j.CreateTokens(*claims)
}

func (j *auth) DeleteTokens(token string) error {
	return j.deleteTokens(token, Access)
}

func (j *auth) deleteTokens(token string, tokenType TokenType) error {
	secret := j.accessTokenSecret
	if tokenType == Refresh {
		secret = j.refreshTokenSecret
	}

	claims, tokenUUID, err := decodeToken(token, secret)
	if err != nil {
		return err
	}

	if !j.useRedis {
		return nil
	}

	if tokenType == Refresh {
		tokenUUID = getAccessUUIDFromRefreshUUID(tokenUUID)
	}

	return j.deleteAuthTokenFromRedis(tokenUUID, claims.UserID)
}

func decodeToken(token, secret string) (*Claims, string, error) {
	fmt.Println(token)
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		fmt.Println(err)
		return nil, "", ErrInvalidToken
	}

	jwtClaims, ok := t.Claims.(jwt.MapClaims)
	if !ok || !t.Valid {
		return nil, "", ErrInvalidToken
	}

	claims := Claims{AdditionalClaims: make(AdditionalClaims)}
	var tokenUUID string
	for k, v := range jwtClaims {
		if internalClaims[k] {
			if k == KeyUUID {
				tokenUUID = v.(string)
			}

			continue
		}

		if k == KeyUserID {
			claims.UserID = v.(string)
			continue
		}

		claims.AdditionalClaims[k] = v
	}

	return &claims, tokenUUID, nil
}
