package jwt

import (
	"fmt"
	"strings"
	"time"
)

type tokenDetails struct {
	AccessToken        string
	RefreshToken       string
	AccessUUID         string
	RefreshUUID        string
	AccessTokenExpiry  int64
	RefreshTokenExpiry int64
}

type accessDetails struct {
	AccessUuid string
	UserId     string
}

func (j *auth) writeAuthTokensToRedis(userID string, td *tokenDetails) error {
	atEx := time.Unix(td.AccessTokenExpiry, 0)
	rtEx := time.Unix(td.RefreshTokenExpiry, 0)
	now := time.Now()

	fmt.Println("writing key", td.AccessUUID)
	err := j.redisClient.Set(td.AccessUUID, userID, atEx.Sub(now)).Err()
	if err != nil {
		return err
	}

	fmt.Println("writing key", td.RefreshUUID)
	err = j.redisClient.Set(td.RefreshUUID, userID, rtEx.Sub(now)).Err()
	if err != nil {
		return err
	}

	return nil
}

func (j *auth) fetchAuthTokenFromRedis(accessDetails *accessDetails) (string, error) {
	userID, err := j.redisClient.Get(accessDetails.AccessUuid).Result()
	if err != nil {
		return "", err
	}

	if accessDetails.UserId != userID {
		return "", ErrUnauthorized
	}

	return userID, nil
}

func (j *auth) deleteAuthTokenFromRedis(accessUUID string, userID string) error {
	_, err := j.redisClient.Del(accessUUID).Result()
	if err != nil {
		return err
	}

	_, err = j.redisClient.Del(getRefreshUUID(accessUUID)).Result()
	if err != nil {
		return err
	}

	return nil
}

func getRefreshUUID(accessUUID string) string {
	return accessUUID + "__refresh"
}

func getAccessUUIDFromRefreshUUID(refreshUUID string) string {
	return strings.Split(refreshUUID, "__")[0]
}
