package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/opxyc/auth-go/jwt"
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Todo struct {
	UserID string `json:"user_id"`
	Title  string `json:"title"`
}

// dummy user
var user = User{
	ID:       "testuser",
	Username: "username",
	Password: "password",
}

type server struct {
	jwtAuth jwt.Auth
}

func main() {
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}

	jwtAuth, err := jwt.NewAuth(&jwt.Options{RedisDSN: dsn})
	if err != nil {
		log.Fatal(err)
	}

	s := server{jwtAuth: jwtAuth}

	var router = gin.Default()
	router.POST("/login", s.login)
	router.POST("/todo", s.createTodo)
	router.POST("/logout", s.logout)
	router.POST("/refresh", s.refreshTokens)
	log.Fatal(router.Run(":8080"))
}

func (s *server) login(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}

	if user.Username != u.Username || user.Password != u.Password {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}

	ts, err := s.jwtAuth.CreateTokens(jwt.Claims{
		UserID: "testuser",
	})
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	tokens := map[string]string{
		"access_token":  ts.AccessToken,
		"refresh_token": ts.RefreshToken,
	}

	c.JSON(http.StatusOK, tokens)
}

func (s *server) createTodo(c *gin.Context) {
	var todo Todo
	if err := c.ShouldBindJSON(&todo); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}

	tokenString := extractTokenFromRequestHeader(c.Request)
	claims, err := s.jwtAuth.VerifyToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}

	todo.UserID = claims.UserID
	// TODO write todo to DB

	c.JSON(http.StatusCreated, todo)
}

func (s *server) logout(c *gin.Context) {
	tokenString := extractTokenFromRequestHeader(c.Request)
	err := s.jwtAuth.DeleteTokens(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}

	c.JSON(http.StatusOK, "successfully logged out")
}
func (s *server) refreshTokens(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	refreshToken := mapToken["refresh_token"]

	ts, err := s.jwtAuth.RefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}

	tokens := map[string]string{
		"access_token":  ts.AccessToken,
		"refresh_token": ts.RefreshToken,
	}

	c.JSON(http.StatusOK, tokens)
}
