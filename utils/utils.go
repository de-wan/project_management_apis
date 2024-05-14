package utils

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/de-wan/project_management_apis/db_sqlc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Resp struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func GenerateUUID() string {
	uuid := uuid.Must(uuid.NewRandom())
	return uuid.String()
}

type JwtCustomClaims struct {
	Uuid     string `json:"uuid"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type JwtCustomRefreshClaims struct {
	Uuid string `json:"uuid"`
	jwt.RegisteredClaims
}

func CreateToken(user db_sqlc.User) (accessToken string, refreshToken string, err error) {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("JWT_SECRET_KEY not set in .env")
	}

	accessExp := time.Now().Add(time.Minute * 5)
	accessClaims := JwtCustomClaims{
		Uuid:     user.Uuid,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExp),
		},
	}
	rawAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = rawAccessToken.SignedString([]byte(secretKey))
	if err != nil {
		return "", "", err
	}

	refreshExp := time.Now().Add(time.Minute * 5)
	refreshClaims := JwtCustomRefreshClaims{
		Uuid: user.Uuid,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExp),
		},
	}
	rawRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = rawRefreshToken.SignedString([]byte(secretKey))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func GetAccessTokenClaims(r *http.Request) (claims jwt.MapClaims, err error) {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		return claims, errors.New("missing authorization header")
	}
	tokenStr = tokenStr[len("Bearer "):]

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return claims, errors.New("invalid token")
	}

	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("JWT_SECRET_KEY not set in .env")
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		return claims, err
	}

	claims = token.Claims.(jwt.MapClaims)

	if !token.Valid {
		return claims, errors.New("invalid token")
	}

	return claims, err
}
