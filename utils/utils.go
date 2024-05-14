package utils

import (
	"log"
	"os"
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
