package utils

import (
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func GenerateUUID() string {
	uuid := uuid.Must(uuid.NewRandom())
	return uuid.String()
}

func CreateToken(username string) (accessToken string, refreshToken string, err error) {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("JWT_SECRET_KEY not set in .env")
	}

	rawAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
			"exp":      time.Now().Add(time.Minute * 5).Unix(),
		})

	accessToken, err = rawAccessToken.SignedString(secretKey)
	if err != nil {
		return "", "", err
	}

	rawRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"exp": time.Now().Add(time.Hour * 24).Unix(),
		})

	refreshToken, err = rawRefreshToken.SignedString(secretKey)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
