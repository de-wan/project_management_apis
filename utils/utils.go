package utils

import "github.com/google/uuid"

func GenerateUUID() string {
	uuid := uuid.Must(uuid.NewRandom())
	return uuid.String()
}
