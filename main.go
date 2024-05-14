package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/de-wan/project_management_apis/db_sqlc"
	"github.com/de-wan/project_management_apis/handlers"
	"github.com/joho/godotenv"
)

func loadEnv() {
	// load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {
	loadEnv()

	db_sqlc.Init()

	serverPort := 3000
	serverPortString := os.Getenv("SERVER_PORT")
	if serverPortString != "" {
		serverPortParsed, err := strconv.ParseInt(serverPortString, 10, 64)
		if err != nil {
			log.Fatal("invalid variable SERVER_PORT in .env")
		}

		serverPort = int(serverPortParsed)
	}

	http.HandleFunc("POST /api/v1/register", handlers.RegisterHandler)
	http.HandleFunc("POST /api/v1/login", handlers.LoginHandler)

	log.Printf("Starting server on port %d", serverPort)
	http.ListenAndServe(fmt.Sprintf(":%d", serverPort), nil)
}
