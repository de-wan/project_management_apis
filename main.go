package main

import (
	"fmt"
	"log"
	"net/http"

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
	fmt.Println("Hello")

	http.HandleFunc("GET /", handlers.RegisterHandler)

}
