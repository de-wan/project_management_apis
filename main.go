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

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func loadEnv() {
	// load .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}
}

func runMigrations() {
	log.Println("Running migrations...")

	dbUsername := os.Getenv("DB_USERNAME")
	if dbUsername == "" {
		log.Fatal("DB_USERNAME not set in environment")
	}

	dbPassword := os.Getenv("DB_PASSWORD")
	if dbPassword == "" {
		log.Fatal("DB_PASSWORD not set in environment")
	}

	dbServer := os.Getenv("DB_SERVER")
	if dbServer == "" {
		log.Fatal("DB_SERVER not set in environment")
	}

	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		log.Fatal("DB_PORT not set in environment")
	}

	dbDatabase := os.Getenv("DB_DATABASE")
	if dbDatabase == "" {
		log.Fatal("DB_DATABASE not set in environment")
	}

	m, err := migrate.New(
		"file://migrations",
		fmt.Sprintf("mysql://%s:%s@tcp(%s:%s)/%s",
			dbUsername,
			dbPassword,
			dbServer,
			dbPort,
			dbDatabase,
		))

	if err != nil {
		log.Fatal(err)
	}

	m_err := m.Up()
	if m_err != nil {
		log.Println("Up err: ", m_err)
	}

	version, _, err := m.Version()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Migrations are at version: ", version)
	log.Println("Migrations complete")
}

func main() {
	loadEnv()
	runMigrations()

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

	http.HandleFunc("GET /api/v1/current_user", handlers.CurrentUserHandler)

	http.HandleFunc("GET /api/v1/projects", handlers.ListProjectsHandler)
	http.HandleFunc("POST /api/v1/projects", handlers.CreateProjectsHandler)
	http.HandleFunc("PUT /api/v1/projects/", handlers.UpdateProjectsHandler)
	http.HandleFunc("DELETE /api/v1/projects/", handlers.ArchiveProjectsHandler)
	http.HandleFunc("GET /api/v1/archived-projects", handlers.ListArchivedProjectsHandler)
	http.HandleFunc("PUT /api/v1/unarchive-project/", handlers.UnArchiveProjectsHandler)

	http.HandleFunc("GET /api/v1/all-project-tasks", handlers.ListAllProjectTasksHandler)
	http.HandleFunc("GET /api/v1/project-tasks/", handlers.ListProjectTasksHandler)
	http.HandleFunc("POST /api/v1/project-tasks", handlers.CreateProjectTasksHandler)
	http.HandleFunc("PUT /api/v1/project-tasks/", handlers.UpdateProjectTasksHandler)
	http.HandleFunc("DELETE /api/v1/project-tasks/", handlers.ArchiveProjectTaskHandler)
	http.HandleFunc("GET /api/v1/archived-project-tasks/", handlers.ListArchivedProjectTasksHandler)
	http.HandleFunc("PUT /api/v1/unarchive-project-task/", handlers.UnArchiveProjectTaskHandler)

	log.Printf("Starting server on port %d", serverPort)
	http.ListenAndServe(fmt.Sprintf(":%d", serverPort), nil)
}
