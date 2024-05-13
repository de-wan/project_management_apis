package db_sqlc

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

// Init initializes the database connection pool.
func Init() {
	// load connection string from .env
	dbConnString := os.Getenv("DB_CONN_STRING")
	if dbConnString == "" {
		log.Fatal("DB_CONN_STRING not set in .env")
	}

	// Open a database connection
	var err error
	DB, err = sql.Open("mysql", dbConnString)
	if err != nil {
		log.Fatal(err)
	}

	// Test the database connection
	err = DB.Ping()
	if err != nil {
		log.Fatal("Error connecting to the database: ", err)
	}
}
