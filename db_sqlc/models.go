// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package db_sqlc

import (
	"time"
)

type User struct {
	Uuid      string
	Username  string
	Email     string
	Phone     string
	Password  string
	CreatedAt time.Time
}
