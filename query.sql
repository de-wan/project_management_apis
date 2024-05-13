-- name: IsUsernameTaken :one
SELECT 1 FROM users WHERE username = ?;

-- name: IsEmailTaken :one
SELECT 1 FROM users WHERE email = ?;

-- name: IsPhoneTaken :one
SELECT 1 FROM users WHERE phone = ?;

-- name: RegisterUser :exec
INSERT INTO users (uuid, username, email, phone, password) VALUES
    (?, ?, ?, ?, ?);