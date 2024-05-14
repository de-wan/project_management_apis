-- name: IsUsernameTaken :one
SELECT EXISTS(SELECT 1 FROM users WHERE username = ?);

-- name: IsEmailTaken :one
SELECT EXISTS(SELECT 1 FROM users WHERE email = ?);

-- name: IsPhoneTaken :one
SELECT EXISTS(SELECT 1 FROM users WHERE phone = ?);

-- name: RegisterUser :exec
INSERT INTO users (uuid, username, email, phone, password) VALUES
    (?, ?, ?, ?, ?);

-- name: GetDetailsForLogin :one
SELECT * FROM users WHERE username = ? OR email = ?;
