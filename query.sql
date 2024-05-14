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

-- name: GetCurrentUser :one
SELECT uuid, username, email, phone FROM users WHERE uuid = ?;

-- name: ListProjects :many
SELECT * FROM projects WHERE user_uuid = ? AND archived_at IS NULL;

-- name: IsProjectNameTaken :one
SELECT EXISTS(SELECT 1 FROM projects WHERE name = ? AND user_uuid = ?);

-- name: IsProjectNameTakenForProject :one
SELECT EXISTS(SELECT 1 FROM projects WHERE name = ? AND user_uuid = ? AND uuid != ?);

-- name: DoesProjectExist :one
SELECT EXISTS(SELECT 1 FROM projects WHERE uuid=?);

-- name: CreateProject :exec
INSERT INTO projects (uuid, name, description, user_uuid) VALUES
    (?, ?, ?, ?);

-- name: UpdateProject :exec
UPDATE projects SET name= ?, description = ? WHERE uuid = ?;

-- name: ArchiveProject :exec
UPDATE projects SET archived_at = NOW() WHERE uuid = ? AND user_uuid = ?;

-- name: UnarchiveProject :exec
UPDATE projects SET archived_at = NULL WHERE uuid = ? AND user_uuid = ?;

-- name: ListAllProjectTasks :many
SELECT pt.*, p.name AS project_name, p.uuid AS project_uuid FROM project_tasks pt
JOIN projects p ON p.uuid = pt.project_uuid
WHERE p.user_uuid = ? AND p.archived_at IS NULL and pt.archived_at IS NULL;

-- name: ListProjectTasks :many
SELECT pt.*, p.name AS project_name, p.uuid AS project_uuid FROM project_tasks pt
JOIN projects p ON p.uuid = pt.project_uuid
WHERE p.user_uuid = ? AND p.uuid = ? AND p.archived_at IS NULL and pt.archived_at IS NULL;

-- name: IsProjectTaskNameTaken :one
SELECT EXISTS(SELECT 1 FROM project_tasks WHERE name = ? AND project_uuid = ?);

-- name: CreateProjectTask :exec
INSERT INTO project_tasks (uuid, name, deadline, project_uuid) VALUES
    (?, ?, ?, ?);

-- name: DoesProjectTaskExist :one
SELECT EXISTS(SELECT 1 FROM project_tasks pt WHERE pt.uuid = ? AND (SELECT user_uuid FROM projects p WHERE pt.project_uuid = p.uuid) = ?);

-- name: IsProjectTaskNameTakenForProjectTask :one
SELECT EXISTS(SELECT 1 FROM project_tasks WHERE name = ? AND uuid != ?);

-- name: UpdateProjectTask :exec
UPDATE project_tasks SET name = ?, deadline = ? WHERE uuid = ?;

-- name: ArchiveProjectTask :exec
UPDATE project_tasks SET archived_at = NOW() WHERE uuid = ?;

-- name: UnarchiveProjectTask :exec
UPDATE project_tasks SET archived_at = NULL WHERE uuid = ?;
