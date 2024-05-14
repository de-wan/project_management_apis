CREATE TABLE project_tasks(
    uuid VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    deadline DATETIME NOT NULL,
    created_at DATETIME DEFAULT NOW() NOT NULL,
    project_uuid VARCHAR(36) NOT NULL,
    archived_at DATETIME,

    FOREIGN KEY (project_uuid) REFERENCES projects(uuid)
)