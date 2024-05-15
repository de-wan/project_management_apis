CREATE TABLE projects(
    uuid VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description VARCHAR(255) NOT NULL,
    user_uuid VARCHAR(36) NOT NULL,
    created_at DATETIME DEFAULT NOW() NOT NULL,
    archived_at DATETIME,

    FOREIGN KEY (user_uuid) REFERENCES users(uuid)
)