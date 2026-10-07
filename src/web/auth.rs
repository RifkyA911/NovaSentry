use std::sync::Arc;
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub token: String,
    pub user_id: String,
    pub username: String,
    pub role: String,
}

#[derive(Clone)]
pub struct AuthDb {
    conn: Arc<Mutex<Connection>>,
}

impl AuthDb {
    /// Initialize SQLite connection and run migrations
    pub fn new(db_path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );",
            [],
        )?;

        // Seed default admin account if table is empty
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users;", [], |row| row.get(0))
            .unwrap_or(0);

        if count == 0 {
            let salt = Uuid::new_v4().to_string();
            let hash = Self::hash_password("sentry123", &salt);
            let _ = conn.execute(
                "INSERT INTO users (id, username, password_hash, salt, role, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
                params![
                    Uuid::new_v4().to_string(),
                    "admin",
                    hash,
                    salt,
                    "Chief SOC Officer",
                    Utc::now().to_rfc3339()
                ],
            );
        }

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn hash_password(password: &str, salt: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(b"::");
        hasher.update(salt.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub async fn register(
        &self,
        username: &str,
        password: &str,
        role: &str,
    ) -> Result<(UserInfo, String), String> {
        let trimmed_user = username.trim().to_lowercase();
        if trimmed_user.len() < 3 {
            return Err("Username must be at least 3 characters".to_string());
        }
        if password.len() < 6 {
            return Err("Password must be at least 6 characters".to_string());
        }

        let user_id = Uuid::new_v4().to_string();
        let salt = Uuid::new_v4().to_string();
        let hash = Self::hash_password(password, &salt);
        let now = Utc::now().to_rfc3339();
        let clean_role = if role.trim().is_empty() {
            "Security Analyst".to_string()
        } else {
            role.trim().to_string()
        };

        let conn = self.conn.lock().await;

        let insert_res = conn.execute(
            "INSERT INTO users (id, username, password_hash, salt, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
            params![&user_id, &trimmed_user, &hash, &salt, &clean_role, &now],
        );

        if let Err(e) = insert_res {
            return Err(format!("Registration error (Username may already exist): {}", e));
        }

        let token = format!("sentry_tok_{}", Uuid::new_v4().simple());
        let _ = conn.execute(
            "INSERT INTO sessions (token, user_id, username, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5);",
            params![&token, &user_id, &trimmed_user, &clean_role, &now],
        );

        Ok((
            UserInfo {
                id: user_id,
                username: trimmed_user,
                role: clean_role,
                created_at: now,
            },
            token,
        ))
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<(UserInfo, String), String> {
        let trimmed_user = username.trim().to_lowercase();
        let conn = self.conn.lock().await;

        let mut stmt = conn
            .prepare("SELECT id, username, password_hash, salt, role, created_at FROM users WHERE username = ?1;")
            .map_err(|e| e.to_string())?;

        let user_row = stmt
            .query_row(params![&trimmed_user], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|_| "Invalid username or password".to_string())?;

        let (id, uname, stored_hash, salt, role, created_at) = user_row;
        let incoming_hash = Self::hash_password(password, &salt);

        if incoming_hash != stored_hash {
            return Err("Invalid username or password".to_string());
        }

        let token = format!("sentry_tok_{}", Uuid::new_v4().simple());
        let now = Utc::now().to_rfc3339();

        let _ = conn.execute(
            "INSERT INTO sessions (token, user_id, username, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5);",
            params![&token, &id, &uname, &role, &now],
        );

        Ok((
            UserInfo {
                id,
                username: uname,
                role,
                created_at,
            },
            token,
        ))
    }

    pub async fn validate_token(&self, token: &str) -> Option<UserSession> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT token, user_id, username, role FROM sessions WHERE token = ?1;")
            .ok()?;

        stmt.query_row(params![token], |row| {
            Ok(UserSession {
                token: row.get(0)?,
                user_id: row.get(1)?,
                username: row.get(2)?,
                role: row.get(3)?,
            })
        })
        .ok()
    }

    pub async fn logout(&self, token: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM sessions WHERE token = ?1;", params![token])?;
        Ok(())
    }
}
