use rusqlite::Connection;
use std::{fs, path::Path, time::Duration};

pub fn open(path: &Path) -> Result<Connection, Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    // Restrict the file before opening SQLite; WAL files inherit its permissions.
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    // Closing another descriptor after SQLite opens would release its POSIX locks.
    drop(file);
    let db = Connection::open(path)?;
    db.busy_timeout(Duration::from_secs(2))?;
    db.execute_batch("
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        PRAGMA foreign_keys=ON;
        PRAGMA cache_size=-1024;
        PRAGMA journal_size_limit=1048576;
        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY, secret TEXT, redirects TEXT NOT NULL, created INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pending (
            code TEXT PRIMARY KEY, csrf TEXT NOT NULL, client TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            redirect TEXT NOT NULL, challenge TEXT NOT NULL, state TEXT NOT NULL, expires INTEGER NOT NULL,
            approved INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS grants (
            access TEXT PRIMARY KEY, refresh TEXT UNIQUE NOT NULL,
            client TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            expires INTEGER NOT NULL, refresh_expires INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS grants_client ON grants(client);
        CREATE TABLE IF NOT EXISTS login (id INTEGER PRIMARY KEY CHECK(id=1), failures INTEGER NOT NULL, locks INTEGER NOT NULL, until INTEGER NOT NULL);
        INSERT OR IGNORE INTO login VALUES (1,0,0,0);
    ")?;
    Ok(db)
}

pub fn cleanup(db: &Connection) -> rusqlite::Result<()> {
    db.execute("DELETE FROM pending WHERE expires <= ?", [super::now()])?;
    db.execute(
        "DELETE FROM grants WHERE refresh_expires <= ?",
        [super::now()],
    )?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn database_reader_process() {
        let Some(path) = std::env::var_os("MCP_SQLITE_LOCK_TEST_PATH") else {
            return;
        };
        let db = Connection::open(path).unwrap();
        let count: u64 = db
            .query_row("SELECT count(*) FROM clients", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn another_process_cannot_unlink_an_active_wal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oauth.sqlite");
        let db = open(&path).unwrap();
        db.execute("INSERT INTO clients VALUES ('test',NULL,'[]',0)", [])
            .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "store::tests::database_reader_process"])
            .env("MCP_SQLITE_LOCK_TEST_PATH", &path)
            .output()
            .unwrap();
        assert!(child.status.success(), "{child:?}");
        assert!(
            dir.path().join("oauth.sqlite-wal").exists(),
            "another process removed the WAL while the server still held it open"
        );
        drop(db);
        let reopened = Connection::open(path).unwrap();
        let count: u64 = reopened
            .query_row("SELECT count(*) FROM clients", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
