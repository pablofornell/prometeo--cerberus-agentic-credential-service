//! Storage errors. No message holds a row value, so an error is safe to log (ADR-0032).

use cerberus_crypto::CryptoError;
use sqlx::error::ErrorKind;

/// An error from the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database engine failed.
    #[error("database error")]
    Db(sqlx::Error),
    /// A migration failed.
    #[error("migration error")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// The file is not a Cerberus vault (wrong or missing application ID, or not a database).
    #[error("not a Cerberus vault")]
    NotAVault,
    /// The vault was made by a newer version of the app (ADR-0013 point 3, error `vault_too_new`).
    #[error("vault made by a newer version")]
    TooNew {
        /// Schema version in the file.
        found: i64,
        /// Newest schema version this build knows.
        supported: i64,
    },
    /// The row does not exist (or has expired).
    #[error("row not found")]
    NotFound,
    /// A constraint stopped the write: a duplicate key, a CHECK or a foreign key.
    #[error("constraint violated")]
    Conflict,
    /// A stored value is out of range or has a wrong shape.
    #[error("corrupt row")]
    Corrupt,
    /// A file operation failed.
    #[error("io error")]
    Io(#[from] std::io::Error),
    /// A restore moved the old vault file aside, then failed, and could not move it back. The old
    /// vault (with its `-wal` and `-shm`) is at `moved`; nothing was deleted (NEW-10).
    #[error("restore failed; the old vault file is left at its .pre-restore name")]
    RestoreStranded {
        /// Where the old vault file is now.
        moved: std::path::PathBuf,
    },
    /// Sealing or opening a blob failed. A moved or changed blob gives `CryptoError::Integrity`.
    #[error("crypto error")]
    Crypto(#[from] CryptoError),
}

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> Self {
        match &error {
            sqlx::Error::RowNotFound => Self::NotFound,
            sqlx::Error::Database(db)
                if matches!(
                    db.kind(),
                    ErrorKind::UniqueViolation
                        | ErrorKind::ForeignKeyViolation
                        | ErrorKind::NotNullViolation
                        | ErrorKind::CheckViolation
                ) =>
            {
                Self::Conflict
            }
            _ => Self::Db(error),
        }
    }
}
