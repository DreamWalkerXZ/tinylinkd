use crate::db::Database;
use crate::error::ApiError;
use crate::users::{self, NewUser, Role, User};

#[derive(Debug, Clone)]
pub struct BootstrapAdmin {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}

impl BootstrapAdmin {
    /// Read bootstrap credentials from the environment.
    ///
    /// Both username and password are required; a partial configuration is
    /// reported and treated as absent so the server still starts.
    pub fn from_env() -> Option<Self> {
        let username = non_empty_env("TLD_BOOTSTRAP_ADMIN_USERNAME");
        let password = non_empty_env("TLD_BOOTSTRAP_ADMIN_PASSWORD");
        let email = non_empty_env("TLD_BOOTSTRAP_ADMIN_EMAIL");
        match (username, password) {
            (Some(username), Some(password)) => Some(Self {
                username,
                password,
                email,
            }),
            (None, None) => {
                if email.is_some() {
                    tracing::warn!(
                        "TLD_BOOTSTRAP_ADMIN_EMAIL is set but no bootstrap username and password are configured"
                    );
                }
                None
            }
            _ => {
                tracing::warn!(
                    "bootstrap Admin requires both TLD_BOOTSTRAP_ADMIN_USERNAME and TLD_BOOTSTRAP_ADMIN_PASSWORD; ignoring partial configuration"
                );
                None
            }
        }
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Create the first Admin from bootstrap credentials.
///
/// Returns `None` when an Admin already exists (the credentials are ignored)
/// or when no credentials were provided. The Instance is allowed to start with
/// no Admin so that an operator can bootstrap later with `tld admin create`.
pub async fn bootstrap_admin(
    db: &Database,
    credentials: Option<BootstrapAdmin>,
) -> Result<Option<User>, ApiError> {
    if users::admin_exists(db).await? {
        if credentials.is_some() {
            tracing::info!("an Admin User already exists; ignoring bootstrap credentials");
        }
        return Ok(None);
    }

    let Some(credentials) = credentials else {
        tracing::warn!(
            "no Admin User exists; bootstrap one with `tld admin create` or TLD_BOOTSTRAP_ADMIN_*"
        );
        return Ok(None);
    };

    let created = users::create_admin_if_none(
        db,
        NewUser {
            username: credentials.username,
            email: credentials.email,
            password: credentials.password,
            role: Role::Admin,
        },
    )
    .await?;

    match &created {
        Some(user) => {
            tracing::info!(user_id = user.id, username = %user.username, "bootstrapped Admin User");
        }
        None => tracing::info!("an Admin User already exists; ignoring bootstrap credentials"),
    }
    Ok(created)
}
