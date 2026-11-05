use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::app::AppState;
use crate::problems::ProblemDetails;
use crate::timeutil;
use crate::tokens;
use crate::users::User;

pub const API_TOKEN_PREFIX_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct GeneratedApiToken {
    pub plaintext: String,
    pub hash: String,
    pub prefix: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub fn hash_token(plaintext: &str) -> String {
    sha256_hex(plaintext.as_bytes())
}

/// Generate an API token: `tld_` followed by 32 random bytes as base64url.
pub fn generate_api_token() -> Result<GeneratedApiToken, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    let plaintext = format!("tld_{}", URL_SAFE_NO_PAD.encode(bytes));
    let hash = hash_token(&plaintext);
    let prefix = plaintext[..API_TOKEN_PREFIX_LEN].to_string();
    Ok(GeneratedApiToken {
        plaintext,
        hash,
        prefix,
    })
}

fn argon2() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 3, 4, None).expect("valid Argon2id parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let mut salt_bytes = [0u8; 16];
    getrandom::fill(&mut salt_bytes).map_err(|_| argon2::password_hash::Error::Crypto)?;
    let salt = SaltString::encode_b64(&salt_bytes)?;
    Ok(argon2()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// The authenticated User behind the current Bearer API token.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub user: User,
    pub token_id: i64,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ProblemDetails;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let instance = parts.uri.path().to_string();

        let header_value = parts
            .headers
            .get(header::AUTHORIZATION)
            .ok_or_else(|| {
                ProblemDetails::unauthorized(
                    "authentication_required",
                    "A Bearer API token is required.",
                    &instance,
                )
            })?
            .to_str()
            .map_err(|_| {
                ProblemDetails::unauthorized(
                    "invalid_token",
                    "The Authorization header is not valid UTF-8.",
                    &instance,
                )
            })?;
        let (scheme, token) = header_value.split_once(' ').ok_or_else(|| {
            ProblemDetails::unauthorized(
                "invalid_token",
                "The Authorization header must use the Bearer scheme.",
                &instance,
            )
        })?;
        if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
            return Err(ProblemDetails::unauthorized(
                "invalid_token",
                "The Authorization header must use the Bearer scheme.",
                &instance,
            ));
        }

        let mut connection = state
            .db
            .read_pool()
            .acquire()
            .await
            .map_err(|error| database_problem(&instance, error))?;
        let found = tokens::authenticate(&mut connection, &hash_token(token))
            .await
            .map_err(|error| error.into_problem(&instance))?;
        drop(connection);

        let Some((token_summary, user)) = found else {
            return Err(ProblemDetails::unauthorized(
                "invalid_token",
                "The API token is invalid.",
                &instance,
            ));
        };

        if token_summary.revoked_at.is_some() {
            return Err(ProblemDetails::unauthorized(
                "token_revoked",
                "The API token has been revoked.",
                &instance,
            ));
        }
        if let Some(expires_at) = &token_summary.expires_at {
            let expires_at = timeutil::parse_rfc3339(expires_at).map_err(|error| {
                tracing::error!(error = %error, "stored API token expiry is not RFC 3339");
                ProblemDetails::internal_error(&instance)
            })?;
            if expires_at <= timeutil::now() {
                return Err(ProblemDetails::unauthorized(
                    "token_expired",
                    "The API token has expired.",
                    &instance,
                ));
            }
        }
        if user.disabled_at.is_some() {
            return Err(ProblemDetails::unauthorized(
                "user_disabled",
                "The User is disabled.",
                &instance,
            ));
        }

        let now = timeutil::now_rfc3339();
        if let Err(error) = sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
            .bind(&now)
            .bind(token_summary.id)
            .execute(state.db.write_pool())
            .await
        {
            tracing::warn!(error = %error, "failed to record API token last use");
        }

        Ok(CurrentUser {
            user,
            token_id: token_summary.id,
        })
    }
}

fn database_problem(instance: &str, error: sqlx::Error) -> ProblemDetails {
    tracing::error!(error = %error, "database error while authenticating API token");
    ProblemDetails::internal_error(instance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::Role;

    #[test]
    fn sha256_hex_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn generated_api_tokens_use_the_tld_prefix_and_are_unique() {
        let first = generate_api_token().expect("token");
        let second = generate_api_token().expect("token");

        assert!(first.plaintext.starts_with("tld_"), "{}", first.plaintext);
        assert_eq!(first.plaintext.len(), "tld_".len() + 43);
        assert_ne!(first.plaintext, second.plaintext);
        assert_eq!(first.prefix, first.plaintext[..12]);
        assert_eq!(first.hash, sha256_hex(first.plaintext.as_bytes()));
        assert_eq!(first.hash.len(), 64);
    }

    #[test]
    fn passwords_are_argon2id_hashed_with_the_spec_parameters_and_verified() {
        let hash = hash_password("correct horse battery staple").expect("hash");

        assert!(
            hash.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"),
            "{hash}"
        );
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn roles_round_trip_through_their_storage_representation() {
        assert_eq!(Role::parse(Role::Admin.as_str()), Some(Role::Admin));
        assert_eq!(Role::parse(Role::User.as_str()), Some(Role::User));
        assert_eq!(Role::parse("owner"), None);
    }
}
