use serde::Serialize;
use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row, Sqlite, SqliteConnection};
use url::Url;
use utoipa::ToSchema;

use crate::db::Database;
use crate::error::ApiError;
use crate::timeutil;

pub const SLUG_MIN_LEN: usize = 3;
pub const SLUG_MAX_LEN: usize = 64;
pub const RANDOM_SLUG_LEN: usize = 8;
pub const RANDOM_SLUG_ATTEMPTS: usize = 10;

const SLUG_ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LinkStatus {
    Active,
    Expired,
}

#[derive(Debug, Clone)]
pub struct Link {
    pub id: i64,
    pub owner_id: i64,
    pub slug: String,
    pub destination_url: String,
    pub has_password: bool,
    pub password_version: i64,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub total_clicks: i64,
    pub human_clicks: i64,
    pub bot_clicks: i64,
}

impl Link {
    pub fn status(&self) -> LinkStatus {
        let Some(expires_at) = &self.expires_at else {
            return LinkStatus::Active;
        };
        match timeutil::parse_rfc3339(expires_at) {
            Ok(expires_at) if expires_at <= timeutil::now() => LinkStatus::Expired,
            Ok(_) => LinkStatus::Active,
            Err(error) => {
                tracing::error!(error = %error, "stored Link expiry is not RFC 3339");
                LinkStatus::Active
            }
        }
    }

    /// Whether the Link's expiry is at or before the current time.
    pub fn is_expired(&self) -> bool {
        self.status() == LinkStatus::Expired
    }
}

/// Validate a Slug: 3-64 characters using ASCII `a-z`, `0-9`, and internal
/// hyphens. It must start and end with a letter or digit. Uppercase input is
/// invalid and is never normalized.
pub fn validate_slug(slug: &str) -> Result<(), ApiError> {
    let bytes = slug.as_bytes();
    let length_ok = (SLUG_MIN_LEN..=SLUG_MAX_LEN).contains(&bytes.len());
    let characters_ok = bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    let edges_ok = matches!(bytes.first(), Some(byte) if byte.is_ascii_alphanumeric())
        && matches!(bytes.last(), Some(byte) if byte.is_ascii_alphanumeric());
    if length_ok && characters_ok && edges_ok {
        Ok(())
    } else {
        Err(ApiError::validation(
            "invalid_slug",
            "Slug must be 3-64 characters using ASCII lowercase letters, digits, and internal \
             hyphens, and must start and end with a letter or digit.",
        ))
    }
}

/// Validate a Destination URL: an absolute `http` or `https` URL. The URL is
/// stored as provided and is never fetched.
pub fn validate_destination_url(value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    let parsed = Url::parse(trimmed).map_err(|_| invalid_destination_url())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(invalid_destination_url());
    }
    Ok(trimmed.to_string())
}

fn invalid_destination_url() -> ApiError {
    ApiError::validation(
        "invalid_destination_url",
        "Destination URL must be an absolute http or https URL.",
    )
}

/// Generate a random 8-character Slug from `a-z0-9`.
pub fn random_slug() -> Result<String, ApiError> {
    let mut bytes = [0u8; RANDOM_SLUG_LEN];
    getrandom::fill(&mut bytes).map_err(|error| {
        ApiError::internal(format!("failed to generate a random Slug: {error}"))
    })?;
    Ok(bytes
        .iter()
        .map(|byte| SLUG_ALPHABET[usize::from(*byte) % SLUG_ALPHABET.len()] as char)
        .collect())
}

pub async fn create_link(
    db: &Database,
    owner_id: i64,
    destination_url: &str,
    slug: Option<&str>,
) -> Result<Link, ApiError> {
    let destination_url = validate_destination_url(destination_url)?;
    match slug {
        Some(slug) => {
            validate_slug(slug)?;
            create_with_slug(db, owner_id, &destination_url, slug).await
        }
        None => create_with_generated_slug(db, owner_id, &destination_url, random_slug).await,
    }
}

async fn create_with_slug(
    db: &Database,
    owner_id: i64,
    destination_url: &str,
    slug: &str,
) -> Result<Link, ApiError> {
    let now = timeutil::now_rfc3339();
    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    if slug_exists(&mut transaction, slug).await? {
        transaction.rollback().await?;
        return Err(ApiError::conflict("slug_taken", "Slug is already taken."));
    }
    let link = insert_link(&mut transaction, owner_id, slug, destination_url, &now).await?;
    transaction.commit().await?;
    Ok(link)
}

/// Create a Link with a generated Slug, retrying collisions up to
/// `RANDOM_SLUG_ATTEMPTS` times.
async fn create_with_generated_slug(
    db: &Database,
    owner_id: i64,
    destination_url: &str,
    mut next_slug: impl FnMut() -> Result<String, ApiError>,
) -> Result<Link, ApiError> {
    let now = timeutil::now_rfc3339();
    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    for _ in 0..RANDOM_SLUG_ATTEMPTS {
        let slug = next_slug()?;
        if slug_exists(&mut transaction, &slug).await? {
            continue;
        }
        let link = insert_link(&mut transaction, owner_id, &slug, destination_url, &now).await?;
        transaction.commit().await?;
        return Ok(link);
    }
    transaction.rollback().await?;
    Err(ApiError::internal(
        "failed to generate a unique random Slug after 10 attempts",
    ))
}

/// Link columns plus the click counts exposed by the API.
const LINK_SELECT: &str = "
    l.id, l.owner_id, l.slug, l.destination_url,
    (l.password_hash IS NOT NULL) AS has_password,
    l.password_version,
    l.expires_at, l.created_at, l.updated_at,
    (SELECT COUNT(*) FROM clicks c WHERE c.link_id = l.id) AS total_clicks,
    (SELECT COUNT(*) FROM clicks c WHERE c.link_id = l.id AND c.is_bot = 0) AS human_clicks,
    (SELECT COUNT(*) FROM clicks c WHERE c.link_id = l.id AND c.is_bot = 1) AS bot_clicks
";

fn link_from_row(row: &SqliteRow) -> Result<Link, ApiError> {
    Ok(Link {
        id: row.try_get("id")?,
        owner_id: row.try_get("owner_id")?,
        slug: row.try_get("slug")?,
        destination_url: row.try_get("destination_url")?,
        has_password: row.try_get::<i64, _>("has_password")? != 0,
        password_version: row.try_get("password_version")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        total_clicks: row.try_get("total_clicks")?,
        human_clicks: row.try_get("human_clicks")?,
        bot_clicks: row.try_get("bot_clicks")?,
    })
}

pub async fn find_by_id(db: &Database, id: i64) -> Result<Option<Link>, ApiError> {
    let row = sqlx::query(&format!("SELECT {LINK_SELECT} FROM links l WHERE l.id = ?"))
        .bind(id)
        .fetch_optional(db.read_pool())
        .await?;
    row.as_ref().map(link_from_row).transpose()
}

async fn find_by_id_on(
    connection: &mut SqliteConnection,
    id: i64,
) -> Result<Option<Link>, ApiError> {
    let row = sqlx::query(&format!("SELECT {LINK_SELECT} FROM links l WHERE l.id = ?"))
        .bind(id)
        .fetch_optional(&mut *connection)
        .await?;
    row.as_ref().map(link_from_row).transpose()
}

/// The warning returned when a Link's Slug changes: the old short URL stops
/// working immediately and may be claimed by another Link.
pub const SLUG_RELEASE_WARNING: &str =
    "The old Slug stops working immediately and may be reused by another Link.";

/// Validate a Link expiry and normalize it to RFC 3339 UTC with the `Z`
/// designator.
pub fn normalize_expiry(value: &str) -> Result<String, ApiError> {
    let parsed = timeutil::parse_rfc3339(value).map_err(|_| {
        ApiError::validation(
            "invalid_expires_at",
            "expires_at must be an RFC 3339 timestamp.",
        )
    })?;
    Ok(timeutil::format_rfc3339(parsed))
}

#[derive(Debug, Clone)]
pub struct LinkChanges {
    pub destination_url: Option<String>,
    pub slug: Option<String>,
    /// Admin-only: the User who will own the Link.
    pub owner_id: Option<i64>,
    /// `None` leaves the password unchanged, `Some(None)` clears it, and
    /// `Some(Some(password))` sets or changes it.
    pub password: Option<Option<String>>,
    /// `None` leaves the expiry unchanged, `Some(None)` clears it, and
    /// `Some(Some(expires_at))` sets or extends it.
    pub expires_at: Option<Option<String>>,
}

#[derive(Debug, Clone)]
pub struct UpdatedLink {
    pub link: Link,
    pub warning: Option<String>,
}

/// Edit a Link. Only its owner or an Admin may update it. A Slug change is a
/// read-modify-write inside one `BEGIN IMMEDIATE` transaction, so the old Slug
/// is released and the new one claimed atomically.
pub async fn update_link(
    db: &Database,
    link_id: i64,
    actor_id: i64,
    is_admin: bool,
    changes: LinkChanges,
) -> Result<UpdatedLink, ApiError> {
    if changes.owner_id.is_some() && !is_admin {
        return Err(ApiError::forbidden(
            "Only Admins may transfer Link ownership.",
        ));
    }
    let destination_url = changes
        .destination_url
        .as_deref()
        .map(validate_destination_url)
        .transpose()?;
    if let Some(slug) = changes.slug.as_deref() {
        validate_slug(slug)?;
    }
    // Hash outside the write transaction: Argon2id is deliberately expensive
    // and must not hold the SQLite writer lock.
    let password_hash: Option<Option<String>> = match changes.password.as_ref() {
        None => None,
        Some(None) => Some(None),
        Some(Some(password)) => {
            crate::users::validate_password(password)?;
            let hash = crate::auth::hash_password(password).map_err(|error| {
                ApiError::internal(format!("failed to hash the Link password: {error}"))
            })?;
            Some(Some(hash))
        }
    };
    let expires_at: Option<Option<String>> = match changes.expires_at.as_ref() {
        None => None,
        Some(None) => Some(None),
        Some(Some(value)) => Some(Some(normalize_expiry(value)?)),
    };

    let now = timeutil::now_rfc3339();
    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    let Some(current) = find_by_id_on(&mut transaction, link_id).await? else {
        transaction.rollback().await?;
        return Err(ApiError::not_found("Link not found."));
    };
    if let Err(error) = ensure_can_manage(&current, actor_id, is_admin, "edit") {
        transaction.rollback().await?;
        return Err(error);
    }

    let owner_id = changes.owner_id.unwrap_or(current.owner_id);
    if owner_id != current.owner_id {
        let owner_exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id = ?")
            .bind(owner_id)
            .fetch_optional(&mut *transaction)
            .await?;
        if owner_exists.is_none() {
            transaction.rollback().await?;
            return Err(ApiError::not_found("User not found."));
        }
    }

    let slug = changes.slug.as_deref().unwrap_or(&current.slug);
    let slug_changed = slug != current.slug;
    if slug_changed && slug_exists(&mut transaction, slug).await? {
        transaction.rollback().await?;
        return Err(ApiError::conflict("slug_taken", "Slug is already taken."));
    }

    let destination_url = destination_url
        .as_deref()
        .unwrap_or(&current.destination_url);
    let owner_changed = owner_id != current.owner_id;
    let password_changed = password_hash.is_some();
    let expiry_changed = expires_at.is_some();
    let changed = slug_changed
        || destination_url != current.destination_url
        || owner_changed
        || password_changed
        || expiry_changed;
    let mut warning = None;
    if changed {
        let password_hash = password_hash.flatten();
        let expires_at = expires_at.flatten();
        sqlx::query(
            "UPDATE links
             SET slug = ?, destination_url = ?, owner_id = ?,
                 password_hash = CASE WHEN ? THEN ? ELSE password_hash END,
                 password_version =
                     CASE WHEN ? THEN password_version + 1 ELSE password_version END,
                 expires_at = CASE WHEN ? THEN ? ELSE expires_at END,
                 updated_at = ?
             WHERE id = ?",
        )
        .bind(slug)
        .bind(destination_url)
        .bind(owner_id)
        .bind(i64::from(password_changed))
        .bind(&password_hash)
        .bind(i64::from(password_changed))
        .bind(i64::from(expiry_changed))
        .bind(&expires_at)
        .bind(&now)
        .bind(link_id)
        .execute(&mut *transaction)
        .await?;
        if slug_changed {
            warning = Some(SLUG_RELEASE_WARNING.to_string());
        }
    }

    let link = find_by_id_on(&mut transaction, link_id)
        .await?
        .ok_or_else(|| ApiError::internal("the edited Link disappeared"))?;
    transaction.commit().await?;
    Ok(UpdatedLink { link, warning })
}

/// Hard-delete a Link. Only its owner or an Admin may delete it. The Link's
/// Clicks cascade and its Slug is released in the same transaction.
pub async fn delete_link(
    db: &Database,
    link_id: i64,
    actor_id: i64,
    is_admin: bool,
) -> Result<(), ApiError> {
    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    let Some(link) = find_by_id_on(&mut transaction, link_id).await? else {
        transaction.rollback().await?;
        return Err(ApiError::not_found("Link not found."));
    };
    if let Err(error) = ensure_can_manage(&link, actor_id, is_admin, "delete") {
        transaction.rollback().await?;
        return Err(error);
    }
    sqlx::query("DELETE FROM links WHERE id = ?")
        .bind(link_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

fn ensure_can_manage(
    link: &Link,
    actor_id: i64,
    is_admin: bool,
    action: &str,
) -> Result<(), ApiError> {
    if link.owner_id != actor_id && !is_admin {
        return Err(ApiError::forbidden(format!(
            "You do not have permission to {action} this Link."
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSort {
    CreatedAtAsc,
    CreatedAtDesc,
}

#[derive(Debug, Clone)]
pub struct LinkFilter {
    pub owner_id: Option<i64>,
    pub status: Option<LinkStatus>,
    pub q: Option<String>,
    pub sort: LinkSort,
    pub limit: i64,
    pub offset: i64,
}

pub async fn list_links(db: &Database, filter: &LinkFilter) -> Result<(Vec<Link>, i64), ApiError> {
    let now = timeutil::now_rfc3339();

    let mut count = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM links l");
    push_list_filters(&mut count, filter, &now);
    let total: i64 = count.build_query_scalar().fetch_one(db.read_pool()).await?;

    let mut select = QueryBuilder::<Sqlite>::new(format!("SELECT {LINK_SELECT} FROM links l"));
    push_list_filters(&mut select, filter, &now);
    match filter.sort {
        LinkSort::CreatedAtAsc => select.push(" ORDER BY l.created_at ASC, l.id ASC"),
        LinkSort::CreatedAtDesc => select.push(" ORDER BY l.created_at DESC, l.id DESC"),
    };
    select
        .push(" LIMIT ")
        .push_bind(filter.limit)
        .push(" OFFSET ")
        .push_bind(filter.offset);
    let rows = select.build().fetch_all(db.read_pool()).await?;

    let links = rows
        .iter()
        .map(link_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((links, total))
}

fn push_list_filters<'a>(
    builder: &mut QueryBuilder<'a, Sqlite>,
    filter: &LinkFilter,
    now: &'a str,
) {
    builder.push(" WHERE 1 = 1");
    if let Some(owner_id) = filter.owner_id {
        builder.push(" AND l.owner_id = ").push_bind(owner_id);
    }
    match filter.status {
        Some(LinkStatus::Active) => {
            builder
                .push(" AND (l.expires_at IS NULL OR julianday(l.expires_at) > julianday(")
                .push_bind(now)
                .push("))");
        }
        Some(LinkStatus::Expired) => {
            builder
                .push(" AND l.expires_at IS NOT NULL AND julianday(l.expires_at) <= julianday(")
                .push_bind(now)
                .push(")");
        }
        None => {}
    }
    if let Some(q) = filter.q.as_deref().filter(|q| !q.is_empty()) {
        let pattern = format!("%{}%", escape_like(q));
        builder
            .push(" AND (l.slug LIKE ")
            .push_bind(pattern.clone())
            .push(" ESCAPE '\\' OR l.destination_url LIKE ")
            .push_bind(pattern)
            .push(" ESCAPE '\\')");
    }
}

/// Escape `%`, `_`, and the escape character itself for a SQLite `LIKE`
/// pattern that uses `ESCAPE '\'`.
fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

pub async fn find_by_slug(db: &Database, slug: &str) -> Result<Option<Link>, ApiError> {
    let row = sqlx::query(&format!(
        "SELECT {LINK_SELECT} FROM links l WHERE l.slug = ?"
    ))
    .bind(slug)
    .fetch_optional(db.read_pool())
    .await?;
    row.as_ref().map(link_from_row).transpose()
}

/// The stored password hash for a Link, used only to verify a visitor's
/// password. The hash is never exposed through the API.
pub async fn find_password_hash(db: &Database, link_id: i64) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT password_hash FROM links WHERE id = ?")
        .bind(link_id)
        .fetch_optional(db.read_pool())
        .await?;
    match row {
        None => Ok(None),
        Some(row) => Ok(row.try_get::<Option<String>, _>("password_hash")?),
    }
}

/// Append a short URL's query string to a Destination URL's query component,
/// before any fragment, using `&` when the Destination URL already has a query.
pub fn redirect_target(destination_url: &str, query: Option<&str>) -> String {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return destination_url.to_string();
    };
    match destination_url.split_once('#') {
        Some((before_fragment, fragment)) => {
            format!("{}#{}", append_query_to(before_fragment, query), fragment)
        }
        None => append_query_to(destination_url, query),
    }
}

fn append_query_to(destination: &str, query: &str) -> String {
    if !destination.contains('?') {
        format!("{destination}?{query}")
    } else if destination.ends_with('?') || destination.ends_with('&') {
        format!("{destination}{query}")
    } else {
        format!("{destination}&{query}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Device {
    Desktop,
    Mobile,
    Tablet,
    Bot,
    Unknown,
}

impl Device {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Mobile => "mobile",
            Self::Tablet => "tablet",
            Self::Bot => "bot",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewClick {
    pub ip: String,
    pub user_agent: String,
    pub referer: Option<String>,
    pub device: Device,
    pub is_bot: bool,
}

/// Classify a User-Agent into a device type and bot flag using a small set of
/// common crawler and browser patterns. No external service is called.
pub fn classify_user_agent(user_agent: &str) -> (Device, bool) {
    let user_agent = user_agent.to_ascii_lowercase();
    if contains_any(
        &user_agent,
        &[
            "bot",
            "crawler",
            "spider",
            "slurp",
            "bingpreview",
            "facebookexternalhit",
            "headlesschrome",
            "phantomjs",
            "curl/",
            "wget/",
            "python-requests",
            "go-http-client",
            "okhttp",
            "java/",
        ],
    ) {
        return (Device::Bot, true);
    }
    if contains_any(
        &user_agent,
        &["ipad", "tablet", "kindle", "silk/", "playbook"],
    ) || (user_agent.contains("android") && !user_agent.contains("mobile"))
    {
        return (Device::Tablet, false);
    }
    if contains_any(
        &user_agent,
        &[
            "mobile",
            "iphone",
            "ipod",
            "android",
            "blackberry",
            "windows phone",
            "opera mini",
            "iemobile",
        ],
    ) {
        return (Device::Mobile, false);
    }
    if contains_any(
        &user_agent,
        &["windows nt", "macintosh", "x11", "linux", "cros"],
    ) {
        return (Device::Desktop, false);
    }
    (Device::Unknown, false)
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

/// Record a Click. The caller treats failures as best-effort.
pub async fn record_click(db: &Database, link_id: i64, click: NewClick) -> Result<(), ApiError> {
    let now = timeutil::now_rfc3339();
    sqlx::query(
        "INSERT INTO clicks (link_id, clicked_at, ip, user_agent, referer, device, is_bot, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(link_id)
    .bind(&now)
    .bind(&click.ip)
    .bind(&click.user_agent)
    .bind(&click.referer)
    .bind(click.device.as_str())
    .bind(if click.is_bot { 1_i64 } else { 0_i64 })
    .bind(&now)
    .execute(db.write_pool())
    .await?;
    Ok(())
}

async fn slug_exists(connection: &mut SqliteConnection, slug: &str) -> Result<bool, ApiError> {
    let exists: i64 = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM links WHERE slug = ?)")
        .bind(slug)
        .fetch_one(&mut *connection)
        .await?;
    Ok(exists != 0)
}

async fn insert_link(
    connection: &mut SqliteConnection,
    owner_id: i64,
    slug: &str,
    destination_url: &str,
    now: &str,
) -> Result<Link, ApiError> {
    let result = sqlx::query(
        "INSERT INTO links (owner_id, slug, destination_url, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(owner_id)
    .bind(slug)
    .bind(destination_url)
    .bind(now)
    .bind(now)
    .execute(&mut *connection)
    .await?;

    Ok(Link {
        id: result.last_insert_rowid(),
        owner_id,
        slug: slug.to_string(),
        destination_url: destination_url.to_string(),
        has_password: false,
        password_version: 1,
        expires_at: None,
        created_at: now.to_string(),
        updated_at: now.to_string(),
        total_clicks: 0,
        human_clicks: 0,
        bot_clicks: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepts(slug: &str) {
        assert!(validate_slug(slug).is_ok(), "expected {slug:?} to be valid");
    }

    fn rejects(slug: &str) {
        assert!(
            validate_slug(slug).is_err(),
            "expected {slug:?} to be invalid"
        );
    }

    #[test]
    fn slug_validation_enforces_the_spec_rules() {
        accepts("abc");
        accepts("123");
        accepts("a1b2");
        accepts("a-b-c");
        accepts("a--b");
        accepts(&"a".repeat(SLUG_MIN_LEN));
        accepts(&"a".repeat(SLUG_MAX_LEN));

        rejects("");
        rejects("ab");
        rejects(&"a".repeat(SLUG_MAX_LEN + 1));
        rejects("Abc");
        rejects("ABC");
        rejects("-abc");
        rejects("abc-");
        rejects("-");
        rejects("a_b");
        rejects("a.b");
        rejects("a b");
        rejects("caf\u{e9}");
        rejects("a/b");
    }

    #[test]
    fn random_slugs_are_eight_lowercase_alphanumeric_characters() {
        for _ in 0..100 {
            let slug = random_slug().expect("random slug");
            assert_eq!(slug.len(), RANDOM_SLUG_LEN);
            assert!(
                slug.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
                "unexpected character in {slug}"
            );
        }
    }

    async fn test_user(db: &Database) -> crate::users::User {
        crate::users::create_user(
            db,
            crate::users::NewUser {
                username: "alice".into(),
                email: None,
                password: "correct horse battery staple".into(),
                role: crate::users::Role::User,
            },
        )
        .await
        .expect("create user")
    }

    #[tokio::test]
    async fn generated_slugs_retry_on_collision() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = Database::connect(dir.path()).await.expect("database");
        let user = test_user(&db).await;
        create_link(&db, user.id, "https://example.com/", Some("taken123"))
            .await
            .expect("seed link");

        let mut candidates = ["taken123", "taken123", "free1234"].into_iter();
        let link = create_with_generated_slug(&db, user.id, "https://example.com/", || {
            candidates
                .next()
                .map(str::to_string)
                .ok_or_else(|| ApiError::internal("no more candidates"))
        })
        .await
        .expect("link created after retries");

        assert_eq!(link.slug, "free1234");
    }

    #[tokio::test]
    async fn generated_slugs_give_up_after_ten_collisions() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = Database::connect(dir.path()).await.expect("database");
        let user = test_user(&db).await;
        create_link(&db, user.id, "https://example.com/", Some("taken123"))
            .await
            .expect("seed link");

        let result = create_with_generated_slug(&db, user.id, "https://example.com/", || {
            Ok::<_, ApiError>("taken123".to_string())
        })
        .await;

        assert!(result.is_err(), "expected Slug generation to give up");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM links")
            .fetch_one(db.read_pool())
            .await
            .expect("count links");
        assert_eq!(count, 1, "a failed creation must not insert a Link");
    }
}
