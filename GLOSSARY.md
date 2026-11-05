# tinylinkd

A small, self-hosted URL shortener. An Instance serves a small set of Users who create Links that redirect visitors to Destination URLs.

## Language

**Instance**:
One self-hosted deployment of tinylinkd, with its own database and Users.
_Avoid_: Deployment, tenant, workspace

**User**:
A login account in an Instance. A User owns the Links they create.
_Avoid_: Account, member

**API token**:
A bearer credential owned by a User that authenticates API requests with that User's permissions.
_Avoid_: API key, access token

**Invite**:
A one-time credential that lets a person create a User account in an Instance.
_Avoid_: Invitation, signup link

**Admin**:
A User role with instance-wide management rights over Users, Links, and settings.
_Avoid_: Owner, superuser, administrator

**Link**:
A short-link record owned by exactly one User. A Link has one current Slug, one Destination URL, and optional password and expiry settings.
_Avoid_: Short link, URL record, redirect

**Slug**:
The path segment at the root URL that identifies a Link, as in `https://host/<slug>`.
_Avoid_: Path, code

**Destination URL**:
The `http` or `https` URL that a Link redirects to.
_Avoid_: Target, long URL, original URL

**Click**:
One successfully recorded visit through a Link's redirect, stored for analytics.
_Avoid_: Visit, hit, view, event

**Password-protected Link**:
A Link that requires a correct password before it redirects.
_Avoid_: Locked link, private link

**Expired Link**:
A Link whose expiry time has passed and which no longer redirects.
_Avoid_: Dead link, inactive link
