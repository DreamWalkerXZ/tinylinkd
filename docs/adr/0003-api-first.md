# API first, admin UI later

The first implementation exposes a JSON HTTP API for authentication, Link management, analytics, and administration; the admin UI is built afterwards on top of that API. This was chosen so the core behavior and contracts are testable and scriptable without committing to a frontend early. The public redirect path still needs minimal server-rendered pages for password entry, expired Links, and not-found responses, because browser visitors cannot use the JSON API for those.
