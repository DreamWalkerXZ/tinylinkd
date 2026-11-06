# JSON API and admin UI are two adapters over the same services

ADR-0003 described the JSON HTTP API as the first implementation and the admin UI as a later client built on top of it. The UI now exists, but it does not call the JSON API over HTTP: both the JSON API handlers and the server-rendered admin UI handlers are adapters over the same in-process application services (Links, Users, Invites, password resets, Settings, and analytics). Each adapter parses its own input, enforces its own authentication mechanism (Bearer API token versus session cookie), and renders its own response shape.

We chose direct service calls for the UI because sharing the service layer, not a network hop, is what keeps behavior aligned. It also avoids the UI depending on the API's versioned wire format and lets each adapter present errors appropriately, such as inline form messages versus RFC 9457 Problem Details.

The JSON API remains the supported external contract: it is versioned under `/_/api/v1`, documented with OpenAPI, and safe for scripts and integrations to depend on. The admin UI is an internal consumer of the same services and may change its HTML freely. Behavior that both adapters expose must be implemented once in the service layer and covered through both HTTP seams, so a fix or validation rule cannot silently apply to only one of them.
