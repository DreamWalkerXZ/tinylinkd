# Redirects do not depend on analytics writes

A short-link redirect is served even if recording the Click fails. The application logs the failure and returns the 302; it does not turn a database error into a 5xx for the visitor. We chose this because the redirect is the core product behavior and analytics is secondary; losing one Click is preferable to breaking a shared link. The trade-off is that Click counts can silently under-report during database contention or disk errors, so failures must be logged and monitored.
