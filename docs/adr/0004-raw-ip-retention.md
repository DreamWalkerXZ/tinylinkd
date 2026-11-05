# Store raw IP addresses with 90-day retention

Clicks record the visitor's IP address in raw form, because identifying the source IP is an explicit product requirement. There is no hashing or truncation mode; the product stores raw IPs only. The default retention is 90 days, configurable per Instance, to limit the privacy impact of storing personal data indefinitely. The trade-off is deliberate: raw IPs are more useful for abuse investigation and unique-visitor analysis, at the cost of stronger privacy obligations.
