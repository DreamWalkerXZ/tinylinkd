# Slugs are editable and immediately reusable

A Link's Slug can be changed after creation. When it changes, the old Slug is released immediately and may be claimed by any other Link; there is no alias redirect and no cooldown. We chose editability because users need to correct or rename short links, and immediate reuse keeps the Slug namespace simple. This refines ADR-0002: Slug uniqueness applies only to the Links currently holding a Slug.

The consequence is deliberate: an old shared link returns 404 until someone claims the Slug, and then redirects to the new owner's Destination URL. API clients must be warned that changing a Slug invalidates the old URL and may expose it to reuse.
