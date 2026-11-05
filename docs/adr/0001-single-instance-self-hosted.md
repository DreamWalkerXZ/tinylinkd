# Single-instance, self-hosted deployment

tinylinkd is designed as one self-hosted Instance per deployment, with its own database and Users. We are not building a multi-tenant SaaS with isolated workspaces, quotas, or billing. This keeps the permission model and operational surface small, matching the project's "one admin or a few users" scope. Adding multi-tenancy later would mean introducing tenant isolation and quotas throughout the data model.
