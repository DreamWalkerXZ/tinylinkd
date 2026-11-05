# Per-user link isolation

Each User sees and manages only the Links they own; Admin is a User role that can see and manage all Links and Users. We chose isolation over a shared workspace because accounts represent distinct people even in a small Instance. Because every Slug resolves at the same root path, Slugs are globally unique across Users. If shared visibility is needed later, it can be added as an explicit sharing feature rather than by weakening ownership.
