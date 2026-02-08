ALTER TABLE users
  ADD COLUMN IF NOT EXISTS display_name text,
  ADD COLUMN IF NOT EXISTS avatar_url text,
  ADD COLUMN IF NOT EXISTS provider text,
  ADD COLUMN IF NOT EXISTS provider_user_id text;

CREATE INDEX IF NOT EXISTS idx_users_provider_user_id
  ON users(provider, provider_user_id);
