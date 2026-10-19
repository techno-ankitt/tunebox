-- TuneBox database. Run this once in your Neon/Supabase SQL editor.
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  display_name TEXT,
  avatar TEXT,
  token_version INT NOT NULL DEFAULT 0,
  recovery_hash TEXT,
  recovery_failed INT NOT NULL DEFAULT 0,
  recovery_locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_idx ON users (lower(username));

CREATE TABLE IF NOT EXISTS liked_songs (
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  track_id BIGINT NOT NULL,
  data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, track_id)
);

CREATE TABLE IF NOT EXISTS playlists (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS playlist_songs (
  playlist_id INT NOT NULL REFERENCES playlists(id) ON DELETE CASCADE,
  track_id BIGINT NOT NULL,
  data JSONB NOT NULL,
  position INT NOT NULL DEFAULT 0,
  PRIMARY KEY (playlist_id, track_id)
);

-- Already created the tables earlier? Run just these two lines once:
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;
-- For "Log out of all devices" (run once on an existing database):
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INT NOT NULL DEFAULT 0;
-- For the recovery code (run once on an existing database):
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_hash TEXT;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_failed INT NOT NULL DEFAULT 0;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_locked_until TIMESTAMPTZ;
