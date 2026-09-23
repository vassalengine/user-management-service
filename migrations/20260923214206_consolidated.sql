CREATE TABLE IF NOT EXISTS users(
  user_id INTEGER PRIMARY KEY NOT NULL,
  username TEXT NOT NULL,
  avatar_template TEXT NOT NULL,
  UNIQUE(username)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE TABLE IF NOT EXISTS sessions(
  session_id TEXT PRIMARY KEY NOT NULL,
  user_id INTEGER NOT NULL,
  expires INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(user_id),
  UNIQUE(user_id)
);
