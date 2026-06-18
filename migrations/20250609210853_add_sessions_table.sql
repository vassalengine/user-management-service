CREATE TABLE IF NOT EXISTS sessions(
  session_id TEXT PRIMARY KEY NOT NULL,
  user_id INTEGER NOT NULL,
  expires INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(user_id),
  UNIQUE(user_id)
);
