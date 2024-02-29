/* TODO: add indices */

CREATE TABLE users(
  user_id INTEGER PRIMARY KEY NOT NULL,
  username TEXT NOT NULL,
  avatar_template TEXT NOT NULL,
  UNIQUE(username)
);
