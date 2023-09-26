CREATE TABLE users (
  id INTEGER PRIMARY KEY NOT NULL,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  anonymous BOOLEAN NOT NULL
);

CREATE TABLE comments (
  id INTEGER PRIMARY KEY NOT NULL,
  parent_id INTEGER,
  user_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  num_children INTEGER NOT NULL,
  FOREIGN KEY(parent_id) REFERENCES comments(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- All passwords are "test"
INSERT INTO users(username,email,password_hash,anonymous) VALUES
  (
    "joe_shmo", "joe@shmo.com",
    "$2a$10$XWEZsEbR0KdAPcgYjy6KO.1RjzEhJpaOOj7ZC74xKN9nkRpKKsNv.",
    0
  ),
  (
    "mary_hary", "mary@hary.com",
    "$2a$10$XWEZsEbR0KdAPcgYjy6KO.1RjzEhJpaOOj7ZC74xKN9nkRpKKsNv.",
    0
  ),
  (
    "shy_guy", "shy@guy.com",
    "$2a$10$XWEZsEbR0KdAPcgYjy6KO.1RjzEhJpaOOj7ZC74xKN9nkRpKKsNv.",
    1
  )
;

INSERT INTO comments(parent_id,user_id,content,timestamp,num_children) VALUES
  (0,1,"This is a post from joe_shmo",0,2),

  (1,2,"This is a reply from mary_hary",3,1),
  (2,1,"This is a reply to the reply from shy_guy",6,0),

  (1,3,"This is a reply from mary_hary",4,1),
  (4,1,"This is a reply to the reply from mary_hary",7,0),

  (0,2,"This is a post from mary_hary",1,1),
  (6,1,"This is a reply from joe_shmo",5,0),

  (0,3,"This is a post from shy_guy",2,0)
;
