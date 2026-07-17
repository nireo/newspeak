CREATE TABLE IF NOT EXISTS local_users (
    username TEXT NOT NULL PRIMARY KEY,
    identity_sk BLOB NOT NULL,
    signed_prekey_sk BLOB NOT NULL,
    kem_decap BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS kem_keys (
    id BLOB PRIMARY KEY,
    username TEXT NOT NULL,
    decap BLOB NOT NULL,
    used INTEGER NOT NULL,
    FOREIGN KEY (username) REFERENCES local_users(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ec_keys (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    sk BLOB NOT NULL,
    used INTEGER NOT NULL,
    FOREIGN KEY (username) REFERENCES local_users(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    peer TEXT NOT NULL,
    ratchet_state BLOB NOT NULL,
    UNIQUE (username, peer),
    FOREIGN KEY (username) REFERENCES local_users(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    is_sender INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS peer_identities (
    username TEXT NOT NULL,
    peer TEXT NOT NULL,
    identity_key BLOB NOT NULL,
    verified INTEGER NOT NULL,
    UNIQUE (username, peer),
    FOREIGN KEY (username) REFERENCES local_users(username) ON DELETE CASCADE
);
