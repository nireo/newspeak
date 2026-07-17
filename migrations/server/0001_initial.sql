CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    identity_key BLOB NOT NULL,
    signed_prekey_kind INTEGER NOT NULL,
    signed_prekey_key BLOB NOT NULL,
    signed_prekey_signature BLOB NOT NULL,
    kem_prekey_kind INTEGER NOT NULL,
    kem_prekey_key BLOB NOT NULL,
    kem_prekey_signature BLOB NOT NULL,
    signed_prekey_created_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
    id INTEGER,
    user_id INTEGER,
    kind INTEGER NOT NULL,
    key BLOB NOT NULL,
    signature BLOB NOT NULL,
    created_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (id, user_id)
);

CREATE TABLE IF NOT EXISTS offline_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_username TEXT NOT NULL,
    receiver_username TEXT NOT NULL,
    message BLOB NOT NULL,
    message_kind INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS one_time_kem_keys (
    id INTEGER,
    user_id INTEGER,
    kind INTEGER NOT NULL,
    key BLOB NOT NULL,
    signature BLOB NOT NULL,
    created_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (id, user_id)
);
