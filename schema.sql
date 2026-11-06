-- Cloudflare D1 migration. All payment authority stays in this database/server.
CREATE TABLE IF NOT EXISTS purchase_orders (
 order_id TEXT PRIMARY KEY,
 uid TEXT NOT NULL,
 amount INTEGER NOT NULL CHECK(amount=19900),
 currency TEXT NOT NULL CHECK(currency='INR'),
 status TEXT NOT NULL CHECK(status IN ('created','paid','refunded')),
 payment_id TEXT UNIQUE,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS purchase_orders_uid ON purchase_orders(uid,created_at);
CREATE TABLE IF NOT EXISTS entitlements (
 uid TEXT NOT NULL,
 product TEXT NOT NULL,
 order_id TEXT NOT NULL,
 active INTEGER NOT NULL CHECK(active IN (0,1)),
 created_at INTEGER NOT NULL,
 PRIMARY KEY(uid,product)
);
CREATE TABLE IF NOT EXISTS exams (
 id TEXT PRIMARY KEY,
 title TEXT NOT NULL,
 questions_json TEXT NOT NULL,
 published INTEGER NOT NULL DEFAULT 0 CHECK(published IN (0,1))
);
CREATE TABLE IF NOT EXISTS attempts (
 uid TEXT NOT NULL,
 test_id TEXT NOT NULL,
 started_at INTEGER NOT NULL,
 deadline INTEGER NOT NULL,
 submitted_at INTEGER,
 score INTEGER,
 answers_json TEXT,
 PRIMARY KEY(uid,test_id)
);
CREATE INDEX IF NOT EXISTS attempts_by_uid ON attempts(uid);

-- Google Play purchase token hashes (never store raw purchase tokens)
CREATE TABLE IF NOT EXISTS play_purchases (
 token_hash TEXT PRIMARY KEY,
 uid TEXT NOT NULL,
 product_id TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS play_purchases_uid ON play_purchases(uid);
