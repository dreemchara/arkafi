CREATE TABLE arkafi_users (
    id SERIAL PRIMARY KEY,
    login VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status BOOLEAN DEFAULT true
);

CREATE TABLE arkafi_users_mac (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES arkafi_users(id) ON DELETE CASCADE,
    mac MACADDR NOT NULL,
    device_name VARCHAR(255),
    CONSTRAINT unique_user_mac UNIQUE (user_id, mac)
);

CREATE TABLE traffic_stats (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES arkafi_users(id) ON DELETE CASCADE,
    ts TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now()),
    proxy_bytes_in BIGINT NOT NULL DEFAULT 0,
    direct_bytes_in BIGINT NOT NULL DEFAULT 0,
    proxy_bytes_out BIGINT NOT NULL DEFAULT 0,
    direct_bytes_out BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT traffic_stats_user_id_ts_key UNIQUE (user_id, ts)
);

CREATE INDEX idx_traffic_stats_ts ON traffic_stats(ts);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO arkafi;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO arkafi;