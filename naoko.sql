CREATE TABLE IF NOT EXISTS videos(type TEXT, id TEXT, duration_ms INTEGER, title TEXT, primary key(type, id));
CREATE TABLE IF NOT EXISTS video_stats(type TEXT, id TEXT, uname TEXT, FOREIGN KEY(type, id) REFERENCES video(type, id));
CREATE INDEX IF NOT EXISTS video_stats_idx ON video_stats(type, id);
CREATE TABLE IF NOT EXISTS bans(reason TEXT, auth INTEGER, uname TEXT, timestamp INTEGER, mod TEXT);
CREATE TABLE IF NOT EXISTS user_count(timestamp INTEGER, count INTEGER, primary key(timestamp, count));

CREATE TABLE IF NOT EXISTS chat(timestamp INTEGER, username TEXT, userid TEXT, msg TEXT, protocol TEXT, channel TEXT, flags TEXT);
CREATE INDEX IF NOT EXISTS chat_ts ON chat(timestamp);
CREATE INDEX IF NOT EXISTS chat_user ON chat(username);
