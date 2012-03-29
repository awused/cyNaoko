CREATE TABLE videos(type TEXT, id TEXT, duration_ms INTEGER, title TEXT, primary key(type, id));
CREATE TABLE video_stats(type TEXT, id TEXT, uname TEXT, plid TEXT, FOREIGN KEY(type, id) REFERENCES video(type, id));
CREATE INDEX video_stats_idx ON video_stats(type, id);
