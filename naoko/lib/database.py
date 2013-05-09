# -*- coding: utf-8 -*-

import sqlite3
import logging
import time
try:
    from settings import LOG_LEVEL
except:
    # This probably only happens when executing this directly
    print "Defaulting to LOG_LEVEL debug [%s]" % (__name__)
    LOG_LEVEL = logging.DEBUG

ProgrammingError = sqlite3.ProgrammingError
DatabaseError = sqlite3.DatabaseError


def dbopen(fn):
    """
    Decorator that ensures fn is only executed on an open database.
    """

    def dbopen_func(self, *args, **kwargs):
        if self._state == "open":
            return fn(self, *args, **kwargs)
        elif self._state == "closed":
            raise DatabaseError("Cannot perform operations on closed database")
        else:
            raise DatabaseError("Database must be open to perform operations")
    return dbopen_func


class NaokoCursor(sqlite3.Cursor):
    """
    Subclass of sqlite3.Cursor that implements the context manager protocol
    """

    _id = 0

    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger('naokocursor')
        self.id = NaokoCursor._id
        NaokoCursor._id += 1
        sqlite3.Cursor.__init__(self, *args, **kwargs)

    def __enter__(self):
        return self

    def __str__(self):
        return "NaokoCursor #%d" % self.id

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        if not self.logger:
            return
        if exc_type and exc_value:
            self.logger.error("%s closed  %s: %s" % (self, exc_type, exc_value))
        else:
            self.logger.debug("%s closed" % self)


class NaokoDB(object):
    """
    Wrapper around an sqlite3 database. Roughly analagous
    to an sqlite3.Connection.

    This is _NOT_ a subclass of sqlite3.Connection.

    Implements the context manager protocol.
    """

    _dbinfo_sql = "SELECT name FROM sqlite_master WHERE type='table'"
    _version_sql = "SELECT value FROM metadata WHERE key='dbversion'"
    _required_tables = set(["video_stats", "videos", "user_count", "bans", "chat"])

    # Low level database handling methods
    def __enter__(self):
        return self

    def __init__(self, database):
        self.logger = logging.getLogger("database")
        self.logger.setLevel(LOG_LEVEL)
        self.db_file = database
        # Set a generous timeout to avoid breaking if conflicting with the web server
        self.con = sqlite3.connect(database, timeout=60)
        self._state = "open"

        # run self.initscript if we have an empty db (one with no tables)
        self.initdb()
        tables = self._getTables()

        if not self._required_tables <= tables:
            raise ValueError("Database '%s' is non-empty but "
                            "does not provide required tables %s" %
                            (database, self._required_tables - tables))

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._state = "closed"
        if self.con:
            self.con.close()
        if exc_type and exc_val:
            self.logger.error("Database '%s' closed due to %s: %s" %
                            (self.db_file, exc_type, exc_val))
        else:
            self.logger.debug("Database '%s' closed" % self.db_file)

    def _getTables(self):
        with self.execute(self._dbinfo_sql) as cur:
            return set([table[0] for table in cur.fetchall()])

    def _getVersion(self):
        tables = self._getTables()
        if 'metadata' in tables:
            try:
                with self.execute(self._version_sql) as cur:
                    version = cur.fetchone()[0]
                    self.logger.debug("Database version is %s" % version)
                    return int(version)
            except TypeError as e:
                # Earlier versions didn't commit the changes, resulting in the possibility of dbversion missing.
                # Assume it's version 3, as it is the most likely scenario and the difference between version 2 and 3 is minor.
                self.logger.debug(e)
                self.logger.debug("Database version is 3 (empty metadata table)")
                self.executeDML("INSERT INTO metadata(key, value) VALUES ('dbversion', '3')")
                self.commit()
                return 3
        elif tables : # There was no explicit version in the original database
            self.logger.debug("Database version is 1 (no metadata table)")
            return 1

    def _update(self):
        version = self._getVersion()
        # The database is either empty or a version from before the metadata table
        if version < 2:
            stmts = ["CREATE TABLE IF NOT EXISTS videos(type TEXT, id TEXT, duration_ms INTEGER, title TEXT, primary key(type, id))",
                "CREATE TABLE IF NOT EXISTS video_stats(type TEXT, id TEXT, uname TEXT, FOREIGN KEY(type, id) REFERENCES video(type, id))",
                "CREATE INDEX IF NOT EXISTS video_stats_idx ON video_stats(type, id)",
                "CREATE TABLE IF NOT EXISTS bans(reason TEXT, auth INTEGER, uname TEXT, timestamp INTEGER, mod TEXT)",
                "CREATE TABLE IF NOT EXISTS user_count(timestamp INTEGER, count INTEGER, primary key(timestamp, count))",
                "CREATE TABLE IF NOT EXISTS chat(timestamp INTEGER, username TEXT, userid TEXT, msg TEXT, protocol TEXT, channel TEXT, flags TEXT)",
                "CREATE INDEX IF NOT EXISTS chat_ts ON chat(timestamp)",
                "CREATE INDEX IF NOT EXISTS chat_user ON chat(username)",
                "ALTER TABLE videos ADD COLUMN  flags INTEGER DEFAULT 0 NOT NULL",
                "CREATE TABLE metadata(key TEXT, value TEXT, PRIMARY KEY(key))",
                "INSERT INTO metadata(key, value) VALUES ('dbversion', '2')"]
            for stmt in stmts:
                self.executeDML(stmt)
            self.commit()
        if version < 3:
            stmts = ["UPDATE chat SET timestamp = timestamp * 1000",
                "UPDATE metadata SET value = '3' WHERE key = 'dbversion'"]
            for stmt in stmts:
                self.executeDML(stmt)
            self.commit()
        if version < 4:
            stmts = ["UPDATE user_count SET timestamp = count, count = timestamp WHERE timestamp < 1000",
                "UPDATE metadata SET value = '4' WHERE key = 'dbversion'"]
            for stmt in stmts:
                self.executeDML(stmt)
            self.commit()
            
    @dbopen
    def initdb(self):
        """
        Initializes an empty sqlite3 database using .initscript.
        """
        self._update()
        assert self._getVersion() >= 4

    @dbopen
    def cursor(self):
        """
        Returns an open cursor of type NaokoCursor.
        """
        return self.con.cursor(NaokoCursor)

    @dbopen
    def execute(self, stmt, *args):
        """
        Opens a cursor using .cursor and executes stmt.

        Returns the open cursor.

        This method should not be directly called unless the returned cursor is handled.
        """
        cur = self.cursor()
        cur.execute(stmt, *args)
        return cur

    @dbopen
    def executeDML(self, stmt, *args):
        """
        Executes a statement without returning an open cursor.
        """
        with self.execute(stmt, *args):
            pass

    @dbopen
    def commit(self):
        """
        Commits changes to the database.

        This method exists because python 2.7.2 introduced a bug when con.commit() is called with a select statement.
        """
        self.con.commit()

    @dbopen
    def executescript(self, script):
        """
        Opens a cursor using .cursor and executes script.

        Returns the open cursor.
        """
        cur = self.cursor()
        cur.executescript(script)
        return cur

    @dbopen
    def fetch(self, stmt, *args):
        """
        Executes stmt and fetches all the rows.

        stmt must be a select statement.

        Returns the fetched rows.
        """
        with self.execute(stmt, *args) as cur:
            return cur.fetchall()

    def close(self):
        """
        Closes the associated sqlite3 connection.
        """
        self.__exit__(None, None, None)


    # Higher level video/poll/chat-related APIs
    # TODO -- Implement blockedSites
    def getVideos(self, num=None, columns=None, orderby=None, duration_s=None, title=None, user=None, blockedFlags=0b11, blockedSites = []):
        """
        Retrieves videos from the video_stats table of Naoko's database.

        num must be an integer specifying the maximum number of rows to return.
        By default all rows are retrieved

        columns must be an iterable specifying which columns to retrieve. By default
        all columns will be retrieved. See naoko.sql for database schema.

        orderby must be a tuple specifying the orderby clause. Valid values are
        ('id', 'ASC'), ('id', 'DESC'), or ('RANDOM()')

        The statement executed against the database will roughly be
        SELECT <columns> FROM video_stats vs, videos v
            WHERE vs.type = v.type AND vs.id = v.id
            [ORDER BY <orderby>] [LIMIT ?]
        """


        _tables = {'videos'      : set(['type', 'id', 'duration_ms', 'title']),
                    'video_stats' : set(['type', 'id', 'uname'])}
        legal_cols = set.union(_tables['videos'], _tables['video_stats'])
        if not columns:
            columns = legal_cols

        if not set(columns) <= legal_cols:
            raise ProgrammingError("Argument columns: %s not a subset of video "
                                    "columns %s" % (columns, _tables['videos']))

        # Canonicalize references to columns
        col_repl = {'id'   : 'v.id',
                    'type' : 'v.type'}

        sel_cols = []
        for col in columns:
            sel_col = col
            if col in col_repl:
                sel_col = col_repl[col]
            sel_cols.append(sel_col)

        binds = ()
        sel_list  = ', '.join(sel_cols)
        sel_cls   = 'SELECT DISTINCT %s' % (sel_list)
        from_cls  = ' FROM video_stats vs, videos v '
        where_cls = ' WHERE vs.type = v.type AND vs.id = v.id '
        
        if isinstance(duration_s, (int, long)):
            where_cls += " AND v.duration_ms <= ? "
            binds += (duration_s*1000,)

        if isinstance(title, (str, unicode)):
            where_cls += " AND v.title like ? COLLATE NOCASE "
            binds += ("%%%s%%" % (title),)

        if isinstance(user, (str, unicode)):
            where_cls += " AND vs.uname like ? COLLATE NOCASE "
            binds += (user,)
       
        if isinstance(blockedFlags, (int, long)):
            where_cls += " AND v.flags & ? = 0 "
            binds += (blockedFlags,)

        if isinstance(blockedSites, (list, tuple)):
            sites_cls = " AND v.type NOT IN ("
            flg = False
            for b in blockedSites:
                if isinstance(b, (str, unicode)) and len(b) == 2:
                    if flg:
                        sites_cls += ","
                    sites_cls += "?"
                    binds += (b,)
                    flg = True
            if flg:
                where_cls += sites_cls + ") "

        sql = sel_cls + from_cls + where_cls

        def matchOrderBy(this, other):
            valid = this == other
            if not valid:
                valid = (len(this) == 2) and (len(other) == 2)
                for i in range(len(this)):
                    valid = valid and (this[i].lower() == other[1].lower())
            return valid

            valid = this and other and (this[0].lower() != other[0].lower())
            if valid and (len(this) == 2) and this[1] and other[1]:
                return valid and (this[1].lower() == other[1].lower())
            else:
                return valid and (this[1] == other[1])

        if orderby is None:
            pass
        elif matchOrderBy(orderby, ('id', 'ASC')):
            sql += ' ORDER BY v.id ASC'
        elif matchOrderBy(orderby, ('id', 'DESC')):
            sql += ' ORDER BY v.id DESC'
        elif matchOrderBy(orderby, ('RANDOM()',)):
            sql += ' ORDER BY RANDOM()'
        else:
            raise ProgrammingError("Invalid orderby %s" % (orderby))

        if isinstance(num, (int, long)):
            sql += ' LIMIT ?'
            binds += (num,)
        elif  num != None:
            raise ProgrammingError("Invalid num %s" % (num))

        self.logger.debug("Generated SQL %s" % (sql))

        with self.execute(sql, binds) as cur:
            return cur.fetchall()

    def insertChat(self, msg, username, userid=None, timestamp=None, protocol='ST', channel=None, flags=None):
        """
        Insert chat message into the chat table of Naoko's database.

        msg is the chat message to be inserted.

        username is the sender of the chat message.

        userid is the userid of the sender of the chat message. This may
        not make sense for all protocols. By default it is None.

        timestamp is the timestamp the message was received. If None
        timestamp will default to the time insertChat was called.

        protocol is the protocol over which the message was sent. The
        default protocol is 'ST'.

        channel is the channel or room for which the message was 
        intended. The default is None.

        flags are any miscellaneous flags attached to the user/message.
        this is intended to denote things such as emotes, video adds, etc.
        By default it is None.
        """
        if userid is None:
            userid = username
        
        if timestamp is None:
            timestamp = int(time.time() * 1000)

        chat = (timestamp, username, userid, msg, protocol, channel, flags)
        with self.cursor() as cur:
            self.logger.debug("Inserting chat message %s" % (chat,))
            cur.execute("INSERT INTO chat VALUES(?, ?, ?, ?, ?, ?, ?)", chat)
        self.commit()

    # excludes is now a list of (name, protocol) tupleS
    def getQuote(self, nick, excludes=[], protocol=None):
        """
        Fetch a random quote out of the chat database from a user with a matching nick on the given protocol.

        If no quote is found a value of None will be returned.

        If no nick is supplied it will select from all users except the user exclude.
        """
        select_cls = "SELECT username, msg, timestamp, protocol FROM chat "
        where_cls = " WHERE msg NOT LIKE '/me%%' AND msg NOT LIKE '$%%' "
        limit_cls = " ORDER BY RANDOM() LIMIT 1"
        
        binds = ()

        if protocol:
            where_cls += " AND protocol = ? "
            binds = (protocol,)
            
        if nick:
            where_cls += " AND username = ? COLLATE NOCASE "
            binds += (nick,)
        else:
            for e in excludes:
                where_cls += " AND (username != ? or protocol != ?) "
                binds += e

        sql = select_cls + where_cls + limit_cls

        rows = self.fetch(sql, binds)
        if rows: return rows[0]
        else: return None

    def flagVideo(self, site, vid, flags):
        """
        Flags a video with the supplied flags.

        Flags:

        1 << 0  : Invalid video, may become valid in the future. Reset upon successful manual add.
        1 << 1  : Manually blacklisted video.
        """
        self.logger.debug("Flagging %s:%s with flags %s", site, vid, bin(flags))
        self.executeDML("UPDATE videos SET flags=(flags | ?) WHERE type = ? AND id = ?", (flags, site, vid))
        self.commit()

    def unflagVideo(self, site, vid, flags):
        """
        Removes the supplied flags from a video.
        """
        self.executeDML("UPDATE videos SET flags=(flags & ?) WHERE type = ? AND id = ?", (~flags, site, vid))
        self.commit()

    def insertVideo(self, site, vid, title, dur, nick):
        """
        Inserts a video into the database.

        The video is assumed to be valid so it also removes the invalid flag from the video.

        dur is supplied in seconds as a float but stored in milliseconds as an integer.

        nick is the username of the user who added it, with unregistered users using an empty string.
        """
        self.logger.debug("Inserting %s into videos", (site, vid, int(dur * 1000), title, 0))
        self.logger.debug("Inserting %s into video_stats", (site, vid, nick))
        self.executeDML("INSERT OR IGNORE INTO videos VALUES(?, ?, ?, ?, ?)", (site, vid, int(dur * 1000), title, 0))
        self.executeDML("INSERT INTO video_stats VALUES(?, ?, ?)", (site, vid, nick))
        self.commit()
        self.unflagVideo(site, vid, 1)

    def insertUserCount(self, count, timestamp):
        """
        Stores the user count at the time provided.

        The timestamp is provided in seconds as a float but stored in milliseconds as an integer.
        """
        self.logger.debug("Inserting %s into user_count", (int(timestamp*1000), count))
        self.executeDML("INSERT INTO user_count VALUES(?, ?)", (int(timestamp*1000), count))
        self.commit()

    def insertBan(self, user, reason, timestamp, modName):
        """
        Inserts a ban into the database.

        user is a SynchtubeUser

        reason is a string giving the reason why the user was banned

        The timestamp is provided in seconds as a float but stored in milliseconds as an integer.
       
        modName is the name of the mod who initiated the ban.

        user.uid is used to determine if the user was logged in.
        """
        # As found elsewhere, user.auth is unreliable.
        auth = int(bool(user.uid))
        self.logger.debug("Inserting %s into bans", (reason, auth, user.nick, int(timestamp*1000), modName))
        self.executeDML("INSERT INTO bans VALUES(?, ?, ?, ?, ?)", (reason, auth, user.nick, int(timestamp*1000), modName))
        self.commit()

    def getLastBans(self, nick, num):
        """
        Fetches the most recent num bans for the specified user.

        If the nick given is -all, the most recent bans for any user will be returned.
        """
        select_cls = "SELECT timestamp, reason, mod, uname FROM bans "
        where_cls = ""
        order_cls = " ORDER BY timestamp DESC LIMIT ?"
        binds = ()

        if nick != "-all":
            where_cls = " WHERE uname = ? COLLATE NOCASE "
            binds += (nick,)

        binds += (num,)

        sql = select_cls + where_cls + order_cls
        return self.fetch(sql, binds)

    def getAverageUsers(self):
        """
        Calculates the average users in the room during any given hour.

        These values are cached by the web server.

        TODO -- Think about storing these values in another table to speed up queries.
        """
        select_cls = "SELECT STRFTIME('%s', STRFTIME('%Y-%m-%dT%H:00', timestamp/1000, 'UNIXEPOCH'))*1000, CAST(ROUND(AVG(count)) AS INTEGER) FROM user_count "
        group_cls = " GROUP BY STRFTIME('%Y%m%d%H', timestamp/1000, 'UNIXEPOCH')"
        sql = select_cls + group_cls
        return self.fetch(sql)

    def getUserVideoStats(self):
        """
        Fetches an ordered list of users and the numbers of videos they've added.

        Specifically ignores blacklisted videos but includes invalid ones.
        """
        select_cls = "SELECT uname, count(*) FROM video_stats vs, videos v "
        where_cls = " WHERE vs.type = v.type AND vs.id = v.id AND NOT v.flags & 2 "
        group_cls = " GROUP BY uname ORDER BY count(*) DESC"
        sql = select_cls + where_cls + group_cls
        return self.fetch(sql)

    def getUserChatStats(self):
        """
        Fetches the number of chat messages sent by each user.
        """
        select_cls = "SELECT username, count(*) FROM chat "
        group_cls = " GROUP BY username ORDER BY count(*) DESC"
        sql = select_cls + group_cls
        return self.fetch(sql)

    def getPopularVideos(self, n=10):
        """
        Fetches the n most popular videos.

        Ignores blacklisted videos, but returns invalid videos with a flag.
        """
        select_cls = "SELECT v.type, v.id, v.title, v.flags & 1, count(*) FROM videos v, video_stats vs "
        where_cls = " WHERE vs.type = v.type AND vs.id = v.id AND NOT v.flags & 2 "
        group_cls = " GROUP BY v.type, v.id ORDER BY count(*) DESC LIMIT ?"
        binds = (n,)
        sql = select_cls + where_cls + group_cls
        return self.fetch(sql, binds)

    def getMessageCounts(self):
        """
        Fetches the ten most popular messages.

        Currently case-sensitive, may change.
        """
        select_cls = "SELECT msg, count(*) FROM chat "
        group_cls = " GROUP BY msg ORDER BY count(*) DESC LIMIT 10"
        sql = select_cls + group_cls
        return self.fetch(sql)


# Run some tests if called directly
# These probably don't work anymore
if __name__ == '__main__' and False:
    logging.basicConfig(format='%(name)-15s:%(levelname)-8s - %(message)s')
    cur_log = logging.getLogger('naokocursor')
    db_log  = logging.getLogger('database')
    loggers = [cur_log, db_log]
    [logger.setLevel(LOG_LEVEL) for logger in loggers]

    vids = [('yt', 'Fp7dKcCBXHI', 37 * 1000,
                u'【English Sub】 Kyouko Canyon 【Yuru Yuri】'),
            ('yt', 'N_5Lllcj3rY', 103 * 1000,
                u'Jumping Kyouko [YuruYuri Eyecatch MAD]')]

    inserts = [('yt', 'N_5Lllcj3rY', 'Falaina'),
                ('yt', 'Fp7dKcCBXHI', 'Desuwa'),
                ('yt', 'N_5Lllcj3rY', 'Fukkireta'),
                ('yt', 'N_5Lllcj3rY', 'Fukkoreta')]

    print "**Testing database creation with :memory: database"

    with NaokoDB(':memory:', file('naoko.sql').read()) as db:

        print "**Testing chat message insertion"
        # Test defaults
        db.insertChat('Message 2', 'falaina')

        # Trivial test
        db.insertChat('Message 1', 'Kaworu', userid=None, timestamp='1',
                      protocol='IRC', channel='Denshi', flags='o')

        with db.cursor() as cur:
            cur.execute('SELECT * FROM chat ORDER by timestamp');

            rows = cur.fetchall()
            print "**Retrieved rows: %s" % (rows,)

            assert len(rows) == 2, 'Inserted 2 rows, but did not retrieve 2'
            
            # The first message should be Kaworu: Message 1 due to 
            # a timestamp of 1
            assert rows[0][0] is 1, 'Incorrect timestamp'
            assert rows[0][1] == 'Kaworu', 'Incorrect name for Kaworu'

            # Second message should be Falaina: Message 2
            assert rows[1][3] == 'Message 2', 'Incorrect message for Falaina'
            assert rows[1][4] == 'ST', 'Incorrect protocol for Falaina'
 
        print "**CHAT TESTS SUCCEEDED\n\n\n"
        with db.cursor() as cur:
            print "**Inserting videos into database: %s" % (vids)
            cur.executemany("INSERT INTO videos VALUES(?, ?, ?, ?)", vids)
            cur.executemany("INSERT OR IGNORE INTO videos VALUES(?, ?, ?, ?)", vids)
            cur.execute("SELECT * FROM videos ORDER BY id")
            row = cur.fetchone()
            while row:
                print "**Retrieved row: %s" % (row,)
                row = cur.fetchone()


            print "**Inserting video stats into database: %s" % (inserts)
            cur.executemany("INSERT INTO video_stats VALUES(?, ?, ?)", inserts)

        # Lets run some quick sanity queries
        with db.cursor() as cur:
            cur.execute("SELECT * FROM video_stats")
            rows = cur.fetchall()
            print "**Retrived rows: %s" % (rows,)
            assert rows == inserts, "Retrieved does not match inserted"


        assert len(db.getVideos(1)) == 1, 'db.getVideos(1) did not return 1'

        rand_rows = db.getVideos(5, None, ('RANDOM()',))
        assert len(rand_rows)  <= 5, 'db.getVideos(5) did not return less than 5'

        all_rows  = db.getVideos(None, None)
        print all_rows

        # Keep fetching videos until we've seen all 24 different permutations
        # The chance of not seeing a permutation at least once over
        # 10000 iterations is vanishingly small
        resultsets = set()
        attempts = 10000
        print "**Attempting to retrieve all permutations using RANDOM() orderby"
        for i in range(attempts):
            # Disable logging for sanity
            [logger.setLevel(logging.WARN) for logger in loggers]
            rand_rows = tuple(db.getVideos(4, None, ('RANDOM()',)))
            resultsets.add(rand_rows)
            if len(resultsets) == 24:
                break

        if len(resultsets) != 24:
            raise AssertionError("10000 random selects did not produce all 24"
                        " permutations of the four videos"
                        " \n[Actual:   %s]\n[Expected: %s]"
                        % (len(resultsets), 24))

        print "**Found all permutations in %d iterations." % (i,)

        # Reenable logging
        [logger.setLevel(LOG_LEVEL) for logger in loggers]

        sorted_rows = db.getVideos(4, set(['id']), ('id', 'ASC'))
        if sorted_rows != sorted(sorted_rows):
            raise AssertionError("sorted rows not actually sorted\n"
                        "[Actual:   %s]\n[Expected: %s]"
                        % (sorted_rows, sorted(sorted_rows)))

        reversed_rows = db.getVideos(4, ['id'], ('id', 'DESC'))
        expected_rows = sorted(reversed_rows, reverse=True)
        if reversed_rows != expected_rows:
            raise AssertionError("reversed rows not actually reversed\n"
                        "[Actual:   %s]\n[Expected: %s]"
                        % (reversed_rows, expected_rows))
       
        print "**VIDEO TESTS SUCCEEDED\n\n\n"

