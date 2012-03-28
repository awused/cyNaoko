# -*- coding: utf-8 -*-
# Naoko - A prototype synchtube bot
#
# Written in 2012 by Desuwa
# Based on Denshi by Falaina falaina@falaina.net
#
# To the extent possible under law, the author(s) have dedicated all
# copyright and related and neighboring rights to this software to the
# public domain worldwide. This software is distributed without any
# warranty.  You should have received a copy of the CC0 Public Domain
# Dedication along with this software. If not, see
# <http://creativecommons.org/publicdomain/zero/1.0/>.

import sqlite3
import logging
from settings import logLevel

ProgrammingError = sqlite3.ProgrammingError
DatabaseError    = sqlite3.DatabaseError

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
      self.logger.setLevel(logLevel)      
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
         self.logger.error("%s closed due to %s: %s" % (self, exc_type, exc_value))
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
   _required_tables = set(['video_stats', 'videos'])
                     
   # Low level database handling methods
   def __enter__(self):
      return self
   
   def __init__(self, database, initscript):
      self.logger = logging.getLogger("database")
      self.logger.setLevel(logLevel)
      self.initscript = initscript
      self.db_file = database
      self.con = sqlite3.connect(database)
      self._state = "open"
      
      def getTables():
         with self.execute(self._dbinfo_sql) as cur:
            return set([table[0] for table in cur.fetchall()])

      tables = set(getTables())

      # run self.initscript if we have an empty db (one with no tables)
      if len(tables) is 0:
         self.initdb()
         tables = set(getTables())
         
      if not self._required_tables <= tables:
         raise ValueError("Database '%s' is non-empty but "
                          "does not pyoovide required tables %s" %
                          (database, self._required_tables - tables))

      
   def __exit__(self, exc_type, exc_val, exc_tb):
      self._state = "closed"
      if self.con:
         self.con.close()
      if exc_type and exc_val:
         self.logger.error("Database '%s' closed due to %s: %s" % (self.db_file, exc_type, exc_val))
      else:
         self.logger.debug("Database '%s' closed" % self.db_file)

   @dbopen
   def initdb(self):
      """
      Initializes an empty sqlite3 database using .initscript.
      """
      self.logger.debug("Running initscript\n%s" % (self.initscript))
      with self.executescript(self.initscript):
         self.con.commit()

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
      """
      cur = self.cursor()
      cur.execute(stmt, *args)
      return cur

   @dbopen
   def executescript(self, script):
      """
      Opens a cursor using .cursor and executes script.

      Returns the open cursor.
      """
      cur = self.cursor()
      cur.executescript(script)
      return cur

   def close(self):
      """
      Closes the associated sqlite3 connection.
      """
      self.__exit__(None, None, None)


   # Higher level video/poll/chat-related APIs
   def getVideos(self, num, columns=None, orderby=None):
      """
      Retrieves videos from the video_stats table of Naoko's database.

      num must be an integer specifying the maximum number of rows to return.
      
      columns must be a tuple specifying which columns to retrieve. By default
      all columns will be retrieved

      orderby must be a tuple specifying the orderby clause. Valid values are
      ('id', 'ASC'), ('id', 'DESC'), or ('RANDOM()')

      The statement executed against the database will roughly be
      SELECT <columns> FROM video_stats [ORDER BY <orderby>] [LIMIT ?]
      """

      
      _tables = {'videos' : set(['type', 'id', 'duration_ms']),
              'video_stats' : set(['type', 'id', 'uname', 'plid'])}
      
      if not columns:
         columns = _tables['videos']

      columns = set(columns)
      if not columns <= _tables['videos']:
         raise ProgrammingError("Argument columns: %s not a subset of video "
                                "columns %s" % (columns, _tables['videos']))

      sel_list = ', '.join(_tables['videos'].union(columns))
      sql = 'SELECT %s FROM videos ' % (sel_list)
      
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
         sql += 'ORDER BY id ASC '
      elif matchOrderBy(orderby, ('id', 'DESC')):
         sql += 'ORDER BY id DESC '
      elif matchOrderBy(orderby, ('RANDOM()',)):
         sql += 'ORDER BY RANDOM() '
      else:
         raise ProgrammingError("Invalid orderby %s" % (orderby))

      if isinstance(num, (int, long)):
         sql += 'LIMIT ?'
      else:
         raise ProgrammingError("Invalid num %s" % (num))

      self.logger.debug("Generated SQL %s" % (sql))

      with self.execute(sql, (num,)) as cur:
         return cur.fetchall()

if __name__ == '__main__':
   logging.basicConfig(format='%(name)-15s:%(levelname)-8s - %(message)s')   
   testvids = [('yt', 'Fp7dKcCBXHI', 37 *1000, u'【English Sub】 Kyouko Canyon 【Yuru Yuri】'),
               ('yt', 'N_5Lllcj3rY', 103*1000, u'Jumping Kyouko [YuruYuri Eyecatch MAD]')]
                                
   print "**Testing database creation with :memory: database"

   with NaokoDB(':memory:', file('../naoko.sql').read()) as db:
      with db.cursor() as cur:
         print "**Inserting into database: %s" % (testvids)
         cur.executemany("INSERT INTO videos VALUES(?, ?, ?, ?)", testvids)
         cur.execute("SELECT * FROM videos ORDER BY id")
         row = cur.fetchone()
         while row:
            print "**Retrieved row: %s" % (row,)
            row = cur.fetchone()            

      assert len(db.getVideos(1)) == 1, 'db.getVideos(1) did not return 1 video'

      rand_rows = db.getVideos(5, None, ('RANDOM()',))
      assert len(rand_rows)  <= 5, 'db.getVideos(5) did not return less than 5 videos'

      sorted_rows = db.getVideos(2, set(['id']), ('id', 'ASC'))
      assert sorted_rows == sorted(sorted_rows), "sorted rows not actually sorted"

      
      
