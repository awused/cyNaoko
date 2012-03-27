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

def dbopen(fn):
   """
   Decorator that ensures fn is only executed on an open database.
   """
   
   def dbopen_func(self, *args, **kwargs):
      if self._state == "open":
         return fn(self, *args, **kwargs)
      elif self._state == "closed":
         raise IOError("Cannot perform operations on closed database")
      else:
         raise Exception("Database must be open to perform operations")
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
         self.logger.error("%s closed due to %s: %s" % (self, exc_type, exc_val))
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

   def __enter__(self):
      return self
   
   def __init__(self, database, initscript):
      self.logger = logging.getLogger("database")
      from logging import DEBUG
      self.logger.setLevel(DEBUG)
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
   def execute(self, stmt):
      """
      Opens a cursor using .cursor and executes stmt.
      
      Returns the open cursor.
      """
      cur = self.cursor()
      cur.execute(stmt)
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
      

if __name__ == '__main__':
   import naoko
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
