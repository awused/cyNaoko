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

import code
import socket
import sys
import threading

BANNER = '------------Naoko REPL--------------'
PROMPT_STRING = 'Naoko via TCP>'

class ReplConn(object):
   def __init__(self, conn):
      self.conn = conn

   def write(self, s):
      self.conn.send(s)

   def read(self, prompt):
      self.conn.send(prompt)
      return self.conn.recv(4096)


class Repl(threading.Thread):
   def __init__(self, port, host='localhost', locals={}):
      sys.ps1      = PROMPT_STRING

      self.port    = port
      self.host    = host
      self.socket  = socket.socket(socket.AF_INET, 
                                   socket.SOCK_STREAM)
      self.socket.bind((self.host, self.port))
      self.socket.listen(1)
      self.console = code.InteractiveConsole(locals)
      print self.console, dir(self.console)
      super(Repl, self).__init__(target=self._replLoop)

      # This thread is relatively self contained and no exceptions
      # should bubble up to an external thread. Be warned the program
      # may not exit if there's a live socket. (it probably will though
      # as the below loop has no exception handler)
      self.start()
      
   def _replLoop(self):
      while True:
         (conn, addr) = self.socket.accept()
         repl = ReplConn(conn)
         sys.stdout   = sys.stderr = repl
         self.console.raw_input = repl.read
         self.console.interact(BANNER)

if __name__ == '__main__':
   HOST = 'localhost'
   PORT = 5001
   Repl(PORT, HOST)
