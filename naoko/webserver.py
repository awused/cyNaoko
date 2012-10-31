#!/usr/bin/env python
# A simple webserver for Naoko that serves up some interesting statistics.
# In integrated mode this is started with Naoko and uses her instance of NaokoDB, though not the thread.
from lib.external.bottle import route, run, default_app, SimpleTemplate, static_file
import logging
from settings import *
import time
import threading
import os.path
from collections import deque

def package(fn, *args, **kwargs):
    def action():
        fn(*args, **kwargs)
    return action 

class NaokoWebServer(object):
    dbclient = None
    def __init__(self, db_queue, db_start, host, port, protocol, room):
        self.logger = logging.getLogger("webserver")
        self.logger.setLevel(LOG_LEVEL)
        self.db_queue = db_queue
        self.db_start = db_start
        # Only one thread can access a connection object 
        self.db_done = threading.Event()
        # Avoid querying the database twice in a row
        self.db_lock = threading.Lock()
        self.host = host
        self.port = port
        self.protocol = protocol
        self.room = room
        f = open(os.path.join("web","template.html"), 'r')
        self.template = SimpleTemplate(f)
        f.close()
        self.cache = None
        self.last_render = 0

    def render(self):
        if time.time() - self.last_render > 60 * 30:
            self.db_lock.acquire()
            if time.time() - self.last_render > 60 * 30:
                self.getData()
            self.db_lock.release()
        return self.rendered

    def static(self, path):
        return static_file(path, root=os.path.join("web", "static"))

    def getData(self):
        self.logger.debug("Fetching new data from the database")
        self.db_done.clear()
        self.db_queue.append(self._getData)
        self.db_start.set()
        self.db_done.wait()
        
    # Takes 4-5 seconds to get everything
    # If performance is a problem possible solutions are:
    # 1: ajax calls + appears more responsive to the user, not just sitting on a blank page
    #       - more http requests will be extremely slow on the bottle.py http server, still puts heavy load on the sqlite database
    # 2: precalculation/running totals in the database + faster, no extra calls, extra load on the database in negligible, potentially serve new data with every request
    #       - complicates database more, requires extra tables and additional columns, initial database upgrade may take a very long time, much more difficult to change decisions later
    def _getData(self): 
        averageUsers = map(lambda (x, y): [int(x), y], NaokoWebServer.dbclient.getAverageUsers())
        userVideoStats = NaokoWebServer.dbclient.getUserVideoStats()
        userChatStats = NaokoWebServer.dbclient.getUserChatStats()
        popularVideos = NaokoWebServer.dbclient.getPopularVideos()
        # Takes 20+ seconds alone on a 100mb database, unacceptable
        #messageStats = NaokoWebServer.dbclient.getMessageCounts()
        self.rendered = self.template.render(averageUsers=averageUsers, userChatStats=userChatStats, popularVideos=popularVideos, userVideoStats=userVideoStats, room=self.room)
        self.last_render = time.time()
        self.db_done.set()    

    def start(self):
        route('/static/<path:path>')(self.static)
        route("/")(self.render)
        if self.protocol == "fastcgi":
            from flup.server.fcgi import WSGIServer
            WSGIServer(default_app(), bindAddress=(self.host, int(self.port))).run()
        elif self.protocol == "http":
            run(host=self.host, port=int(self.port))

# Runs a dedicated thread for accessing the database
def dbloop(dbfile, db_queue, db_signal):
    from lib.database import NaokoDB
    NaokoWebServer.dbclient = NaokoDB(dbfile)
    while db_signal.wait():
        db_signal.clear()
        while db_queue:
            db_queue.popleft()() 

if __name__ == "__main__":
    # Standalone mode runs the webserver as a daemon
    import ConfigParser
    import sys, os
    from lib.daemon.manager import manageDaemon

    config = ConfigParser.RawConfigParser()
    config.read("naoko.conf")
    dbfile = config.get("naoko", "db_file")
    mode = config.get("naoko", "webserver_mode")
    host = config.get("naoko", "webserver_host")
    port = config.get("naoko", "webserver_port")
    protocol = config.get("naoko", "webserver_protocol")
    room = config.get("naoko", "room")
    assert mode == "standalone", "Web server not set to standalone mode"
    assert dbfile and dbfile != ":memory:", "No database file"

    def startServer():
        logging.basicConfig(format='%(name)-15s:%(levelname)-8s - %(message)s', stream=sys.__stderr__)
        db_queue = deque()
        db_signal = threading.Event()
        dbthread = threading.Thread(target=dbloop, args=[dbfile, db_queue, db_signal])
        dbthread.start()
        server = NaokoWebServer(db_queue, db_signal, host, port, protocol, room)
        server.start()
    
    command = sys.argv[1] if len(sys.argv) > 1 else None
    if command == "debug":
        startServer()
    else:
        manageDaemon(startServer, command, sys.argv[0], "/tmp/naokoweb.pid", os.path.abspath(os.getcwd()))
    
else:
    import time
    def startServer(naoko):
        # Give Naoko time to set up everything 
        while not hasattr(naoko, "dbclient"):
            # Sleep until the NaokoDB is ready
            time.sleep(1)

        # flup doesn't work from threads that aren't the main thread
        assert naoko.webserver_protocol == "http", "Embedded web server only supports http mode."

        naoko.logger.debug("Starting web server in embedded mode on %s:%s:%s." % (naoko.webserver_protocol, naoko.webserver_host, naoko.webserver_port))
        NaokoWebServer.dbclient = naoko.dbclient
        server = NaokoWebServer(naoko.sql_queue, naoko.sqlAction, naoko.webserver_host, naoko.webserver_port, naoko.webserver_protocol, naoko.room)
        server.start()

