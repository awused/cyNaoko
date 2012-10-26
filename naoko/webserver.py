#!/usr/bin/env python
# A simple webserver for Naoko that serves up some interesting statistics.
# In integrated mode this is started with Naoko and uses her instance of NaokoDB, though not the thread.
from lib.external.bottle import route, run, default_app

class NaokoWebServer(object):
    def __init__(self, dbclient, host, port, protocol):
        self.dbclient = dbclient
        self.host = host
        self.port = port
        self.protocol = protocol

    def render(self):
        return "ur a faget"

    def _getData(self):
        #self.dbclient.executeDML
        pass

    def start(self):
        route("/")(self.render)
        if self.protocol == "fastcgi":
            from flup.server.fcgi import WSGIServer
            WSGIServer(default_app(), bindAddress=(self.host, int(self.port))).run()
        elif self.protocol == "http":
            run(host=self.host, port=int(self.port))

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
    assert mode == "standalone", "Web server not set to standalone mode"
    assert dbfile and dbfile != ":memory:", "No database file"

    def startServer():
        import logging
        from lib.database import NaokoDB
        logging.basicConfig(format='%(name)-15s:%(levelname)-8s - %(message)s', stream=sys.__stderr__)
        server = NaokoWebServer(NaokoDB(dbfile), host, port, protocol)
        server.start()
    
    command = sys.argv[1] if len(sys.argv) > 1 else None
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
        server = NaokoWebServer(naoko.dbclient, naoko.webserver_host, naoko.webserver_port, naoko.webserver_protocol)
        server.start()

