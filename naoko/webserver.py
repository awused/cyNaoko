#!/usr/bin/env python
# A simple webserver for Naoko that serves up some interesting statistics.
# In integrated mode this is started with Naoko and uses her instance of NaokoDB, though not the thread.
from lib.bottle import route, run, default_app

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
            application = default_app()
            WSGIServer(application, bindAddress=(self.host, int(self.port))).run()
        elif self.protocol == "http":
            run(host=self.host, port=int(self.port))

if __name__ == "__main__":
    # Standalone mode runs the webserver as a daemon
    import ConfigParser
    import logging, sys, os
    from lib.database import NaokoDB
    from flup.server.fcgi import WSGIServer
    from lib.daemon.manager import manageDaemon

    config = ConfigParser.RawConfigParser()
    config.read("naoko.conf")
    dbfile = config.get("naoko", "db_file")
    webserver_mode = config.get("naoko", "webserver_mode")
    webserver_host = config.get("naoko", "webserver_host")
    webserver_port = config.get("naoko", "webserver_port")
    webserver_protocol = config.get("naoko", "webserver_protocol")
    assert webserver_mode == "standalone", "Web server not set to standalone mode"
    assert dbfile and dbfile != ":memory:", "No database file"

    def startServer(dbfile, host, port, protocol):
        logging.basicConfig(format='%(name)-15s:%(levelname)-8s - %(message)s', stream=sys.__stderr__)
        server = NaokoWebServer(NaokoDB(dbfile), host, port, protocol)
        server.start()
    
    command = sys.argv[1] if len(sys.argv) > 1 else None
    manageDaemon(startServer, command, sys.argv[0], "/tmp/naokoweb.pid", os.path.abspath(os.getcwd()), args=[dbfile, webserver_host, webserver_port, webserver_protocol])
    
else:
    import time
    def startServer(naoko):
        # Give Naoko time to set up everything 
        while not hasattr(naoko, "dbclient"):
            # Sleep until the NaokoDB is ready
            time.sleep(1)

        naoko.logger.debug("Starting web server in integrated mode on %s:%s." % (naoko.webserver_host, naoko.webserver_port, webserver_protocol))
        server = NaokoWebServer(naoko.dbclient, naoko.webserver_host, naoko.webserver_port)
        server.start()

