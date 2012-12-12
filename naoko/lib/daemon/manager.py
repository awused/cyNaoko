#!/usr/bin/env python
# Daemon code for python originally posted by anonymous and expanded in functionality by Desuwa

import sys, time
from daemon import Daemon

# The run method is assigned by manageDaemon
class MyDaemon(Daemon):
    pass

# Manages a daemon
# target : the object to be executed in a daemon process
# command : the argument for the manager start|stop|restart|status
# filename : the name of the file to be printed in the usage command
# pidfile : the file used to store the pid
# stdio : a tuple or list of up to three strings specificying files for stdin, stdout, and stderr for the daemon. They default to /dev/null
# wd : the working directory for the daemon process
# args : a tuple or list of arguments for the target
# kwargs : a dictionary of keyword arguments for the target
# This does not fail silently and communicates to the user over stdout.
# This should not be used as a component of something larger unless you know exactly what you're doing.
def manageDaemon(target, command, filename="manager",  pidfile="/tmp/daemon-example.pid", wd="/",  stdio=[], args=[], kwargs={}):
    def run(self):
        target(*args, **kwargs)
    MyDaemon.run = run
    daemon = MyDaemon(pidfile, wd, *stdio)

    if 'start' == command:
        daemon.start()
    elif 'stop' == command:
        daemon.stop()
    elif 'restart' == command:
        daemon.restart()
    elif 'status' == command:
        daemon.status()
    else:
        print "usage: %s start|stop|restart|status" % filename
        sys.exit(2)
    

if __name__ == "__main__":
    # Dummy method to demonstrate usage
    def run():
        while True:
            time.sleep(1)
    
    success = manageDaemon(run, sys.argv[1] if len(sys.argv) == 2 else None, sys.argv[0])
    daemon = MyDaemon('/tmp/daemon-example.pid')
    sys.exit(0)

