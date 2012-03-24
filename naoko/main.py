#!/usr/bin/env python
# The supervisor process that is responsible for starting and restarting Naoko
import os, sys, time
import signal
import threading
from multiprocessing import Pipe, Process
name = "Launcher"

from naoko import SynchtubeClient
from settings import *

# Don't fork too often
MIN_DUR = 0.25

# Set up logging
logging.basicConfig(format='%(name)-15s:%(levelname)-8s - %(message)s')
logger = logging.getLogger("socket.io client")
logger.setLevel(logLevel)
(info, debug, warning, error) = (logger.info, logger.debug, logger.warning, logger.error)

class throttle:
    def __init__ (self, fn):
        self.fn = fn
        self.last_call = 0

    def __call__ (self, *args, **kwargs):
        remaining = MIN_DUR - time.time() + self.last_call
        if remaining > 0:
            time.sleep(remaining)
        self.last_call = time.time()
        self.fn(*args, **kwargs)

def spawn(script):
    (pipe_in, pipe_out) = Pipe(False)
    p = Process(target=script, args=(pipe_out,))
    p.daemon = True # If the main process crashes for any reason then kill the child process
    p.start()
    pipe_out.close()
    return (pipe_in, p)

@throttle
def run(script):
    global child
    (child_pipe, child) = spawn (script)
    print "[%s] Forked off (%d)\n" % (name, child.pid)
    try:
        while child_pipe.poll(TIMEOUT):
            buf = child_pipe.recv()
            if buf == "RESTART":
                time.sleep(5)
                break
            elif buf == "HEALTHY":
                continue
            else:
                raise Exception("Received invalid message (%s)"% (buf))
    except EOFError:
        print "[%s] EOF on child pipe" % (name)
    except IOError:
        print "[%s] IOError on child pipe" % (name)
    except OSError as e:
        print "Received exception ", str(e)
    finally:
        child.terminate()

if __name__ == '__main__':
    try:
        while True:
            run(SynchtubeClient)
    except KeyboardInterrupt:
        print "\n Shutting Down"
"""except IOError, AssertionError: # Windows Python process bug, you get the old code
    print "Failed to fork a process likely due to bugs in Python for Windows"
    print "Running Naoko anyway, but she will not automatically restart"
    try:
        t = threading.Thread(target=SynchtubeClient)
        t.daemon=True;
        t.start()
        while t.isAlive(): time.sleep(TIMEOUT)
        print '\n Shutting Down'
    except (KeyboardInterrupt):
        print '\n! Received keyboard interrupt'"""
