#!/usr/bin/env python
# Daemon code for python originally posted by anonymous and expanded in functionality by Desuwa
import sys, os, time, atexit
from signal import SIGTERM, SIGKILL
from errno import ESRCH
 
class Daemon:
    """
    A generic daemon class.
    
    Usage: subclass the Daemon class and override the run() method
    """
    def __init__(self, pidfile, wd, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.wd = wd
    
    def _daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced 
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit first parent
                sys.exit(0) 
        except OSError as e: 
            sys.stderr.write("\nfork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)
    
        # decouple from parent environment
        os.chdir(self.wd) 
        os.setsid() 
        os.umask(0) 
    
        # do second fork
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit from second parent
                sys.exit(0) 
        except OSError as e: 
            sys.stderr.write("\nfork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1) 
    
        print "Forked."
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
    
        # write pidfile
        atexit.register(self._delpid)
        pid = str(os.getpid())
        file(self.pidfile,'w+').write("%s\n" % pid)
    
    def _delpid(self):
        if os.path.exists(self.pidfile):
            os.remove(self.pidfile)
 
    def start(self):
        """
        Start the daemon
        """
        pid = self._check() 
    
        if pid:
            sys.stderr.write("Daemon already running.\n")
            sys.exit(1)
        
        # Start the daemon
        sys.stdout.write("Forking daemon: ")
        sys.stdout.flush()
        self._daemonize()
        self.run()
 
    def stop(self):
        """
        Stop the daemon
        """
        pid = self._check() 
    
        if not pid:
            sys.stderr.write("Daemon not running.\n")
            return # not an error in a restart
 
        # Try killing the daemon process    
        try:
            os.kill(pid, SIGKILL)
            while 1:
                time.sleep(0.1)
                os.kill(pid, SIGTERM)
        except OSError as e:
            if ESRCH == e.errno:
                self._delpid()
            else:
                print str(e)
                sys.exit(1)
        print "Daemon stopped."

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()
 
    def status(self):
        """
        Check the status of the daemon.
        """
        if self._check():
            print "Daemon running."
        else:
            print "Daemon not running."

    def _check(self):
        """
        Checks to see if the process is running and returns the pid if it is, and False if it isn't.
        Also removes stale pidfiles.
        """
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            return False
        
        try:
            os.kill(pid, 0)
        except OSError as e:
            if e.errno == ESRCH:
                print "Removing stale pidfile."
                self._delpid()
                return False
            print str(e)
            sys.exit(1)
        return pid

    def run(self):
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """
        pass
