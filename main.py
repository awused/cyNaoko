
# The supervisor process that is responsible for starting and restarting Naoko
import threading, time
import ConfigParser

from naoko import SynchtubeClient
from settings import *

# Set up logging
logging.basicConfig(format='%(name)-15s:%(levelname)-8s - %(message)s')
logger = logging.getLogger("socket.io client")
logger.setLevel(logLevel)
(info, debug, warning, error) = (logger.info, logger.debug, logger.warning, logger.error)

config = ConfigParser.RawConfigParser()
config.read("naoko.conf")
room = config.get('naoko', 'room')
nick = config.get('naoko', 'nick')
pw   = config.get('naoko', 'pass')
spam = float(config.get('naoko', 'spam_interval'))
server = config.get('naoko', 'irc_server')
channel = config.get('naoko', 'irc_channel')
ircnick = config.get('naoko', 'irc_nick')
ircpw = config.get('naoko', 'irc_pass')

# Spin off the socket thread from the main thread.
try:
    t = threading.Thread(target=SynchtubeClient, args=[room, nick, pw, spam, server, channel, ircnick, ircpw])
    t.daemon=True;
    t.start()
    while t.isAlive(): time.sleep(100)
    time.sleep(10)
    print '\n Shutting Down'
except (KeyboardInterrupt, SystemExit):
    print '\n! Received keyboard interrupt'