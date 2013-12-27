#!/usr/bin/env python
# Naoko - A prototype synchtube bot
# Based on Denshi written in 2011 by Falaina falaina@falaina.net
#
# This software is released under the 2-clause BSD License.
# A copy of this license should have been provided with this 
# software. If not see
# <http://www.freebsd.org/copyright/freebsd-license.html>.

import hashlib
import itertools
import json
import logging
import random
import sched, time, math
import socket
import struct
import threading
import re
from urllib2 import Request, urlopen
from collections import namedtuple, deque
import ConfigParser
from datetime import datetime

from lib.repl import Repl
from settings import *
from webserver import startServer
from lib.database import NaokoDB
from lib.sioclient import SocketIOClient
from lib.ircclient import IRCClient
from lib.apiclient import APIClient

# Cleverbot doesn't like publicly posting code to access it. 
try:
    from lib.cbclient import CleverbotClient
except ImportError:
    class CleverbotClient(object):
        pass

try:
    from lib.mumble.client import MumbleClient
except ImportError:
    MumbleClient = False

# Package arguments for later use.
# Due to the way python handles scopes this needs to be used to avoid race conditions.
def package(fn, *args, **kwargs):
    def action():
        fn(*args, **kwargs)
    return action

# Decorator for simplicity of use
# Prevents users without adequate permissions from using commands.
class hasPermission(object):
    def __init__(self, mask, required=True, leader=False):
        self.mask = mask # Bitmask for the permission
        self.required = required # Some commands allow users without permission to take limited action
        self.leader = leader # Whether the command is allowed for anyone who is a mod
    def __call__(self, fn):
        def wrapped(naoko, command, user, *args, **kwargs):
            # Hybrid mods can be disabled
            name = user.name.lower()
            # Mods implicitly have all permissions
            if user.rank >= 2 or (self.leader and user.leader) or (user.rank >= 1 and naoko.hybridModStatus and name in naoko.hybridModList and (naoko.hybridModList[name] & naoko.MASKS[mask][0])):
                return fn(naoko, command, user, *args, **kwargs)
            elif not self.required:
                # Some commands allow users without permissions to take limited actions
                # Permission should default to True
                return fn(naoko, command, user, *args, permission=False, **kwargs)
        return wrapped

eight_choices = [
    "It is certain",
    "It is decidedly so",
    "Without a doubt",
    "Yes - definitely",
    "You may rely on it",
    "As I see it, yes",
    "Most likely",
    "Outlook good",
    "Signs point to yes",
    "Yes",
    "Reply hazy, try again",
    "Ask again later",
    "Better not tell you now",
    "Cannot predict now",
    "Concentrate and ask again",
    "Don't count on it",
    "My reply is no",
    "My sources say no",
    "Outlook not so good",
    "Very doubtful"]

# Simple Record Types for variable synchtube constructs
CytubeUser = namedtuple("CytubeUser",
                           ["name", "rank", "leader", "meta", "profile", "msgs"])

CytubeVideo = namedtuple("CytubeVideo",
                              ["vidinfo", "queueby", "temp", "uid"])
                              # currentTime also exists. It seems to be the duration as a float, in seconds
                              # except for the currently playing video. Not included with 'queue' frames.
                              # Best to ignore it for now, but this information will be needed for leading

                              # duration also exists but seems to be for display purposes only. It is currently ignored.
CytubeVidInfo = namedtuple("CytubeVidInfo", ["type", "id", "title", "seconds"])

IRCUser = namedtuple("IRCUser", ["name", "rank", "leader"])

# Generic object that can be assigned attributes
class Object(object):
    pass

# Synchtube  "client" built on top of a socket.io socket
# Synchtube messages are generally of the form:
#   ["TYPE", DATA]
# e.g., The self message (describes current client)
#   ["self" ["bbc2c922",22262,true,"jpg",false,true,21]]
# Which describes a particular connection for the user Naoko
# (uid 22262). The first field is the session identifier,
# second is uid, third is whether or not client is authenticated
# fourth is avatar type, and so on.
class Naoko(object):
    
    # Bitmasks for hybrid mods.
    MASKS = {
        "LEAD"          : (1, 'O'),         # O - Both the steal, lead, and mod commands.
        "BUMP"          : ((1 << 1), 'B'),  # B - Bumping videos.
        "DELETE"        : ((1 << 2), 'D'),  # D - Deleting videos.
        "KICK"          : ((1 << 3), 'K'),  # K - Kicking users.
        "BAN"           : ((1 << 4), 'Q'),  # Q - Banning and unbanning users, as well as viewing the banlist.
        "RESTART"       : ((1 << 5), 'R'),  # R - Restarting Naoko.
        "CLEAN"         : ((1 << 6), 'C'),  # C - The clean command.
        "SKIP"          : ((1 << 7), 'S'),  # S - Skipping videos.
        "LOCK"          : ((1 << 8), 'L'),  # L - Lock and unlock the playlist.
        "RANDOM"        : ((1 << 9), 'A'),  # A - Addrandom with more than 5 videos or load a playlist.
        "SETSKIP"       : ((1 << 11), 'E'), # E - Setskip.
        "DUPLICATES"    : ((1 << 12), 'T'), # T - Remove duplicate videos.
        "MUTE"          : ((1 << 13), 'M'), # M - Mute or unmute Naoko.
        "PURGE"         : ((1 << 14), 'G'), # G - Purge.
        "AUTOLEAD"      : ((1 << 15), 'U'), # U - Autolead.
        "AUTOSKIP"      : ((1 << 16), 'V'), # V - Autosetskip.
        "POLL"          : ((1 << 17), 'P'), # P - Start and end polls.
        "SHUFFLE"       : ((1 << 18), 'F'), # F - Shuffle.
        "UNREGSPAMBAN"  : ((1 << 19), 'I'), # I - Change whether unregistered users are banned for spamming or have multiple chances.
        "ADD"           : ((1 << 20), 'H'), # H - Add when the list is locked.
        "MANAGE"        : ((1 << 21), 'N'), # N - Enable or disable playlist management
        "PLAYLISTS"     : ((1 << 22), 'Y')} # Y - Save or delete playlists
    # Bitmasks for deferred tosses
    DEFERRED_MASKS = {
        "SKIP"          : 1,
        "UNBAN"         : 1 << 1,
        "SHUFFLE"       : 1 << 2}

    # Playback states
    _STATE_VOTE_SKIP        = -4
    _STATE_NORMAL_SKIP      = -3 # Switch initiated by Naoko
    _STATE_FORCED_SWITCH    = -2 # A switch initiated by a user before a video has finished
    _STATE_NORMAL_SWITCH    = -1 # A switch initiated normally at the end of a video
    _STATE_UNKNOWN          = 0
    _STATE_PLAYING          = 1
    _STATE_PAUSED           = 2

    def __init__(self, wasKicked, pipe=None):
        # Initialize all loggers
        self.logger = logging.getLogger("stclient")
        self.logger.setLevel(LOG_LEVEL)
        self.chat_logger = logging.getLogger("stclient.chat")
        self.chat_logger.setLevel(LOG_LEVEL)
        self.irc_logger = logging.getLogger("stclient.irc")
        self.irc_logger.setLevel(LOG_LEVEL)
       
        # Seem to have some kind of role in os.terminate() from the watchdog
        self.thread = threading.currentThread()
        self.thread.st = self
        self.thread.close = self.close

        self._getConfig()

        # If more than one thread attempts to close Naoko at the same time it will cause an error
        self.closeLock = threading.Lock()
        self.closing = threading.Event()
        # Since the video list can be accessed by two threads synchronization is necessary
        # This is currently only used to make nextVideo() thread safe
        self.vidLock = threading.Lock()
        
        self._initHandlers()
        self._initCommandHandlers()
        self._initIRCCommandHandlers()
        self._initPersistentSettings()

        self.rankList = {}
        self.room_info = {}
        self.vidlist = []
        self.skipLevel = None
        self.skips = deque(maxlen=3)
        self.muted = False
        self.doneInit = False
        
        # Workarounds for non-atomic operations
        self.verboseBanlist = False
        self.unbanTarget = None
        self.shuffleBump = False
        self.pendingSkip = False

        # Used to control taking and returning leader
        self.leader_queue = deque()
        self.leader_sid = None
        # Stores the action that will be necessary to give back leader after Naoko is done with it
        self.pendingToss = False
        # Used to avoid handing back the leader when asLeader is called multiple times in quick succession
        self.notGivingBack = False
        self.tossing = False
        self.deferredToss = 0
        # Tracks whether she is leading
        # Is not triggered when she is going to give the leader position back or turn tv mode back on
        self.leading = threading.Event()
         
        # Pending kicks/bans to prevent duplicates
        self.pending = {}

        # Used to implement a three-strikes policy
        self.banTracker = {}

        # By default USER_COUNT_THROTTLE is 0 so this will have no effect
        self.userCountTime = time.time() - USER_COUNT_THROTTLE
       
        # If we were kicked try to take back the room forcibly
        # May result in weirdness
        self.wasKicked = wasKicked
        self.beingKicked = False

        # Used to avoid spamming chat or the playlist
        self.last_random = time.time() - 5
        self.last_quote = time.time() - 5
       
        # All the information related to playback state
        self.state = Object()
        self.state.state = self._STATE_UNKNOWN
        self.state.Id = -1
        self.state.current = None
        self.state.time = 0
        self.state.pauseTime = -1.0
        self.state.dur = 0
        self.state.reason = None
        self.skipOverride = False # Overrides the state when determining whether a video should be deleted

        # Room settings
        self.channelOpts = {}
        
        # Tracks when she needs to update her playback status
        # This is used to interrupt her timer as she is waiting for the end of a video
        self.playerAction = threading.Event()
        
        self.userlist = {}

        self.io_url = self._readIOUrl()

        if not self.io_url:
            self.logger.info("Retrieving IO_URL")
            try:
                io_url = urlopen("http://%s/assets/js/iourl.js" % (self.domain)).read()
                # Unless someone has changed their iourl.js a lot this is going to work
                self.io_url = io_url[io_url.rfind("var IO_URL"):].split('"')[1]
            except Exception:
                self.logger.warning("Unable to load iourl.js, using default io_url if available.")
                self.io_url = self.default_io_url 
        else:
            self._writeIOUrl("")

        # Assume HTTP because Naoko can't handle other protocols anyway
        socket_ip, socket_port = self.io_url[7:].split(':')
        
        self.logger.info("Starting SocketIO Client")
        self.client = SocketIOClient(socket_ip, int(socket_port), "socket.io", {"t": int(round(time.time() * 1000))})
        
        # Various queues and events used to sychronize actions in separate threads
        # Some are initialized with maxlen = 0 so they will silently discard actions meant for non-existent threads
        self.st_queue = deque()
        self.irc_queue = deque(maxlen=0)
        self.mumble_queue = deque(maxlen=0)
        self.sql_queue = deque(maxlen=0)
        self.api_queue = deque()
        self.st_action_queue = deque()
        self.add_queue = deque()
        # Events are used to prevent busy-waiting
        self.sqlAction = threading.Event()
        self.stAction = threading.Event()
        self.apiAction = threading.Event()
        self.addAction = threading.Event()

        # Initialize the clients that are always used
        self.apiclient = APIClient(self.apikeys)
        self.cbclient = CleverbotClient()
        self.client.connect()
        self.mumbleclient = False

        # Set a default selfUser with admin permissions, it will be updated later
        self.selfUser = CytubeUser(self.name, 3, False, {"afk": False}, {"text": "", "image": ""}, deque(maxlen=3))

        # Connect to the room
        self.send("joinChannel", {"name": self.room})
        
        # Log In
        self.send ("login", {"name": self.name, "pw": self.pw})

        # Start the threads that are required for all normal operation
        self.chatthread = threading.Thread(target=Naoko._chatloop, args=[self])
        self.chatthread.start()

        self.stthread = threading.Thread(target=Naoko._stloop, args=[self])
        self.stthread.start()

        self.stlistenthread = threading.Thread(target=Naoko._stlistenloop, args=[self])
        self.stlistenthread.start()

        self.addthread = threading.Thread(target=Naoko._addloop, args=[self])
        self.addthread.start()

        #self.playthread = threading.Thread(target=Naoko._playloop, args=[self])
        #self.playthread.start()

        self.apithread = threading.Thread(target=Naoko._apiloop, args=[self])
        self.apithread.start()

        # Start the optional threads
        if self.irc_nick:
            self.ircclient = False
            self.ircthread = threading.Thread(target=Naoko._ircloop, args=[self])
            self.ircthread.start()
        
        if self.mumble_host and MumbleClient:
            self.mumblethread = threading.Thread(target=Naoko._mumbleloop, args=[self])
            self.mumblethread.start()

        if self.dbfile:
            self.sql_queue = deque()
            self.sqlthread = threading.Thread(target=Naoko._sqlloop, args=[self])
            self.sqlthread.start()
            # A database is required for Naoko's web server
            if self.webserver_mode == "embedded":
                self.webthread = threading.Thread(target=startServer, args=[self])
                self.webthread.start()

        # Start a REPL on the specified port. Only accept connections from localhost
        # and expose ourself as 'naoko' in the REPL's local scope
        # WARNING: THE REPL WILL REDIRECT STDOUT AND STDERR.
        # the logger will still go to the the launching terminals
        # stdout/stderr, however print statements will probably be rerouted
        # to the socket.
        # This is not checked by the healthcheck
        if self.repl_port:
            self.repl = Repl(port=int(self.repl_port), host='localhost', locals={"naoko": self, "package": package})

        # Healthcheck loop, reports to the watchdog timer every 5 seconds
        while not self.closing.wait(5):
            # Sleeping first lets everything get initialized
            # The parent process will wait
            try:
                status = self.stthread.isAlive() and self.stlistenthread.isAlive()
                status = status and (not self.irc_nick or self.ircthread.isAlive())
                status = status and self.chatthread.isAlive()
                # Catch the case where the client is still connecting after 5 seconds
                status = status and (not self.client.heartBeatEvent or self.client.hbthread.isAlive())
                status = status and (not self.dbfile or self.sqlthread.isAlive())
                status = status and (not self.dbfile or self.webserver_mode != "embedded" or self.webthread.isAlive())
                status = status and (not self.mumbleclient or self.mumblethread.isAlive())
                status = status and (not self.mumbleclient or not self.mumbleclient.heartBeatEvent or self.mumbleclient.hbthread.isAlive())
                #status = status and self.playthread.isAlive()
                status = status and self.apithread.isAlive()
                status = status and self.addthread.isAlive()
            except Exception as e:
                self.logger.error(e)
                status = False
            if status and pipe:
                pipe.send("HEALTHY")
            if not status:
                self.close()
        else:
            if pipe:
                if self.beingKicked:
                    self.logger.warn("Kicked")
                    pipe.send("KICKED")
                else:
                    self.logger.warn("Restarting")
                    pipe.send("RESTART")

    # Responsible for listening to communication from Synchtube
    def  _stlistenloop(self):
        client = self.client
        while not self.closing.isSet():
            data = client.recvMessage()
            try:
                data = json.loads(data)
            except ValueError as e:
                self.logger.warn("Failed to parse"  + data)
                raise e;
            if not data or len(data) == 0:
                continue
            st_type = data["name"]
            try:
                if "args" in data:
                    arg = data["args"][0]
                else:
                    arg = ''
                fn = self.handlers[st_type]
            except KeyError:
                self.logger.warn("No handler for %s [%s]", st_type, arg)
            else:
                self.stExecute(package(fn, st_type, arg))
        else:
            self.logger.info("Synchtube Listening Loop Closed")
            self.close()

    def _mumbleloop(self):
        self.mumbleclient = client = MumbleClient(self.mumble_host, self.mumble_port, self.mumble_name, self.mumble_pw, self.mumble_channel)
        client.connect()

        self.mumble_queue = deque()
        while not self.closing.isSet():
            name, msg = client.recvMessage()
            
            self.sqlExecute(package(self.insertChat, msg=msg, username=name, 
                        userid=name, timestamp=None, protocol='MUMBLE', channel="MUMBLE", flags=None))

            self.enqueueMsg("(%s) %s" % (name, self._fixChat(msg)), mumble=False)
        else:
            self.logger.info("Mumble Loop Closed")

    # Responsible for handling messages from Synchtube
    def _stloop(self):
        client = self.client
        while self.stAction.wait():
            self.stAction.clear()
            if self.closing.isSet(): break
            while self.st_action_queue:
                self.st_action_queue.popleft()()
        self.logger.info("Synchtube Loop Closed")

    # Responsible for communicating with IRC
    def _ircloop(self):
        time.sleep(3)
        self.irc_logger.info("Starting IRC Client")
        self.ircclient = client = IRCClient(self.server, self.channel, self.irc_nick, self.ircpw)
        self.irc_queue = deque()
        failCount = 0
        while not self.closing.isSet():
            frame = deque(client.recvMessage().split('\n'))
            while len(frame) > 0:
                data = self.filterString(frame.popleft().strip())[1]
                if data.find("PING :") != -1:
                    client.ping()
                elif data.find("PRIVMSG " + self.channel + " :") != -1:
                    name = data.split('!', 1)[0][1:]
                    msg = data[data.find("PRIVMSG " + self.channel + " :") + len("PRIVMSG " + self.channel + " :"):]
                    if not name == self.irc_nick:

                        self.sqlExecute(package(self.insertChat, msg=msg, username=name, 
                                userid=name, timestamp=None, protocol='IRC', channel=self.channel, flags=None))

                        self.enqueueMsg(("(" + name + ") " + msg), irc=False)
                        self.chatCommand(IRCUser(*(name, 1, False)), msg, True)
                    self.irc_logger.info("IRC %r:%r", name, msg)
                # Currently ignore messages sent directly to her
                elif data.find("PRIVMSG " + self.irc_nick + " :") != -1:
                    continue
                
                # Failed to send to the channel
                elif data.find("404 " + self.irc_nick + " " + self.channel +" :Cannot send to channel") != -1:
                    failCount += 1
                    self.irc_logger.debug("Failed to send to channel %d times" % (failCount))
                    if failCount > 4:
                        self.irc_logger.info("Could not send to %s %d times, restarting" % (self.channel, failCount))
                        self.sendChat("Failed to send messages to the IRC channel %d times, check my configuration file." % (failCount))
                        self.close()
                    if self.ircpw and not client.loggedIn:
                        client.send("PRIVMSG nickserv :id " + self.ircpw + "\n")
                    if not client.inChannel:
                        client.send("JOIN " + self.channel + "\n")

                elif data.find("NOTICE " + self.irc_nick + " :Password accepted - you are now recognized.") != -1:
                    client.loggedIn = True
                    self.irc_logger.debug("Authenticated")
                elif data.find("JOIN :" + self.channel) != -1:
                    client.inChannel = True
                    self.irc_logger.debug("Joined Channel")

                # Disable IRC support when an incorrect password is provided.
                elif data.find("NOTICE " + self.irc_nick + " :Password incorrect.") != -1:
                    self.disableIRC("Incorrect IRC password provided. Disabling IRC support.")
                    return

                # Nickname in use, attempt to ghost if a password is provided or use an alternate name
                elif data.find("433 * " + self.irc_nick + " :Nickname is already in use.") != -1:
                    if self.ircpw:
                        self.irc_logger.info("Nickname in use, attempting to ghost.")
                        client.send("NICK " + self.irc_nick[:24] + "_naoko\n")
                        client.send("PRIVMSG nickserv :ghost " +self.irc_nick + " " + self.ircpw + "\n")
                    else:
                        failCount += 1
                        if failCount > 4:
                            self.disableIRC("Unable to find an unused IRC nickname. Disabling IRC support.")
                            return
                        self.irc_logger.info("Nickname in use and no password provided. Switching to alternate name")
                        self.irc_nick = self.irc_nick[:29] + str(failCount)
                        client.send("NICK " + self.irc_nick + "\n")
                # Ghost Succeeded
                elif data.find("NOTICE " + self.irc_nick[:24] + "_naoko :Ghost with your nick has been killed.") != -1:
                    self.irc_logger.info("Ghost successful, reverting name.")
                    client.send("NICK " + self.irc_nick + "\n")
                    client.send("PRIVMSG nickserv :id " + self.ircpw + "\n")
                    client.send("JOIN " + self.channel + "\n")
                # Ghost failed. Since the nickname is in use and an incorrect password is provided disable IRC
                # to avoid being stuck in a restart loop and bring attention to the incorrect password.
                elif data.find("NOTICE " + self.irc_nick[:24] + "_naoko :Access denied.") != -1:
                    self.disableIRC("IRC nickname in use and incorrect password provided. Disabling IRC support.")
                    return
                elif data[:5] == "ERROR":
                    err = "Unknown Error"
                    if data.find("(") != -1 and data.find(")") != -1:
                        err = data[data.find("(") + 1:data.find(")")]
                    self.disableIRC("IRC connection closed due to %s. Restarting in 2 minutes." % (err))
                    time.sleep(2*60)
                    self.close()
        else:
            self.logger.info("IRC Loop Closed")

    # Responsible for sending chat messages to IRC and Synchtube.
    # Only the $status command and error messages should send a chat message to Synchtube or IRC outside this thread.
    def _chatloop(self):
        while not self.closing.isSet():
            # Detect when far too many messages are being sent and clear the queue
            if len(self.irc_queue) > 20 or len(self.st_queue) > 20 or len(self.mumble_queue) > 20:
                time.sleep(5)
                self.irc_queue.clear()
                self.st_queue.clear()
                self.mumble_queue.clear()
                continue
            if self.muted:
                self.irc_queue.clear()
                self.st_queue.clear()
                self.mumble_queue.clear()
            else:
                if self.irc_queue:
                    self.ircclient.sendMsg(self.irc_queue.popleft())
                if self.st_queue:
                    self.sendChat(self.st_queue.popleft())
                if self.mumble_queue:
                    self.mumbleclient.sendChat(self.mumble_queue.popleft())
            time.sleep(self.spam_interval)
        else:
            self.logger.info("Chat Loop Closed")

    # Responsible for handling playback
    """
    def _playloop(self):
        while self.leading.wait():
            if self.closing.isSet(): break
            if not self.doneInit:
                # When the room is initalizing, leader comes before cm
                # If Naoko is the only one in the room, and therefore leader on connection, this will result in non-deterministic behaviour
                time.sleep(0.01)
                continue
            sleepTime = self.state.dur + (self.state.time / 1000) - time.time() + 1
            if sleepTime < 0:
                sleepTime = 0
            if not self.state.current:
                self.enqueueMsg("Unknown video playing, skipping.")
                self.nextVideo()
                self.state.state = -1
                sleepTime = 60
            elif self.state.reason:
                self.enqueueMsg(self.state.reason)
                self.state.reason = None
                self.nextVideo()
                self.state.state = -1
                sleepTime = 60
            # If the video is paused, unpause it automatically.
            elif self.state.state == 2:
                unpause = 0
                if not self.state.pauseTime < 0:
                    unpause = self.state.pauseTime - (self.state.time / 1000)
                self.pauseTime = -1.0
                self.logger.info("Unpausing video %.3f seconds from the beginning." % (unpause))
                self.send("s", [1, unpause])
                sleepTime = 60
            elif self.state.state == 0:
                sleepTime = 60
            self.logger.debug("Waiting %.3f seconds for the end of the video." % (sleepTime))
            if not self.playerAction.wait(sleepTime):
                if self.closing.isSet(): break
                if not self.leading.isSet(): continue
                self.nextVideo()
            self.playerAction.clear()
        self.logger.info("Playback Loop Closed")
    """

    def _sqlloop(self):
        self.db_logger = logging.getLogger("stclient.db")
        self.db_logger.setLevel(LOG_LEVEL)
        self.db_logger.info("Starting Database Client")
        self.dbclient = client = NaokoDB(self.dbfile)
        while self.sqlAction.wait():
            self.sqlAction.clear()
            if self.closing.isSet(): break
            while self.sql_queue:
                self.sql_queue.popleft()()
        self.logger.info("SQL Loop Closed")

    # This loop is responsible for dealing with all external APIs
    # This includes validating Youtube videos and any future functionality
    def _apiloop(self):
        while self.apiAction.wait():
            self.apiAction.clear()
            if self.closing.isSet(): break
            while self.api_queue:
                self.api_queue.popleft()()
        self.logger.info("API Loop Closed")

    # Responsible for adding videos without triggering the anti-flood
    def _addloop(self):
        safety = 1.20 # 20% safety factor
        burst = 10.0
        sustained = 2.0 / safety
        lastAdd = time.time() - 10
        current = 0

        while self.addAction.wait():
            self.addAction.clear()
            if self.closing.isSet(): break
            while self.add_queue:
                if time.time() - lastAdd > burst / sustained:
                    current = 0
                if current >= burst:
                    # The eleventh video needs a bit of an extra delay
                    # Reason for this is that the first ten videos likely arrive all at once and the server needs a second to process them
                    delay = lastAdd + ((current == burst) + 1)/sustained - time.time()
                    if delay > 0:
                        time.sleep(delay)
                self.add_queue.popleft()()
                lastAdd = time.time()
                current += 1
        self.logger.info("Add Loop Closed")

    # Initialize stored settings that can be changed within Synchtube.
    # In the case of any error, default to everything being disabled.
    def _initPersistentSettings(self):
        self.logger.debug("Reading persistent settings.")
        f = None
        try:
            f = open("persistentsettings", "rb")
            line = f.readline()
            while line and line[0] == '#':
                line = f.readline()
            if line == "ON\n" or line == "OFF\n":
                version = 0
            else:
                version = int(line.strip())
                line = f.readline()
            self.autoLead = (line == "ON\n")
            line = f.readline()
            
            self.autoSkip = line[:-1]
            line = f.readline()
            
            self.unregSpamBan = (line == "ON\n")
            line = f.readline()
            
            # Determines which classes of users can use commands, takes priority over hybrid mods
            self.commandLock = ""
            if (version >= 1):
                self.commandLock = line[:-1]
                line = f.readline()

            # Whether Naoko is actively managing the playlist and adding videos to extend it
            self.managing = False
            if (version >= 2):
                self.managing = (line == "ON\n")
                line = f.readline()

            self.hybridModStatus = (line == "ON\n")
            self.hybridModList = {}
            line = f.readline()
            while line:
                line = line.strip().split(' ', 1)
                self.hybridModList[line[0]] = int(line[1])
                line = f.readline()
        except Exception as e:
            self.logger.debug("Reading persistent settings failed.")
            self.logger.debug(e)
            self.autoLead = False
            self.autoSkip = "none"
            self.managing = False
            self.hybridModStatus = False
            self.hybridModList = {}
            self.unregSpamBan = False
            self.commandLock = ""
        finally:
            if f:
                f.close()
    
    # Read the IO_URL cache
    def _readIOUrl(self):
        self.logger.debug("Reading io_url.")
        f = None
        try:
            f = open("iourlcache", "rb")
            return f.readline().strip()
        except Exception as e:
            self.logger.debug("Reading cached io_url failed.")
            self.logger.debug(e)
            return False
        finally:
            if f:
                f.close()

    def _initHandlers(self):
        """              "leader"           : self.leader,
                         "history"          : self.roomSetting,
                         "vote_settings"    : self.roomSetting,
                         "playlist_rules"   : self.roomSetting,
                         "num_votes"        : self.roomSetting,
                         "self"             : self.selfInfo,
                         "kick"             : self.kicked}"""
        self.handlers = {"chatMsg"          : self.chat,
                        "channelOpts"       : self.channelOpts,
                        "userlist"          : self.users,
                        "addUser"           : self.addUser,
                        "userLeave"         : self.remUser,
                        "setCurrent"        : self.currentVideo,
                        "setPlaylistMeta"   : self.playlistMeta,
                        "queue"             : self.addMedia,
                        "playlist"          : self.playlist,
                        "delete"            : self.removeMedia,
                        "moveVideo"         : self.moveMedia,
                        "chatFilters"       : self.ignore,
                        "rank"              : self.ignore,
                        "closePoll"         : self.ignore,
                        "newPoll"           : self.ignore,
                        "updatePoll"        : self.ignore,
                        "queueFail"         : self.ignore, # Might want to catch these if there's ever something cytube catches that Naoko doesn't
                        "mediaUpdate"       : self.mediaUpdate,
                        "changeMedia"       : self.mediaUpdate,
                        "setTemp"           : self.setTemp,
                        "acl"               : self.acl,
                        "usercount"         : self.userCount,
                        "login"             : self.login,
                        "setPlaylistLocked" : self.playlistLock,
                        "setAFK"            : self.setAFK}
                        #leader  -- Use being leader as a signal to actively manage the playlist?
                                # -- Requires actually implementing media switching and sending mediaUpdates every 5 seconds
                                                    # Note: seems to be 5 seconds regardless of if a media switch has occurred
                                # could make $lead a toggle and it'd provide good 
                        #updateUser - worry about selfUser, maybe make selfUser a function
                        #disconnect
                        #accouncement
                        #voteskip (count, need)
                        #kick
                        #banlist
                        #drinkCount - probably ignore
                        # poll information probably doesn't need to be tracked unless I need to track whether a poll is open
                                    # newPoll/updatePoll/closePoll
                        # seenlogins - used to determine valid targets for bans
                        # joinMessage

    def _initCommandHandlers(self):
        """
                                "steal"             : self.steal,
                                "lead"              : self.lead,
                                "mod"               : self.makeLeader,
                                "ban"               : self.ban,
                                "lastbans"          : self.lastBans,
                                "lastban"           : self.lastBans,
                                "unban"             : self.unban,
                                "banlist"           : self.getBanlist,
                                "setskip"           : self.setSkip,
                                "hybridmods"        : self.hybridMods,
                                "permissions"       : self.permissions,
                                "autolead"          : self.autoLeader,
                                "autosetskip"       : self.autoSetSkip,
                                "shuffle"           : self.shuffleList,
                                "unregspamban"      : self.setUnregSpamBan,
                                "commandlock"       : self.setCommandLock,"""
        self.commandHandlers = {
                                # Functions that only result in chat messages being sent
                                # These functions do not access the database directly, change the states of any users, modify the playlist, or have any effects outside of chat
                                "status"            : self.status,
                                "choose"            : self.choose,
                                "permute"           : self.permute,
                                "d"                 : self.dice,
                                "dice"              : self.dice,
                                "ask"               : self.ask,
                                "8ball"             : self.eightBall,
                                "help"              : self.help,
                                "eval"              : self.eval,
                                "steak"             : self.steak,
                                "poll"              : self.poll,
                                "endpoll"           : self.endPoll,
                                # Functions that require a database
                                "addrandom"         : self.addRandom,
                                "blacklist"         : self.blacklist,
                                "quote"             : self.quote,
                                "saveplaylist"      : self.savePlaylist,
                                "deleteplaylist"    : self.deletePlaylist,
                                # Functions that query an external API
                                "cleverbot"         : self.cleverbot,
                                "translate"         : self.translate,
                                "wolfram"           : self.wolfram,
                                "anagram"           : self.anagram,
                                # Functions for controlling Naoko that do not affect the room or permissions
                                "restart"           : self.restart,
                                "mute"              : self.mute,
                                "unmute"            : self.unmute,
                                # Functions that modify the playlist
                                "clean"             : self.cleanList,
                                "duplicates"        : self.cleanDuplicates,
                                "delete"            : self.delete,
                                "purge"             : self.purge,
                                "bump"              : self.bump,
                                "management"        : self.setPlaylistManagement,
                                "lock"              : self.lock,
                                "unlock"            : self.lock,
                                "add"               : self.add,
                                "skip"              : self.skip,
                                "accident"          : self.accident,
                                "loadplaylist"      : self.loadPlaylist,
                                "shuffle"           : self.shuffleList,
                                # Functions that change the states of users
                                "kick"              : self.kick,
                                # Other
                                "setskip"           : self.setSkip}
                                

    def _initIRCCommandHandlers(self):
        self.ircCommandHandlers = {"status"             : self.status,
                                   "choose"             : self.choose,
                                   "permute"            : self.permute,
                                   "ask"                : self.ask,
                                   "8ball"              : self.eightBall,
                                   "steak"              : self.steak,
                                   "d"                  : self.dice,
                                   "dice"               : self.dice,
                                   "cleverbot"          : self.cleverbot,
                                   "translate"          : self.translate,
                                   "wolfram"            : self.wolfram,
                                   "anagram"            : self.anagram,
                                   "eval"               : self.eval,
                                   "help"               : self.help,
                                   "quote"              : self.quote}

    # Handle chat commands from both IRC and Synchtube
    def chatCommand(self, user, msg, irc=False):
        if not msg or msg[0] != '$': return
       
        """
        if self.commandLock == "Mods" and not user.mod:
            return
        elif self.commandLock == "Registered" and not user.uid:
            return
        elif self.commandLock == "Named" and user.name == "unnamed":
            return
        """
        commands = self.commandHandlers
        if irc:
            commands = self.ircCommandHandlers

        line = msg[1:].split(' ', 1)
        command = line[0].lower()
        try:
            if len(line) > 1:
                arg = line[1].strip()
            else:
                arg = ''
            fn = commands[command]
        except KeyError:
            # Dice is a special case
            if re.match(r"^[0-9]+d[0-9]+$", command):
                self.dice(command, user, " ".join(command.split('d')))
            else:
                self.logger.warn("No handler for %s [%s]", command, arg)
        else:
            fn(command, user, arg)

    # Executes a function in the main Synchtube thread
    def stExecute(self, action):
        self.st_action_queue.append(action)
        self.stAction.set()

    def sqlExecute(self, action):
        self.sql_queue.append(action)
        self.sqlAction.set()

    def apiExecute(self, action):
        self.api_queue.append(action)
        self.apiAction.set()

    def addExecute(self, action):
        self.add_queue.append(action)
        self.addAction.set()

    def nextVideo(self):
        if len(self.vidlist) == 1:
            self.pendingSkip = True
        if not self.vidlist or len(self.vidlist) <= 1:
            if self.managing:
                self.stExecute(package(self.addRandom, "addrandom", self.selfUser, ""))
            else:
                self.stExecute(package(self.addRandom, "addrandom 1", self.selfUser, ""))
        else:
            self.state.state = self._STATE_NORMAL_SKIP
            self.skipOverride = True
            self.send("playNext")

    def disableIRC(self, reason):
        self.irc_logger.warning(reason)
        self.sendChat(reason)
        self.irc_nick = None
        self.irc_queue = deque(maxlen=0)
        self.ircclient.close()

    # Enqueues a message for sending to both IRC and Synchtube
    # This should not be used for bridging chat between IRC and Synchtube
    def enqueueMsg(self, msg, st=True, irc=True, mumble=True):
        if irc: self.irc_queue.append(msg)
        if st: self.st_queue.append(msg)
        if mumble: self.mumble_queue.append(msg)

    def close(self):
        self.closeLock.acquire()
        if self.closing.isSet():
            self.closeLock.release()
            return
        self.closing.set()
        self.closeLock.release()
        #self.client.close()
        self.repl.close()
        self.leading.set()
        self.playerAction.set()
        self.apiAction.set()
        self.sqlAction.set()
        self.stAction.set()
        self.addAction.set()
        if self.irc_nick and self.ircclient:
            self.ircclient.close()
        if self.mumbleclient:
            self.mumbleclient.close()

    def sendChat(self, msg):
        #self.logger.debug(repr(msg))
        self.send("chatMsg", {"msg": msg})

    def send(self, tag='', data=''):
        buf = {"name": tag}
        if data != '':
            buf["args"] = [data]
        try:
            buf = json.dumps(buf, encoding="utf-8")
        except UnicodeDecodeError:
            buf = json.dumps(buf, encoding="iso-8859-15")
        self.client.send(5, data=buf)

    def checkVideo(self, site, vid): 
        # appendleft so it doesn't wait for the entire playlist to be checked
        self.api_queue.appendleft(package(self._checkVideo, site, vid))
        self.apiAction.set()

    # Skips the current invalid video if she is leading.
    # Otherwise saves that information for if she does take lead.
    def invalidVideo(self, reason):
        if reason and self.managing:
            self.enqueueMsg(reason, irc=False, mumble=False)
            self.nextVideo()

    # Kicks a user for something they did in chat
    # Tracks kicks by username for a three strikes policy
    # REIMPLEMENT
    """
    def chatKick(self, user, reason):
        if self.pending.has_key(user.name):
            return
        else:
            self.pending[user.sid] = True
            if self.banTracker.has_key(user.nick):
                self.banTracker[user.nick] = self.banTracker[user.nick] + 1
            else:
                self.banTracker[user.nick] = 1

            reason = "[%d times] %s" % (self.banTracker[user.nick], reason)
            if self.banTracker[user.nick] >= 3 or (not user.uid and self.unregSpamBan):
                self.banTracker.pop(user.nick)
                self.asLeader(package(self._banUser, user.sid, reason))
            else:
                self.asLeader(package(self._kickUser, user.sid, reason))
    """

    # Handlers for Cytube message types
    # All of them receive input in the form (tag, data)

    def currentVideo(self, tag, data):
        old = self.state.current
        self.state.current = self.getVideoIndexById(data)
        self.state.Id = data
        # Case where the playlist is empty
        if self.state.current == -1 or not self.vidlist:
            self.state.current = -1
            self.state.state = self._STATE_UNKNOWN
            return
       
        # TODO -- Remove this quick fix
        if self.state.dur - self.state.time <= 6.0:
            # This should make false positives as rare as possible
            self.state.state = self._STATE_NORMAL_SWITCH
        elif self.state.state != self._STATE_NORMAL_SKIP:
            self.state.state = self._STATE_FORCED_SWITCH
        # END QUICK FIX 

        self.state.dur = self.vidlist[self.state.current].vidinfo.seconds

        if self.managing and (old or old == 0): # Starting a new video
            # playlistIdx doesn't get sent when videos are moved or deleted but check the player state anyway.
            if (self.state.state == self._STATE_NORMAL_SWITCH or self.state.state == self._STATE_NORMAL_SKIP or self.skipOverride) and old != -1 and self.state.current != old and not self.vidlist[old].temp:
                self.deleteMedia(self.vidlist[old].uid)
                self.state.state = self._STATE_UNKNOWN
                self.skipOverride = False


    def playlistMeta(self, tag, data):
        if "count" in data and data["count"] != len(self.vidlist):
            self.logger.warn("Video list out of sync, restarting. This is serious. Tell Desuwa.")
            self.logger.warn("Expected: %d. Actual: %d" % (len(self.vidlist), data["count"]))
            # TODO -- Re-enable this check later
            #self.close()

    def mediaUpdate(self, tag, data):
        if self.state.state == self._STATE_UNKNOWN and tag == "changeMedia":
            self.state.dur = data["seconds"]
        
        time = data["currentTime"]
        if tag == "changeMedia":
            if self.managing:
                if data["type"] in ["yt", "bt", "dm", "vi", "sc"]:
                    self.checkVideo(data["type"], data["id"])

                if self.doneInit:
                    self.enqueueMsg("Playing: %s" % (data["title"]), irc=False, mumble=False)
 
            if self.state.dur - self.state.time <= 6.0:
                # This should make false positives as rare as possible
                self.state.state = self._STATE_NORMAL_SWITCH
            elif self.state.state != self._STATE_NORMAL_SKIP:
                self.state.state = self._STATE_FORCED_SWITCH
        else:
            self.state.state = self._STATE_PLAYING
        
        self.state.time = data["currentTime"]
        
        # Add random videos a little in advance since there's no atomic way to change to a new video
        # Actually leading will allow more control over the room, but this is fine for now
        if self.managing and len(self.vidlist) <= 1 and self.state.dur - self.state.time <= 6 and (self.state.time != -1 or self.state.dur <= 6):
            self.sqlExecute(package(self.addRandom, "addrandom", self.selfUser, ""))

    def acl(self, tag, data):
        self.rankList = {}
        for u in data:
            self.rankList[u["name"]] = u["rank"]
    
    def setTemp(self, tag, data):
        idx = self.getVideoIndexById(data["uid"])
        self.vidLock.acquire()
        self.vidlist[idx] = self.vidlist[idx]._replace(temp=data["temp"])
        self.vidLock.release()
        
    def addMedia(self, tag, data):
        self._addVideo(data["item"], self.getVideoIndexById(data["after"]) + 1)
        if self.pendingSkip:
            self.nextVideo()
            self.pendingSkip = False

    def removeMedia(self, tag, data):
        self._removeVideo(data["uid"])
        if len(self.vidlist) == 0:
            self.nextVideo()

    def deleteMedia(self, uid):
        self.send("delete", uid)

    def moveMedia(self, tag, data):
        self._moveVideo(data["from"], data["after"])

    def playlist(self, tag, data):
        self.clear(tag, None)
        for i, v in enumerate(data):
            # Don't add the entire playlist to the database
            # It's also unsafe to delete any videos detected as invalid
            self._addVideo(v, i, False)
        if len(self.vidlist) == 0:
            self.nextVideo()

    def clear(self, tag, data):
        self.vidLock.acquire()
        self.vidlist = []
        self.vidLock.release()
        
    def ignore(self, tag, data):
        self.logger.debug("Ignoring %s", tag)
        #self.logger.debug("Ignoring %s, %s", tag, data)

    def login(self, tag, data):
        if not data["success"] or "error" in data:
            if "error" in data:
                raise Exception(data["error"])
            else:
                raise Exception("Failed to login.")
        # Set AFK on join
        self.sendChat("/afk")

    def playlistLock(self, tag, data):
        self.room_info["locked"] = data["locked"]

    def setAFK(self, tag, data):
        if not data["name"]==self.name:return
        if not data["afk"]:
            self.sendChat("/afk")
        
    def addUser(self, tag, data, isSelf=False):
        self._addUser(data, data["name"] == self.name)
  
    # Stores the number of viewers, not just the number of named users
    def userCount(self, tag, data):
        self._storeUserCount(data)

    def remUser(self, tag, data):
        try:
            del self.userlist[data["name"]]
            if self.pending.has_key(data["name"]):
                del self.pending[data["name"]]
        except KeyError:
            self.logger.exception("Failure to delete user %s from %s", data["name"], self.userlist)

    def users(self, tag, data):
        for u in data:
            self._addUser(u)

    # REIMPLEMENT
    """
    def banlist(self, tag, data):
        if not self.unbanTarget:
            # If there is no pending unban simply display the list.
            out = []
            for ban in data:
                if not self.verboseBanlist:
                    out.append(self.filterString(ban[0], True)[1])
                else:
                    out.append("%s %s" % (self.filterString(ban[0], True)[1], ban[1]))
            self.verboseBanlist = False
            self.enqueueMsg("Banlist: %s" % (", ".join(out)))
        else:
            # If there is a pending unban perform it if a target can be found.
            self.logger.info("Unbanning %s" % (self.unbanTarget))
            target = None
            for ban in data:
                if self.unbanTarget.lower() == ban[0].lower():
                    self.unbanTarget = ban[1]
                if self.unbanTarget == ban[1]:
                    target = ban[1]
                    break
            if target and self.leader_sid == self.sid:
                self.send("unban", {"id": target})
            self.unbanTarget = None
            if self.deferredToss & self.DEFERRED_MASKS["UNBAN"]:
                self.deferredToss &= ~self.DEFERRED_MASKS["UNBAN"]
                if not self.deferredToss:
                    self.tossLeader()
    """

    # REIMPLEMENT
    """
    def kicked(self, tag, data):
        if self.doneInit:
            self.beingKicked = True
        self.close()
    """

    def chat(self, tag, data):
        # Best to just ignore every chat message until initialization is done
        if not self.doneInit: return
       
        if not data["username"] in self.userlist: return

        user = self.userlist[data["username"]]
        msg = self._fixChat(data["msg"])

        self.chat_logger.info("%s: %r" , user.name, msg)
        if not user.name == self.name and self.doneInit:
            self.enqueueMsg(("(" + user.name + ") " + msg), st=False)
        
        # Only interpret regular messages as commands
        if not data["meta"].get("addClass"):
            self.chatCommand(user, msg)
        
        # Don't log messages from IRC, may result in a few unlogged messages
        if user.name != self.name or not msg or msg[0] != '(':
            self.sqlExecute(package(self.insertChat, msg=msg, username=user.name, 
                    userid=user.name, timestamp=None, protocol='CT', channel=self.room, flags=None))

        if user.rank >= 2 or user.name == self.name: return

        # REIMPLEMENT
        """
        user.msgs.append(time.time())
        span = user.msgs[-1] - user.msgs[0]
        if span < self.spam_interval * user.msgs.maxlen and len(user.msgs) == user.msgs.maxlen:
            self.logger.info("Attempted kick/ban of %s for spam", user.name)
            reason = "%s sent %d messages in %1.3f seconds" % (user.name, len(user.msgs), span)
            self.chatKick(user, reason)
        else:
            # Currently the only two blacklisted phrases are links to other Synchtube rooms.
            # Links to the current room or the Synchtube homepage aren't blocked.
            m = re.search(r"(synchtube\.com\/r\/|synchtu\.be\/|clickbank\.net|\/muppet\/images\/4\/48\/LookAtMeBook\.jpg|chaturbate\.com|mylazysundays\.com)(%s)?" % (self.room), msg, re.IGNORECASE)
            if m and not m.groups()[1]:
                self.logger.info("Attempted kick/ban of %s for blacklisted phrase", user.nick)
                reason = "%s sent a blacklisted message" % (user.name)
                self.chatKick(user, reason)
        """

    # REIMPLEMENT 
    """
    def leader(self, tag, data):
        self.logger.debug("Leader is %s", self.userlist[data])
        self.leader_sid = data
        self.tossing = False
        if self.leader_sid == self.sid and not self.wasKicked:
            toss = self.pendingToss
            self._leaderActions()
            if not toss:
                self.leading.set()
        else:
            self.leading.clear()
    """
    
    def channelOpts(self, tag, data):
        self.channelOpts = data

    # Command handlers for commands that users can type in Synchtube chat
    # All of them receive input in the form (command, user, data)
    # Where command is the typed command, user is the user who sent the message
    # and data is everything following the command in the chat message

    @hasPermission("SKIP")
    def skip(self, command, user, data):
        self.nextVideo()

    @hasPermission("SKIP")
    def accident(self, command, user, data):
        self.enqueueMsg("A terrible accident has befallen the currently playing video.")
        self.nextVideo()
    
    @hasPermission("SKIP")
    def setSkip(self, command, user, data):
        # Declare varriables 
        allow_voteskip = self.channelOpts["allow_voteskip"]
        voteskip_ratio = self.channelOpts["voteskip_ratio"]
        fail = False
        
        # Decode data
        if data=="on":
            allow_voteskip = True
        elif data=="off":
            allow_voteskip = False
        else:
            try:
                voteskip_ratio = float(data)
            except:
                try:
                    # Check if data is a percentage
                    data = (float(data.replace("%","")))/100
                    voteskip_ratio = round(data,3)
                except:
                    fail = True
        
        # Send options frame with only voteskip items changed
        if not fail:
            self.send("setOptions",{
                "allow_voteskip": allow_voteskip,
                "voteskip_ratio": voteskip_ratio,
                "afk_timeout": self.channelOpts["afk_timeout"],
                "pagetitle": self.channelOpts["pagetitle"],
                "maxlength": self.channelOpts["maxlength"],
                "externalcss": self.channelOpts["externalcss"],
                "externaljs": self.channelOpts["externaljs"],
                "chat_antiflood": self.channelOpts["chat_antiflood"],
                "show_public": self.channelOpts["show_public"],
                "enable_link_regex": self.channelOpts["enable_link_regex"]
                })
    
    # REIMPLEMENT
    """
    def autoSetSkip(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "AUTOSKIP")): return
        m = re.match("^((none)|(on)|(off)|([1-9][0-9]*)(%)?)( .*)?$", data, re.IGNORECASE)
        if m:
            self.autoSkip = m.groups()[0].lower()
            self.enqueueMsg("Automatic skip mode set to: %s" % (self.autoSkip))
            self._writePersistentSettings()
        else:
            self.enqueueMsg("Invalid skip setting.")
    """

    # REIMPLEMENT
    """
    def autoLeader(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "AUTOLEAD")): return
        d = data.lower()
        if d == "on":
            self.autoLead = True
            self.enqueueMsg("Automatic leading is enabled.")
        elif d == "off":
            self.autoLead = False
            self.enqueueMsg("Automatic leading is disabled.")
        else: return    
        self._writePersistentSettings()
    """
 
    # REIMPLEMENT
    """
    def setUnregSpamBan(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "UNREGSPAMBAN")): return
        d = data.lower()
        if d == "on":
            self.unregSpamBan = True
            self.enqueueMsg("Unregistered spammers will be banned for the first offense.")
        elif d == "off":
            self.unregSpamBan = False
            self.enqueueMsg("Unregistered spammers will have three chances.")
        else: return
        self._writePersistentSettings()
    """

    @hasPermission("MANAGE")
    def setPlaylistManagement(self, command, user, data):
        d = data.lower()
        if d == "on":
            self.managing = True
            self.enqueueMsg("Now actively managing the playlist.")
        elif d == "off":
            self.managing = False
            self.enqueueMsg("No longer actively managing the playlist.")
        else: return
        self._writePersistentSettings()

    # Note: Should use numeric ranks in addition to admin = 3+, mods = 2+, users 1+ (what exactly is 0?)
    # REIMPLEMENT
    """
    def setCommandLock(self, command, user, data):
        if not user.mod: return
        d = data.lower()
        if d == "registered":
            self.commandLock = "Registered"
            self.enqueueMsg("Unregistered users are unable to use commands.")
        elif d == "named":
            self.commandLock = "Named"
            self.enqueueMsg("Unnamed users are unable to use commands.")
        elif d == "mods":
            self.commandLock = "Mods"
            self.enqueueMsg("Only mods may use commands.")
        elif d == "off":
            self.commandLock = ""
            self.enqueueMsg("Unregistered users can use commands.")
        else: return
        self._writePersistentSettings()
    """
    
    @hasPermission("SHUFFLE")
    def shuffleList(self, command, user, data):
        self.send("shufflePlaylist")

    def help(self, command, user, data):
        self.enqueueMsg("I only do this out of pity. https://raw.github.com/Suwako/cyNaoko/master/commands.txt")
        #self.enqueueMsg("I refuse; you are beneath me.")

    # Creates a poll given an asterisk separated list of strings containing the title and at least two choices.
    @hasPermission("POLL")
    def poll(self, command, user, data):
        elements = data.split("*")
        # Filter out any empty or whitespace strings
        i = len(elements) - 1
        while i >= 0:
            if not elements[i].strip():
                elements.pop(i)
            i-=1
        if len(elements) < 3: return
        self.send("closePoll")
        self.send("newPoll", {"title": elements[0], "opts": elements[1:]})   

    @hasPermission("POLL")
    def endPoll(self, command, user, data):
        self.send("closePoll")

    @hasPermission("MUTE")
    def mute(self, command, user, data):
        self.muted = True

    @hasPermission("MUTE")
    def unmute(self, command, user, data):
        self.muted = False

    # REIMPLEMENT
    """
    def steal(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "LEAD")): return
        self.changeLeader(user.sid)
    
    def lead(self, command, user, data):
        if not (user.mod or user.sid == self.leader_sid or self.hasPermission(user, "LEAD")): return
        self.changeLeader(self.sid)

    def makeLeader(self, command, user, data):
        if not (user.mod or user.sid == self.leader_sid or self.hasPermission(user, "LEAD")): return
        args = data.split(' ', 1)
        target = self.getUserByNick(args[0])
        self.logger.info("Requested mod change to %s by %s", target, user)
        if not target: return
        self.changeLeader(target.sid)
    """

    def dice(self, command, user, data):
        if not data: return
        params = data.split()
        if len(params) < 2: return
        num = 0
        size = 0
        try:
            num = int(params[0])
            size = int(params[1])
            if num < 1 or size < 1 or num > 1000 or size > 1000: return # Limits
            sum = 0
            i = 0
            output = []
            while i < num:
                rand = random.randint(1, size)
                if i < 5:
                    output.append(str(rand))
                if i == 5:
                    output.append("...")
                sum = sum + rand
                i = i+1
            self.enqueueMsg("%dd%d: %d [%s]" % (num, size, sum, ",".join(output)))
        except (TypeError, ValueError) as e:
            self.logger.debug(e)

    # Bumps the last video added by the specificied user
    # If no name is provided it bumps the last video by the user who sent the command
    @hasPermission("BUMP")
    def bump(self, command, user, data):
        
        p = self.parseParameters(data, 0b10011)
     
        if not p: return
        name, num, title = p["base"], p["num"], p["title"]
        if not name == None:
            if name == "-unnamed":
                name = ""
            elif name == "-all":
                name = None
            else:
                name = self.filterString(name, True)[1]
                if not name: return
        else:
            if not title:
                name = user.name.lower()

        if not num:
            num = 1
        else:
            if num > 10 or num < 1: return
        
        bumpList = []
        i = len(self.vidlist)
        while i > self.state.current + 1 and len(bumpList) < num:
            i -= 1
            if self.state.current + 1 == i and len(bumpList) == 0: return
            v = self.vidlist[i]
            # Match names
            if not (None == name or v.queueby.lower() == name): continue
            # Titles 
            if title and v.title.lower().find(title) == -1: continue
            bumpList.append(i)    
        
        bumpList.reverse()
       
        self._bump(bumpList, self.state.current)
    
    def _bump(self, targets, after):
        bumpList = sorted(targets) 
        for t in bumpList:
            after += 1
            self.send("moveMedia", {"from": t, "to": after})

    # Cleans all the videos above the currently playing video
    @hasPermission("CLEAN")
    def cleanList(self, command, user, data):
        if self.state.current == 0: return
        self.logger.debug("Cleaning %d Videos", self.state.current)
        i = self.state.current - 1
        while i >= 0:
            self.deleteMedia(self.vidlist[i].uid)
            i -= 1
            
    # Clears any duplicate videos from the list
    @hasPermission("DUPLICATES")
    def cleanDuplicates(self, command, user, data):
        kill = []
        vids = set()
        i = 0
        while i < len(self.vidlist):
            key = "%s:%s" % (self.vidlist[i].vidinfo.id, self.vidlist[i].vidinfo.type)
            if key in vids:
                if not i == self.state.current:
                    kill.append(self.vidlist[i].uid)
            else:
                vids.add(key)
            i += 1
        if kill:
            self._cleanPlaylist(kill)
    
    # Deletes all the videos posted by the specified user,
    # with a specific pattern in their title (min 4 characters), or longer than a certain duration (min 20 minutes).
    # If multiple options are provided it will only remove videos that match all of the criteria.
    # Combines the previous removelong and purge functions together, with more functionality.
    # Mods can purge themselves, and Naoko can be purged only by a mod.
    @hasPermission("PURGE")
    def purge(self, command, user, data):
        p = self.parseParameters(data, 0b111)
        if not p: return
        name, duration, title = p["base"], p["dur"], p["title"]
        if not name == None:
            if name == "-unnamed":
                name = ""
            else:
                name = self.filterString(name, True)[1]
                if not name: return
        if name == None and not duration and not title: return
        if duration and duration < 20 * 60: return

        # Only mods can purge themselves or Naoko.
        # TODO -- limit purging of mods
        #if name and (name in self.modList and not (name == user.name.lower() or (user.mod and name == self.name.lower()))):
        #    return

        kill = []
        for i, v in enumerate(self.vidlist):
            vi = v.vidinfo
            # Only purge videos that match all criteria
            if not i == self.state.current and (name == None or v.queueby.lower() == name) and (not duration 
                    or vi.seconds >= duration) and (not title or vi.title.lower().find(title) != -1):
                kill.append(self.vidlist[i].uid)
        if kill:
            self._cleanPlaylist(kill)
    
    # targets is a list of integer video indices
    def _cleanPlaylist(self, targets):
        for x in targets:
            self.deleteMedia(x)
    
    # Deletes the last video matching the given criteria. Same parameters as purge, but if nothing is given it will default to the last video
    # posted by the user who calls it.
    @hasPermission("DELETE", False)
    def delete(self, command, user, data, permission=True):
        p = self.parseParameters(data, 0b10111)
        if not p: return
        name, duration, title, num = p["base"], p["dur"], p["title"], p["num"]
        if not name == None:
            if name == "-unnamed":
                name = ""
            elif name == "-all":
                name = None
            else:
                name = self.filterString(name, True)[1]
                if not name: return
        else:
            if not duration and not title:
                name = user.name.lower()

        if not num:
            num = 1
        else:
            if num > 10 or num < 1: return
        
        # Non-mods and non-hybrid mods can only delete their own videos
        if (not user.name.lower() == name or title or duration) and not (permission): return
        
        kill = []
        i = len(self.vidlist)
        while i > self.state.current + 1 and len(kill) < num:
            i -= 1
            v = self.vidlist[i]
            # Match names
            if None != name and v.queueby.lower() != name: continue
            # Titles 
            if title and v.title.lower().find(title) == -1: continue
            # Durations
            if duration and v.seconds < duration: continue
            kill.append(self.vidlist[i].uid)    

        if kill:
            self._cleanPlaylist(kill)

    # Adds random videos from the database
    @hasPermission("RANDOM", False)
    def addRandom(self, command, user, data, permission=True):
        # Limit to once every 5 seconds
        if user != self.selfUser and time.time() - self.last_random < 5: return
        self.last_random = time.time()
        
        if not (permission or len(self.vidlist) <= 10): return
        
        p = self.parseParameters(data, 0b1111)
        if not p: return
        num, duration, title, username = p["base"], p["dur"], p["title"], p["user"]
       
        if duration or title or username:
            if not permission: return

        if not duration:
            duration = 600

        try:
            num = int(num)
            if num > 20 or (not permission and num > 5) or num < 1: return
        except (TypeError, ValueError) as e:
            if num: return
            num = 5
        self.sqlExecute(package(self._addRandom, num, duration, title, username))

    @hasPermission("PLAYLISTS")
    def savePlaylist(self, command, user, data):
        valid, name = self.filterString(data, True, False)
        if not valid or not name:
            self.enqueueMsg("Invalid playlist name.")
            return
        self.apiExecute(package(self._fixPlaylist, name, [(v.vidinfo.type, v.vidinfo.id) for v in self.vidlist], user.name))

    # TODO -- similar permissions similar to addrandom
    @hasPermission("RANDOM")
    def loadPlaylist(self, command, user, data): 
        self.sqlExecute(package(self._loadPlaylist, data))

    @hasPermission("PLAYLISTS")
    def deletePlaylist(self, command, user, data):
        self.sqlExecute(package(self._deletePlaylist, data))

    # Blacklists the currently playing video so Naoko will ignore it
    def blacklist(self, command, user, data):
        # Rather arbitrary requirement of rank 5
        if user.rank < 5: return
        if self.state.current == -1: return
        target = self.vidlist[self.state.current].vidinfo
        self.flagVideo(target.type, target.id, 0b10)

    # Retrieve the latest bans for the specified user
    # REIMPLEMENT
    """
    def lastBans(self, command, user, data):
        params = data.split()
        target = user.nick
        num = 1
        if params and user.mod:
            target = params[0]
            if len(params) > 1 and command == "lastbans":
                try:
                    num = int(params[1])
                except (TypeError, ValueError) as e:
                    self.logger.debug(e)
        if num > 5 or num < 1: return
        self.sqlExecute(package(self._lastBans, target, num))
    """

    @hasPermission("ADD", False)
    def add(self, command, user, data, store=True, permission=True, wait=False):
        if self.room_info["locked"] and not permission:
            return
        nick = user.name
        site = False
        vid = False
        if data.find("youtube") != -1:
            x = data.find("v=")
            if x != -1:
                site = "yt"
                vid = data[x + 2:x + 13]
        elif data.find("youtu.be") != -1:
            x = data.find("be/")
            if x != -1:
                site = "yt"
                vid = data[x + 3:x + 14]
        elif data.find("vimeo") != -1:
            x = data.find(".com/")
            if x != -1:
                site = "vm"
                vid = data[x+5:x+13]
        elif data.find("dailymotion") != -1:
            x = data.find("video/")
            if x != -1:
                site = "dm"
                vid = data[x+6:x+12]
        elif data.find("blip.tv") != -1:
            site = "bt"
            vid = data[-7:]
            return # Cytube doesn't support blip.tv
        elif data.find("soundcloud") != -1:
            # Soundcloud URLs do not contain ids so additional steps are required.
            site = "sc"
            vid = data

        if site and (site == "sc" or self._checkVideoId(site, vid)):
            if wait:
                self.apiExecute(package(self._add, site, vid, nick, store))
            else:
                self.api_queue.appendleft(package(self._add, site, vid, nick, store))
                self.apiAction.set()

    # Add an individual video after verifying it
    def _add(self, site, vid, nick, store):
        url = vid
        if site == "sc":
            vid = self.apiclient.resolveSoundcloud(vid)
            if not vid: return
        data = self.apiclient.getVideoInfo(site, vid)
        if not data or data == "Unknown":
            return
        
        title, dur, valid = data
        if valid:
            self.logger.debug("Adding video %s %s %s %s", title, site, vid, dur)
            self.addExecute(package(self._addVideoToList, site, vid, url, False)) 
            if store and not dur == 0:
                self.sqlExecute(package(self.insertVideo, site, vid, title, dur, nick))
        else:
            self.flagVideo(site, vid, 0b1)
            self.logger.debug("Invalid video %s %s %s, unable to add.", title, site, vid)
    
    @hasPermission("LOCK")
    def lock(self, command, user, data):
        if self.room_info["locked"] == (command == "lock"): return
        self.send("togglePlaylistLock", {"locked": command == "lock"})

    def status(self, command, user, data):
        msg = "Status = ["
        if not self.muted:
            msg += "Not "
        msg += "Muted, Hybrid Mods "
        msg += "Enabled" if self.hybridModStatus else "Disabled"
        msg += ", Automatic Leading "
        msg += "Enabled" if self.autoLead else "Disabled"
        msg += ", Automatic Skip Mode: %s" % (self.autoSkip)
        msg += ", Unregistered Spammers: "
        msg += "One Chance" if self.unregSpamBan else "3 Chances"
        msg += ", Command Lock: "
        msg += "%s, " % (self.commandLock if self.commandLock else "Disabled")
        if not self.managing:
            msg += "Not "
        msg += "Managing Playlist]"
        self.sendChat(msg)
        if self.irc_nick and self.ircclient:
            self.ircclient.sendMsg(msg)
    
    # REIMPLEMENT
    """
    def hybridMods(self, command, user, data):
        if not user.mod: return
        d = data.lower()
        if d == "on":
            self.hybridModStatus = True
            self.enqueueMsg("Hybrid mods enabled.")
            self._writePersistentSettings()
        if d == "off":
            self.hybridModStatus = False
            self.enqueueMsg("Hybrid mods disabled.")
            self._writePersistentSettings()
        if not d:
            output = []
            for h, v in self.hybridModList.iteritems():
                if v:
                    output.append(h)
            self.enqueueMsg("Hybrid Mods: %s" % ",".join(output))
    """

    # Displays and possibly modifies the permissions of a hybrid mod.
    # REIMPLEMENT
    """
    def permissions(self, command, user, data):
        m = re.match(r"^((\+|\-)((ALL)|(.*)) )?(.*)$", data.upper())
        if not m: return

        g = m.groups()
        if g[5]:
            if not user.mod: return
            valid, name = self.filterString(g[5], True)
            if not valid:
                self.enqueueMsg("Invalid name.")
                return
        else:
            if g[0]:
                self.enqueueMsg("No name given.")
                return
            # Default to displaying the permissions for the current user.
            name = user.nick
        name = name.lower()
        p = 0
        if name in self.hybridModList:
            p = self.hybridModList[name]
        # Change permissions before displaying them.
        # Only change permissions if the calling user is a mod, a valid name was given, and flags were specified.
        # Also check whether a hybrid mod administrator is set.
        if user.mod and g[0] and g[5] and ((not self.hmod_admin) or self.hmod_admin.lower() == user.nick.lower()):
            mask = 0
            if g[3]:
                mask = ~0
            if g[4]:
                for ma, k in self.MASKS.itervalues():
                    if g[4].find(k) != -1:
                        mask |= ma
            if g[1] == '+':
                p |= mask
            else:
                p &= ~mask
            self.hybridModList[name] = p
            self._writePersistentSettings()

        output = []
        for ma, k in self.MASKS.itervalues():
            if p & ma:
                output.append(k)
        self.enqueueMsg("Permissions for %s: %s" % (name, "".join(output)))
    """

    @hasPermission("RESTART")
    def restart(self, command, user, data):
        self.close()

    def choose(self, command, user, data):
        if not data: return
        self.enqueueMsg("[Choose: %s] %s" % (data, random.choice(data.split())))

    def permute(self, command, user, data):
        if not data: return
        choices = data.split()
        random.shuffle(choices)
        self.enqueueMsg("[Permute] %s" % (" ".join(choices)))

    def steak(self, command, user, data):
        self.enqueueMsg("There is no steak.")

    def ask(self, command, user, data):
        if not data: return
        self.enqueueMsg("[Ask: %s] %s" % (data, random.choice(["Yes", "No"])))

    def eightBall(self, command, user, data):
        if not data: return
        self.enqueueMsg("[8ball: %s] %s" % (data, random.choice(eight_choices)))

    def quote(self, command, user, data):
        # Limit to once every 5 seconds
        if time.time() - self.last_quote < 5: return
        self.last_quote = time.time()
        
        self.sqlExecute(package(self._quote, data))
    
    def _quote(self, name):
        row = self.dbclient.getQuote(name, [(self.name, "ST"), (self.irc_nick, "IRC"), (self.name, "CT")])
        if row:
            self.enqueueMsg("[%s %s-%s] %s" % (row[0], row[3],  datetime.fromtimestamp(row[2] / 1000).isoformat(' '), row[1])) 

    # Kick a single user by their name.
    # Two special arguments -unnamed and -unregistered.
    # Those commands kick all unnammed and unregistered users. 
    @hasPermission("KICK")
    def kick(self, command, user, data):
        args = data.split(' ', 1)

        # TODO -- handle guest users
        """
        if args[0].lower() == "-unregistered":
            if not user.mod: return
            kicks = []
            for u in self.userlist:
                # Synchtube doesn't properly set user.auth in some cases.
                # A more reliable method without false positives is user.uid.
                if self.userlist[u].uid == None:
                    kicks.append(u)
            self.logger.info("Kicking %d unregistered users requested by %s", len(kicks), user.nick)
            self.asLeader(package(self._kickList, kicks))
            return
        """

        target = self.getUserByNick(args[0])
        if not target or target.rank > user.rank: return
        self.logger.info("Kick Target %s Requestor %s", target.name, user.name)
        if len(args) > 1:
            self._kickUser(target.name, args[1])
        else:
            self._kickUser(target.name)

    def _kickList(self, kicks):
        for k in kicks:
            self._kickUser(k, sendMessage=False)

    # REIMPLEMENT
    """
    def ban(self, command, user, data):
        if not data or not (user.mod or self.hasPermission(user, "BAN")): return
        args = data.split(' ', 1)
        target = self.getUserByNick(args[0])
        if not target or target.mod: return
        self.logger.info("Ban Target %s Requestor %s", target, user)
        if len(args) > 1:
            self.asLeader(package(self._banUser, target.sid, args[1], modName=user.nick))
        else:
            self.asLeader(package(self._banUser, target.sid, modName=user.nick))
    """

    # REIMPLEMENT
    """
    def unban(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "BAN")): return
        target = data
        if not target: return
        self.unbanTarget = target
        self.getBanlist(command, user, data)
    """

    # REIMPLEMENT
    """
    def getBanlist(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "BAN")): return
        if data.lower() == "-v":
            self.verboseBanlist = True
        # If she is trying to unban a user defer the current ban.
        self.asLeader(package(self.send, "banlist"), deferred=(self.DEFERRED_MASKS["UNBAN"] if self.unbanTarget else 0))
    """

    def cleverbot(self, command, user, data):
        if not hasattr(self.cbclient, "cleverbot"): return
        text = data
        if text:
            self.apiExecute(package(self._cleverbot, text))

    def _cleverbot(self, text):
        self.enqueueMsg(self.cbclient.cleverbot(text))

    def eval(self, command, user, data):
        self.enqueueMsg("You're not the boss of me.")

    # Translate a given string.
    # Defaults to translating to English and detecting the source language.
    # If the string starts with [src->dst], [src>dst], or [dst] where src and dst
    # are ISO two letter language code it will attempt to translate using those codes.
    def translate(self, command, user, data):
        m = re.match("^(\[(([a-zA-Z]{2})|([a-zA-Z]{2})-?>([a-zA-Z]{2}))\] ?)?(.+)$", data)
        if not m: return
        g = m.groups()
        src = g[3] or None
        dst = g[2] or g[4] or "en"
        self.apiExecute(package(self._translate, g[5], src, dst))

    def _translate(self, text, src, dst):
        out = self.apiclient.translate(text, src, dst)
        if out:
            if out != -1:
                self.enqueueMsg("[%s] %s" % (dst.lower(), out))
        else:
            self.enqueueMsg("Translate query failed.")
    
    # Queries the Wolfram Alpha API with the provided string.
    def wolfram(self, command, user, data):
        query = data
        if not query: return
        self.apiExecute(package(self._wolfram, query))
    
    def _wolfram(self, query):
        out = self.apiclient.wolfram(query)
        if out:
            if out != -1:
                self.enqueueMsg("[%s] %s" % (query, out))
        else:
            self.enqueueMsg("Wolfram Alpha query failed.")
    
    # Queries the anagram bot with the provided string.
    def anagram(self, command, user, data):
        text = re.sub(r"[^a-zA-Z]", "", data)
        if not text: return
        if len(text) < 7:
            self.enqueueMsg("Message is too short.")
            return
        if len(text) > 30:
            self.enqueueMsg("Message is too long.")
            return
        self.apiExecute(package(self._anagram, data))
    
    def _anagram(self, text):
        out = self.apiclient.anagram(text)
        if out:
            if out != -1:
                self.enqueueMsg("%s -> %s" % (text, out))
            else:
                self.enqueueMsg("Message is too short.")
        else:
            self.enqueueMsg("Anagram failed.")
   
    # Telnet commands
    # Only callable through telnet
    
    # Executes a command as Naoko. Respects all the limits a user with her rank is subject to.
    def command(self, msg):
        msg = '$' + msg if msg [0] != '$' else msg 
        self.stExecute(package(self.chatCommand, self.selfUser, msg)) 

    # Kicks everyone in the channel except Naoko.
    def clearRoom(self, kickSelf=False):
        kill = [u for u in self.userlist.iterkeys() if u != self.sid]
        if kickSelf:
            kill.append(self.sid)
        self.stExecute(package(self.asLeader, package(self._kickList, kill)))

    # Imports all the videos in <filename>.lst
    # An lst file is simply a plain text file containing a list of videos, one per line.
    def importFile(self, filename, name=False):
        if name:
            name = self.filterString(name, True, False)[1]
        f = False
        try:
            f = file("%s.lst" % (filename), "r")
            user = CytubeUser(*self.selfUser)
            user = user._replace(name=str(name))
            for line in f:
                self.add("add", user, line, name!=False, wait=True)
        except Exception as e:
            print e
            return
        finally:
            if f != False:
                f.close()

    # Parses the parameters common to several functions.
    # All returned values are lower case
    # Returns a lone unfiltered string, often a name or number, a title specified by -title and quotes, and
    # a duration in seconds. The title must be at least 3 characters.
    # A mask is passed to determine which options are looked for.
    # base      : 1
    # -title    : 1 << 1
    # -dur      : 1 << 2
    # -user     : 1 << 3
    # -n        : 1 << 4
    def parseParameters(self, data, mask):
        text = data.lower().split("\"")
        
        params = re.split(" +", text[0])
        if len(text) == 3:
            if not text[1] or len(text[1]) < 3: return
            params.append(-1)
            params.extend(re.split(" +", text[2]))
        elif len(text) != 1: return
        params = deque(params) 
        
        base = None
        duration = None
        title = None
        user = None
        num = None
        # Could be done with a huge regexp but this is probably cleaner and easier to maintain.
        while params:
            t = params.popleft()
            if not t: continue
            if t == -1: return
            if t == "-title" and mask & (1 << 1):
                if title or not params or params.popleft(): return 
                if not params or not params.popleft() == -1 or len(text) < 3: return
                title = text[1]
            elif t == "-dur" and mask & (1 << 2):
                if duration or not params: return
                duration = params.popleft()
                if not duration or duration == -1: return

                m = re.match("^(([0-9]*):)?([0-9]*)$", duration)
                if not m: return
                length = 0
                g = m.groups()
                if g[1]:
                    length = int(g[1]) * 60
                if g[2]:
                    length += int(g[2])
        
                duration = length * 60
            elif t == "-user" and mask & (1 << 3):
                if user or not params: return
                user = params.popleft()
                if not user or user == -1: return
            elif t == "-n" and mask & (1 << 4):
                if num or not params: return
                try:
                    num = int(params.popleft())
                except Exception:
                    return
            else:
                if not t: continue
                if not base == None or not mask & 1: return
                base = t
        return {"base"  : base,
                "dur"   : duration,
                "title" : title,
                "user"  : user,
                "num"   : num}
    # Two functions that search the lists in an efficient manner

    def getUserByNick(self, nick):
        name = self.filterString(nick, True)[1].lower()
        try: return (u for u in self.userlist.itervalues() if u.name.lower() == name).next()
        except StopIteration: return None

    def getVideoIndexById(self, vid):
        try: return (idx for idx, ele in enumerate(self.vidlist) if ele.uid == vid).next()
        except StopIteration: return -1
    
    # Updates the required skip level
    # REIMPLEMENT
    """
    def updateSkipLevel(self):
        if not self.doneInit: return
        if not self.room_info["skip?"] or not "vote_settings" in self.room_info:
            self.skipLevel = False
            return
        
        if self.room_info["vote_settings"]["settings"] == "percent":
            self.skipLevel = int(math.ceil(self.room_info["vote_settings"]["num"] * len(self.userlist) / 100.0))
        else:
            self.skipLevel = self.room_info["vote_settings"]["num"]
    """

    # logs the user count to the database
    def _storeUserCount(self, count):
        storeTime = time.time()
        if storeTime - self.userCountTime > USER_COUNT_THROTTLE:
            self.userCountTime = storeTime
            self.sqlExecute(package(self.insertUserCount, count, storeTime))
   
    # REIMPLEMENT
    """
    def checkSkip(self):
        if "num_votes" in self.room_info and self.room_info["num_votes"]["votes"] >= self.skipLevel:
            self.skips.append(time.time())
            if len(self.skips) == self.skips.maxlen and self.skips[-1] - self.skips[0] <= self.skips.maxlen * self.skip_interval: 
                self.setSkip("",  self.selfUser, "off")
    """

    # Returns whether or not a video id could possibly be valid
    # Guards against possible attacks and annoyances
    def checkVideoId(self, site, vid):
        if not site or not vid: return False

        if type(vid) is not str and type(vid) is not unicode:
            vid = str(vid)

        return self._checkVideoId(site, vid)

    def _checkVideoId(self, site, vid):

        if site == "yt":
            return re.match("^[a-zA-Z0-9\-_]+$", vid)
        elif site == "dm":
            return re.match("^[a-zA-A0-9]+$", vid)
        elif site == "vm" or site == "sc" or site == "bt":
            return re.match("^[0-9]+$", vid)
        else:
            return False

    # REIMPLEMENT
    """
    def takeLeader(self):
        if self.wasKicked:
            self.send("takeleader", self.sid)
            self.send("turnon_tv")
            time.sleep(0.0001)
            self.send("turnon_tv")
            return
        if self.sid == self.leader_sid and not self.tossing:
            self._leaderActions()
            return
        if self.tossing:
            self.unToss()
        elif self.room_info["tv?"]:
            self.send("turnoff_tv")
        else:
            self.send("takeleader", self.sid)
    """

    # REIMPLEMENT
    """
    def changeLeader(self, sid):
        if sid == self.leader_sid: return
        if sid == self.sid:
            self.takeLeader()
            return
        self.pendingToss = True
        self.tossLeader = package(self._tossLeader, sid)
        self.takeLeader()
    """

    # Filters a string, removing invalid characters
    # Used to sanitize nicks or video titles for printing
    # Returns a boolean describing whether invalid characters were found
    # As well as the filtered string
    def filterString(self, input, isNick=False, replace=True):
        if input == None: return (False, "")
        output = []
        value = input
        if type(value) is not str and type(value) is not unicode:
            value = str(value)
        if type(value) is not unicode:
            try:
                value = value.decode('utf-8')
            except UnicodeDecodeError:
                value = value.decode('iso-8859-15')
        valid = True
        for c in value:
            o = ord(c)
            # Locale independent ascii alphanumeric check
            if isNick and ((o >= 48 and o <= 57) or (o >= 97 and o <= 122) or (o >= 65 and o <= 90) or o == 95):
                output.append(c)
                continue
            validChar = o > 31 and o != 127 and not (o >= 0xd800 and o <= 0xdfff) and o <= 0xffff
            if (not isNick) and validChar:
                output.append(c)
                continue
            valid = False
            if replace:
                output.append(unichr(0xfffd))
        return (valid, "".join(output))

    # Undoes the changes cytube applies to chat messages
    def _fixChat(self, input):
        if input == None: return ""
        value = input
        if type(value) is not str and type(value) is not unicode:
            value = str(value)
        if type(value) is not unicode:
            try:
                value = value.decode('utf-8')
            except UnicodeDecodeError:
                value = value.decode('iso-8859-15')
        
        output = value

        # Replace html tags with whatever they replaced
        output = re.sub(r"</?strong>", "*", output)
        output = re.sub(r"</?em>", "_", output)
        output = re.sub(r"</?code>", "`", output)
        output = re.sub(r"</?s>", "~~", output)


        # Remove any other html tags that were added
        output = output.split("<")
        for i, val in enumerate(output):
            if ">" in val:
                output[i] = val.split(">", 1)[1]
        output = "".join(output)

        # Unescape &gt; and &lt;
        output = output.replace("&gt;", ">")
        output = output.replace("&lt;", "<")
        output = output.replace("&quot;", "\"")
        output = output.replace("&amp;", "&")

        return output

    # The following private API methods are fairly low level and work with
    # synchtube sid's (session ids) or raw data arrays. They will usually
    # Fire off a synchtube message without any validation. Higher-level
    # public API methods should be built on top of them.

    # Add the user described by u_dict
    def _addUser(self, u_dict, isSelf=False):
        userinfo = u_dict.copy()
        #userinfo['nick'] = self.filterString(userinfo['nick'], True)[1]
        userinfo['msgs'] = deque(maxlen=3)
        #userinfo['nickChanges'] = 0
        userinfo["leader"] = False
        assert set(userinfo.keys()) == set(CytubeUser._fields), "User information has changed formats. Tell Desuwa."
        user = CytubeUser(**userinfo)
        self.userlist[user.name] = user
        if isSelf:
            self.selfUser = user
            
            # Avoid issues with empty rooms
            if not self.doneInit:
                self._writeIOUrl(self.io_url)
                if self.managing and self.state.state == self._STATE_UNKNOWN:
                    self.stExecute(package(self.addRandom, "addrandom", self.selfUser, ""))
                self.doneInit = True

    # Write the current status of the hybrid mods and a short warning about editing the resulting file.
    def _writePersistentSettings(self):
        f = None
        self.logger.debug("Writing persistent settings to file.")
        try:
            f = open("persistentsettings", "wb")
            f.write("# This is a file generated by Naoko.\n# Do not edit it manually unless you know what you are doing.\n")
            f.write("2\n") # Version number, increment whenever something is added to this function
            f.write("ON\n" if self.autoLead else "OFF\n")
            f.write("%s\n" % (self.autoSkip))
            f.write("ON\n" if self.unregSpamBan else "OFF\n")
            f.write("%s\n" % (self.commandLock))
            f.write("ON\n" if self.managing else "OFF\n")
            f.write("ON\n" if self.hybridModStatus else "OFF\n")
            for h, v in self.hybridModList.iteritems():
                if v:
                    f.write("%s %d\n" % (h, v))              
        except Exception as e:
            self.logger.debug("Failed to write hybrid mods to file.")
            self.logger.debug(e)
        finally:
            if f:
                f.close()
    
    # Write the current status of the hybrid mods and a short warning about editing the resulting file.
    def _writeIOUrl(self, io_url):
        f = None
        self.logger.debug("Writing io_url to file.")
        try:
            f = open("iourlcache", "wb")
            f.write(io_url + "\n")
        except Exception as e:
            self.logger.debug("Failed to write io_url.")
            self.logger.debug(e)
        finally:
            if f:
                f.close()

    # Marks a video with the specified flags.
    # 1 << 0    : Invalid video, may become valid in the future. Reset upon successful manual add.
    # 1 << 1    : Manually blacklisted video.
    def flagVideo(self, site, vid, flags):
        self.sqlExecute(package(self._flagVideo, site, vid, flags))

    # Wrapper
    def _flagVideo(self, *args, **kwargs):
        self.dbclient.flagVideo(*args, **kwargs)
        
    # Remove flags from a video.
    def unflagVideo(self, site, vid, flags):
        self.sqlExecute(package(self._unflagVideo, site, vid, flags))

    # Wrapper
    def _unflagVideo(self, *args, **kwargs):
        self.dbclient.unflagVideo(*args, **kwargs)

    # Wrapper for dbclient.insertVideo
    def insertVideo(self, *args, **kwargs):
        self.dbclient.insertVideo(*args, **kwargs)
    
    # Wrapper for dbclient.insertUserCount
    def insertUserCount(self, *args, **kwargs):
        self.dbclient.insertUserCount(*args, **kwargs)
    
    # Wrapper for dbclient.insertChat
    def insertChat(self, *args, **kwargs):
        self.dbclient.insertChat(*args, **kwargs)

    # Checks to see if the current video isn't invalid, blocked, or removed.
    # Also updates the duration if necessary to prevent certain types of annoying attacks on the room.
    def _checkVideo(self, site, vid):
        url = vid
        if site == "sc":
            vid = self.apiclient.resolveSoundcloud(vid)
            if not vid: return

        if site == "vi": site = "vm"

        if not self.checkVideoId(site, vid):
            self.invalidVideo("Invalid video ID.")
            return

        data = self.apiclient.getVideoInfo(site, vid)
        if data:
            if data != "Unknown":
                title, dur, embed = data
                if not embed:
                    self.logger.debug("Embedding disabled.")
                    self.logger.debug(data)
                    self.invalidVideo("Embedding disabled.")
                    return
                # When someone has manually added a video with an incorrect duration.
                elif self.state.dur != dur:
                    if site == "yt" and dur == 0:
                        # Live Youtube stream
                        self.logger.debug("Live Youtube stream detected.")
                        self.state.dur = DEFAULT_WAIT
                    else:
                        self.logger.debug("Duration mismatch: %d expected, %.3f actual." % (self.state.dur, dur))
                        if abs(self.state.dur - dur) >= 1:
                            self.logger.debug("Large mismatch detected, clearing Cytube cache.")
                            self.send("uncache", {"id" : vid})
                            self.invalidVideo("Duration Mismatch")
                        self.state.dur = dur
                    #self.playerAction.set()
            return
        self.invalidVideo("Invalid video.")

    # Validates a video before inserting it into the database.
    # Will correct invalid durations and titles for videos.
    # This makes SQL inserts dependent on the external API.
    def _validateAddVideo(self, v, sql, idx):
        # Don't insert videos added by Naoko.
        # We can also assume any video added by Naoko has passed her own checks
        if v.queueby == self.name: return
       
        vi = v.vidinfo

        valid = True
        data = None
        v_id = self._fixVideoID(v.vidinfo)
        if v_id == None:
            valid = False
        if v_id == False:
            valid = "Unknown"

        if valid and not valid == "Unknown":
            data = self.apiclient.getVideoInfo(vi.type, v_id)
            if data == "Unknown":
                # Do not store the video if it is invalid or from an unknown website.
                # Trust that it is a video that will play.
                valid = "Unknown"
            elif data:
                title, dur, valid = data
            else:
                # Shouldn't be possible with Cytube but better to be safe
                valid = False
        
        # This shouldn't ever happen
        if not valid:
            # The video is invalid don't insert it.
            self.logger.debug("Invalid video, skipping SQL insert.")
            self.logger.debug(data)
            # Flag the video as invalid.
            self.flagVideo(vi.type, v_id, 1)
            # Go even further and remove it from the playlist completely
            self.enqueueMsg("Invalid video removed.")
            self.deleteMedia(v.uid)
            return
        # Curl is missing or the duration is 0, don't insert it but leave it on the playlist
        if valid == "Unknown" or dur == 0: return

        if sql:
            # Insert the video using the retrieved title and duration.
            # Trust the external APIs over the Synchtube playlist.
            self.sqlExecute(package(self.insertVideo, vi.type, v_id, title, dur, v.queueby))
        else: 
            # Flag it as valid even if we don't add it
            self.unflagVideo(vi.type, v_id, 1)

    def _fixVideoID(self, vi):
        v_id = vi.id
        if vi.type == "sc":
            # Soundcloud is special
            v_id = self.apiclient.resolveSoundcloud(v_id)
        if vi.type == "dm":
            v_id = v_id[:6]
        return v_id   

    # REIMPLEMENT
    """
    def _lastBans(self, nick, num):
        rows = self.dbclient.getLastBans(nick, num)
        if not nick == "-all":
            if not rows:
                self.enqueueMsg("No recorded bans for %s" % nick)
                return
            if num > 1:
                self.enqueueMsg("Last %d bans for user %s:" % (num, nick))
            else:
                self.enqueueMsg("Last ban for user %s:" % (nick))
            for r in rows:
                self.enqueueMsg("%s by %s - %s" % (datetime.fromtimestamp(r[0] / 1000).isoformat(' '), r[2], r[1]))
        else:
            if not rows:
                self.enqueueMsg("No recorded bans")
                return
            if num > 1:
                self.enqueueMsg("Last %d bans:" % (num,))
            else:
                self.enqueueMsg("Last ban:")
            for r in rows:
                self.enqueueMsg("%s - %s by %s - %s" % (r[3], datetime.fromtimestamp(r[0] / 1000).isoformat(' '), r[2], r[1]))
    """

    def _fixPlaylist(self, name, vids, nick):
        cleanVids = []
        for site, vid in vids:
            if site == 'sc':
                vid = self.apiclient.resolveSoundcloud(v_id)
            cleanVids.append((site, vid)) 
        self.sqlExecute(package(self._savePlaylist, name, cleanVids, nick))
    
    def _savePlaylist(self, name, vids, nick):
        self.logger.debug("Storing playlist %s, length %d, by %s" % (name, len(vids), nick))
        self.dbclient.insertPlaylist(name, vids, nick)
        self.enqueueMsg("Playlist saved.")

    def _deletePlaylist(self, name):
        #self.logger.debug("Storing playlist %s, length %d, by %s" % (name, len(vids), nick))
        self.dbclient.deletePlaylist(name)
 
    def _loadPlaylist(self, name):
        self.logger.debug("Retrieving playlist %s", name)
        vids = self.dbclient.getPlaylist(name, ['type', 'id'], blockedSites=["bt"])
        self.logger.debug("Retrieved %s", vids)
        self._addVideosToList(vids)

    def _addRandom(self, num, duration, title, user):
        self.logger.debug("Adding %d randomly selected videos, with title like %s, and duration no more than %s seconds, posted by user %s", num, title, duration, user)
        vids = self.dbclient.getVideos(num, ['type', 'id'], ('RANDOM()',), duration, title, user, blockedSites=["bt", "sc"]) # Cytube doesn't support Blip.tv, and no one likes Soundcloud anyway
        # TODO -- Make blockedSites something the user can specify
        self.logger.debug("Retrieved %s", vids)
        self._addVideosToList(vids)
        #self.stExecute(package(self.asLeader, package(self._addVideosToList, list(vids))))

    def _addVideosToList(self, vids):
        for v in vids:
            self.add_queue.append(package(self._addVideoToList, *v))
            #self.send("am", [v[0], v[1], self.filterString(v[2])[1],"http://i.ytimg.com/vi/%s/default.jpg" % (v[1]), v[3]/1000.0])
        self.addAction.set()

    def _addVideoToList(self, site, vid, url=None, check=True):
        if site == "sc" and not url:
            self.api_queue.appendleft(package(self._addSoundcloudToList, site, vid, url))
            self.apiAction.set()
            return
        
        packet = {"id"  : vid,
                "type"  : site,
                "pos"   : "end"}
        
        if site == "vm":
            packet["type"] = "vi"
        if site == "sc":
            packet["type"] = url

        self.send("queue", packet)
        if check:
            self.apiExecute(package(self._checkAddedVideo, site, vid))
    
    def _addSoundcloudToList(self, site, vid, url=None):
        packet = {"id"  : vid,
                "type"  : site,
                "pos"   : "end"}
        
        if url:
            packet["id"] = url
        else:
            packet["id"] = self.apiclient.getSoundcloudURL(vid)
        
        self.addExecute(package(self.send, "queue", packet))
        self.apiExecute(package(self._checkAddedVideo, site, vid))

    def _checkAddedVideo(self, site, vid):
        data = self.apiclient.getVideoInfo(site, vid)
        if data == "Unknown": return
        if not data or not data[2]:
           self.flagVideo(site, vid, 1)
        
    # Add the video described by v_dict
    def _addVideo(self, v_dict, idx, sql=True):
        if self.stthread != threading.currentThread():
            raise Exception("_addVideo should not be called outside the Synchtube thread")

        vi = v_dict["media"].copy()
        v = v_dict.copy()
        del v["media"] 

        # currentTime seems to be useless to keep around since it is not available with "queue" messages
        if "currentTime" in v:
            del v["currentTime"]
        # duration is for display purposes only and can be safely ignored
        if "duration" in vi:
            del vi["duration"]
        
        # Ignore paused for now, it'll probably go away
        if "paused" in v:
            del v["paused"]
    
        # More effort to switch to "vi" than it is to just ignore it
        # Will make maitaining two versions or porting changes back to Naoko normal
        if vi["type"] == "vi":
            vi["type"] = "vm"

        if "temp" not in v:
            v["temp"] = False

        if "queueby" not in v:
            v["queueby"] = ""

        assert set(vi.keys()) >= set(CytubeVidInfo._fields), "Video information has changed formats. Unable to continue. Tell Desuwa."
        assert set(v.keys()) >= set(CytubeVideo._fields) - set(["vidinfo"]), "Video information has changed formats. Unable to continue. Tell Desuwa."

        if not set(v.keys()) == set(CytubeVideo._fields) - set(["vidinfo"]):
            self.logger.warn("Video information has changed formats. Tell Desuwa. Ignoring new fields.")
            
            self.logger.debug ("New fields: %s" %(set(v.keys()) - set(CytubeVideo._fields)))
            for key in set(v.keys()) - set(CytubeVideo._fields):
                del v[key]
        
        if not set(vi.keys()) == set(CytubeVidInfo._fields):
            self.logger.warn("Video information has changed formats. Tell Desuwa. Ignoring new fields.")
            
            self.logger.debug ("New fields: %s" %(set(vi.keys()) - set(CytubeVidInfo._fields)))
            for key in set(vi.keys()) - set(CytubeVidInfo._fields):
                del vi[key]
       
        vidinfo = CytubeVidInfo(**vi)
        v ["vidinfo"] = vidinfo 
        vid = CytubeVideo(**v)
        self.vidLock.acquire()
        self.vidlist.insert(idx, vid)
        self.vidLock.release()
        if self.state.current == -1 and vid.uid == self.state.Id:
            self.state.current = idx

        self.apiExecute(package(self._validateAddVideo, vid, sql, idx))
        
    def _removeVideo(self, uid):
        if self.stthread != threading.currentThread():
            raise Exception("_removeVideo should not be called outside the Synchtube thread")
        idx = self.getVideoIndexById(uid)
        if idx == -1: return
        self.vidLock.acquire()
        self.vidlist.pop(idx)
        self.vidLock.release()
        if idx <= self.state.current:
            if idx == self.state.current:
                self.state.time = -11 # Set the time to negative so it doesn't delete another video when the current video is deleted
            self.state.current -= 1

    def _moveVideo(self, vid, after):
        if self.stthread != threading.currentThread():
            raise Exception("_moveVideo should not be called outside the Synchtube thread")
        src = self.getVideoIndexById(vid)
        self.vidLock.acquire()
        video = self.vidlist.pop(src)

        if after == "prepend":
            dest = 0
        else:
            dest = self.getVideoIndexById(after) + 1
            
        self.vidlist.insert(dest, video)
        
        # Cytube doesn't send a playlistUpdateIdx message after moves
        if src == self.state.current:
            self.state.current = dest
        else:
            if src < self.state.current:
                self.state.current -= 1
            if dest <= self.state.current:
                self.state.current += 1
        
        self.logger.debug("Inserted %s after %s", video, self.vidlist[dest - 1])
        self.vidLock.release()

    # Kick user using their name (case-sensitive)
    def _kickUser(self, name, reason="Requested", sendMessage=True):
        if sendMessage:
            self.enqueueMsg("Kicked %s: (%s)" % (name, reason))
        self.sendChat("/kick %s %s" % (name, reason))

    # REIMPLEMENT
    """
    def _banUser(self, sid, reason="Requested", sendMessage=True, modName=None):
        if not sid in self.userlist: return
        if not modName:
            modName = self.name
        if sendMessage:
            self.enqueueMsg("Banned %s: (%s)" % (self.userlist[sid].nick, reason))
        self.send("ban", sid)
        self.sqlExecute(package(self.dbclient.insertBan, self.userlist[sid], reason, time.time(), modName))
    """

    # Give leader to another user using their sid(session id)
    # This command does not ensure the client is currently leader before executing
    # REIMPLEMENT
    """
    def _tossLeader(self, sid):
        # Short sleep to give Synchtube some time to react
        time.sleep(0.05)
        self.pendingToss = False
        self.notGivingBack = False
        self.tossing = True
        self.unToss = package(self.send, "takeleader", self.sid)
        self.send("toss", sid)
    """

    def _getConfig(self):
        config = ConfigParser.RawConfigParser()
        config.read("naoko.conf")
        self.room = config.get("naoko", "room")
        self.room_pw = config.get("naoko", "room_pw")
        self.name = config.get("naoko", "nick")
        self.pw   = config.get("naoko", "pass")
        self.domain = config.get("naoko", "domain")
        self.default_io_url = config.get("naoko", "default_io_url")
        self.repl_port = config.get("naoko", "repl_port")
        self.hmod_admin = config.get("naoko", "hmod_admin").lower()
        self.spam_interval = float(config.get("naoko", "spam_interval"))
        self.skip_interval = float(config.get("naoko", "skip_interval"))
        self.server = config.get("naoko", "irc_server")
        self.channel = config.get("naoko", "irc_channel")
        self.irc_nick = config.get("naoko", "irc_nick")
        self.ircpw = config.get("naoko", "irc_pass")
        self.dbfile = config.get("naoko", "db_file")
        self.apikeys = Object()
        self.apikeys.mst_id = config.get("naoko", "mst_client_id")
        self.apikeys.mst_secret = config.get("naoko", "mst_client_secret")
        self.apikeys.sc_id = config.get("naoko", "sc_client_id")
        self.apikeys.wf_id = config.get("naoko", "wolfram_id")
        self.apikeys.yt_id = config.get("naoko", "youtube_id")
        self.webserver_mode = config.get("naoko", "webserver_mode")
        self.webserver_host = config.get("naoko", "webserver_host")
        self.webserver_port = config.get("naoko", "webserver_port")
        self.webserver_protocol = config.get("naoko", "webserver_protocol")
        self.webserver_url = config.get("naoko", "webserver_url")
        self.mumble_host = config.get("naoko", "mumble_host")
        self.mumble_port = int(config.get("naoko", "mumble_port"))
        self.mumble_name = config.get("naoko", "mumble_name")
        self.mumble_pw = config.get("naoko", "mumble_pass")
        self.mumble_channel = config.get("naoko", "mumble_channel") 
