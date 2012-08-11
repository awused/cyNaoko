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
import sched, time
import socket
import struct
import threading
import urllib, urlparse, httplib
import re
from urllib2 import Request, urlopen
from collections import namedtuple, deque
import ConfigParser
import random
from datetime import datetime
import code

from lib.repl import Repl
from settings import *
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

# Package arguments for later use.
# Due to the way python handles scopes this needs to be used to avoid race conditions.
def package(fn, *args, **kwargs):
    def action():
        fn(*args, **kwargs)
    return action

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
SynchtubeUser = namedtuple('SynchtubeUser',
                           ['sid', 'nick', 'uid', 'auth', 'ava', 'lead', 'mod', 'karma', 'msgs', 'nickChanges'])

SynchtubeVidInfo = namedtuple('SynchtubeVidInfo',
                            ['site', 'vid', 'title', 'thumb', 'dur'])

SynchtubeVideo = namedtuple('SynchtubeVideo',
                              ['vidinfo', 'v_sid', 'uid', 'nick'])

IRCUser = namedtuple('IRCUser', ["nick", "mod"])

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
    _ST_IP = "173.255.204.78"
    _HEADERS = {'User-Agent' : 'NaokoBot',
                'Accept' : 'text/html,application/xhtml+xml,application/xml;',
                'Host' : 'www.synchtube.com',
                'Connection' : 'keep-alive',
                'Origin' : 'http://www.synchtube.com',
                'Referer' : 'http://www.synchtube.com'}

    # Bitmasks for hybrid mods.
    MASKS = {
        "LEAD"          : (1, 'O'),         # O - Both the steal and mod command.
        "BUMP"          : ((1 << 1), 'B'),  # B - Bumping videos.
        "DELETE"        : ((1 << 2), 'D'),  # D - Deleting videos.
        "KICK"          : ((1 << 3), 'K'),  # K - Kicking users.
        "BAN"           : ((1 << 4), 'Q'),  # Q - Banning and unbanning users, as well as viewing the banlist.
        "RESTART"       : ((1 << 5), 'R'),  # R - Restarting Naoko.
        "CLEAN"         : ((1 << 6), 'C'),  # C - The clean command.
        "SKIP"          : ((1 << 7), 'S'),  # S - Skipping videos.
        "LOCK"          : ((1 << 8), 'L'),  # L - Lock and unlock the playlist.
        "RANDOM"        : ((1 << 9), 'A'),  # A - Addrandom with more than 5 videos.
        "SETSKIP"       : ((1 << 11), 'E'), # E - Setskip.
        "DUPLICATES"    : ((1 << 12), 'T'), # T - Remove duplicate videos.
        "MUTE"          : ((1 << 13), 'M'), # M - Mute or unmute Naoko.
        "PURGE"         : ((1 << 14), 'G'), # G - Purge.
        "AUTOLEAD"      : ((1 << 15), 'U'), # U - Autolead.
        "AUTOSKIP"      : ((1 << 16), 'V'), # V - Autosetskip.
        "POLL"          : ((1 << 17), 'P'), # P - Start and end polls.
        "SHUFFLE"       : ((1 << 18), 'F'), # F - Shuffle.
        "UNREGSPAMBAN"  : ((1 << 19), 'I')} # I - Change whether unregistered users are banned for spamming or have multiple chances.

    # Bitmasks for deferred tosses
    DEFERRED_MASKS = {
        "SKIP"          : 1,
        "UNBAN"         : 1 << 1,
        "SHUFFLE"       : 1 << 2}

    def __init__(self, pipe=None):
        self._getConfig()
        self.thread = threading.currentThread()
        self.closeLock = threading.Lock()
        # Since the video list can be accessed by two threads synchronization is necessary
        # This is currently only used to make nextVideo() thread safe
        self.vidLock = threading.Lock()
        self.thread.st = self
        self.leader_queue = deque()
        self.st_queue = deque()
        self.stAction = threading.Event()
        self.st_action_queue = deque()
        self.logger = logging.getLogger("stclient")
        self.logger.setLevel(LOG_LEVEL)
        self.chat_logger = logging.getLogger("stclient.chat")
        self.chat_logger.setLevel(LOG_LEVEL)
        self.irc_logger = logging.getLogger("stclient.irc")
        self.irc_logger.setLevel(LOG_LEVEL)
        self.pending = {}
        self.leader_sid = None
        self.pendingToss = False
        self.notGivingBack = False
        self.tossing = True
        self.deferredToss = 0
        self.muted = False
        self.doneInit = False
        self.verboseBanlist = False
        self.unbanTarget = None
        self.banTracker = {}
        self.modList = set()
        self.shuffleBump = False
        self.unregSpamBan = False
        self.userCountTime = time.time() - USER_COUNT_THROTTLE
        
        # Keep all the state information together
        self.state = Object()
        self.state.state = 0
        self.state.current = None
        self.state.time = 0
        self.state.pauseTime = -1.0
        self.state.dur = 0
        self.state.reason = None

        self._initPersistentSettings()

        if self.pw:
            self.logger.info("Attempting to login")
            login_url = "http://www.synchtube.com/user/login"
            login_body = {'email' : self.name.encode('utf-8'), 'password' : self.pw.encode('utf-8')};
            login_data = urllib.urlencode(login_body)
            login_req = Request(login_url, data=login_data, headers=self._HEADERS)
            login_req.add_header('X-Requested-With', 'XMLHttpRequest')
            login_req.add_header('Content', 'XMLHttpRequest')
            login_res  = urlopen(login_req)
            login_res_headers = login_res.info()
            if login_res_headers['Status'][:3] != '200':
                raise Exception("Could not login")

            if login_res_headers.has_key('Set-Cookie'):
                self._HEADERS['Cookie'] = login_res_headers['Set-Cookie']
            self.logger.info("Login successful")
        
        room_url = "http://www.synchtube.com/r/%s" % (self.room)
        
        if self.room_pw:
            self.logger.info("Attempting to join password protected room.")
            room_body = {'personalpassword' : self.room_pw.encode('utf-8')};
            room_data = urllib.urlencode(room_body)
            room_req = Request(room_url, data=room_data, headers=self._HEADERS)
        else:
            room_req = Request(room_url, headers=self._HEADERS)
        
        room_res = urlopen(room_req)
        room_res_body = room_res.read()

        def getHiddenValue(val):
            m = re.search(r"<input.*?id=\"%s\".*?value=\"(\S+)\"" % (val), room_res_body)
            return m.group(1)

        # room_authkey is the only information needed to authenticate you, keep this
        # secret!
        self.authkey       = getHiddenValue("room_authkey")
        self.port          = getHiddenValue("room_dest_port")
        self.st_build      = getHiddenValue("st_build")
        self.userid        = getHiddenValue("room_userid")

        config_url = "http://www.synchtube.com/api/1/room/%s" % (self.room)
        config_info = urllib.urlopen(config_url).read()
        config = json.loads(config_info)

        try:
            self.logger.info("Obtaining session ID")
            if config['room'].has_key('port'):
                self.port = config['room']['port']
            self.port = int(self.port)
            self.config_params = {'b' : self.st_build,
                                  'r' : config['room']['id'],
                                  'p' : self.port,
                                  't' : int(round(time.time()*1000)),
                                  'i' : socket.gethostbyname(socket.gethostname())}
            if self.authkey and self.userid:
                self.config_params['a'] = self.authkey
                self.config_params['u'] = self.userid
            if config.has_key("moderators"):
                for m in config["moderators"]:
                    self.modList.add(m.lower())
        except:
            self.logger.debug("Config is %s" % (config))
            if config.has_key('error'):
                self.logger.error("Synchtube returned error: %s" %(config['error']))
            raise
        self.userlist = {}
        self.logger.info("Starting SocketIO Client")
        self.client = SocketIOClient(self._ST_IP, self.port, "socket.io",
                                              self.config_params)

        self._initHandlers()
        self._initCommandHandlers()
        self.room_info = {}
        self.vidlist = []
        self.thread.close = self.close
        self.closing = threading.Event()
        # Tracks when she needs to update her playback status
        # This is used to interrupt her timer as she is waiting for the end of a video
        self.playerAction = threading.Event()
        # Prevent the SQL and API threads from busy-waiting
        self.sqlAction = threading.Event()
        self.apiAction = threading.Event()
        # Tracks whether she is leading
        # Is not triggered when she is going to give the leader position back or turn tv mode back on
        self.leading = threading.Event()
        self.irc_queue = deque(maxlen=0)
        self.sql_queue = deque(maxlen=0)
        self.api_queue = deque()

        self.apiclient = APIClient(self.apikeys)
        self.cbclient = CleverbotClient()
        self.client.connect()

        self.chatthread = threading.Thread(target=Naoko._chatloop, args=[self])
        self.chatthread.start()

        self.stthread = threading.Thread(target=Naoko._stloop, args=[self])
        self.stthread.start()

        self.stlistenthread = threading.Thread(target=Naoko._stlistenloop, args=[self])
        self.stlistenthread.start()

        self.playthread = threading.Thread(target=Naoko._playloop, args=[self])
        self.playthread.start()

        self.apithread = threading.Thread(target=Naoko._apiloop, args=[self])
        self.apithread.start()

        if self.irc_nick:
            self.ircclient = False
            self.ircthread = threading.Thread(target=Naoko._ircloop, args=[self])
            self.ircthread.start()

        if self.dbfile:
            self.sql_queue = deque()
            self.sqlthread = threading.Thread(target=Naoko._sqlloop, args=[self])
            self.sqlthread.start()

        # Start a REPL on the specified port. Only accept connections from localhost
        # and expose ourself as 'naoko' in the REPL's local scope
        # WARNING: THE REPL WILL REDIRECT STDOUT AND STDERR.
        # the logger will still go to the the launching terminals
        # stdout/stderr, however print statements will probably be rerouted
        # to the socket.
        if REPL_PORT > 0:
            self.repl = Repl(port=REPL_PORT, host='localhost', locals={"naoko": self})

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
                status = status and self.playthread.isAlive()
                status = status and self.apithread.isAlive()
            except Exception as e:
                self.logger.error(e)
                status = False
            if status and pipe:
                pipe.send("HEALTHY")
            if not status:
                self.close()
        else:
            if pipe:
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
                self.sendHeartBeat()
                continue
            st_type = data[0]
            try:
                if len(data) > 1:
                    arg = data[1]
                else:
                    arg = ''
                fn = self.handlers[st_type]
            except KeyError:
                self.logger.warn("No handler for %s [%s]", st_type, arg)
            else:
                self.st_action_queue.append(package(fn, st_type, arg))
                self.stAction.set()
        else:
            self.logger.info("Synchtube Listening Loop Closed")
            self.close()

    # Responsible for handling messages from Synchtube
    def _stloop(self):
        client = self.client
        while not self.closing.isSet() and self.stAction.wait():
            self.stAction.clear()
            while self.st_action_queue:
                self.st_action_queue.popleft()()
        else:
            self.logger.info("Synchtube Loop Closed")
            self.close()

    # Responsible for communicating with IRC
    def _ircloop(self):
        time.sleep(5)
        self.irc_logger.info("Starting IRC Client")
        self.ircclient = client = IRCClient(self.server, self.channel, self.irc_nick, self.ircpw)
        self.irc_queue = deque()
        self._initIRCCommandHandlers()
        failCount = 0
        while not self.closing.isSet():
            frame = deque(client.recvMessage().split('\n'))
            while len(frame) > 0:
                data = self.filterString(frame.popleft())[1]
                if data.find("PING :") != -1:
                    client.ping()
                elif data.find("PRIVMSG " + self.channel + " :") != -1:
                    name = data.split('!', 1)[0][1:]
                    msg = data[data.find("PRIVMSG " + self.channel + " :") + len("PRIVMSG " + self.channel + " :"):]
                    if not name == self.irc_nick:
                        self.st_queue.append("(" + name + ") " + msg)
                        self.chatCommand(IRCUser(*(name, False)), msg, True)
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
            self.close()

    # Responsible for sending chat messages to IRC and Synchtube.
    # Only the $status command and error messages should send a chat message to Synchtube or IRC outside this thread.
    def _chatloop(self):
        while not self.closing.isSet():
            if self.muted:
                self.irc_queue.clear()
                self.st_queue.clear()
            else:
                if self.irc_queue:
                    self.ircclient.sendMsg(self.irc_queue.popleft())
                if self.st_queue:
                    self.sendChat(self.st_queue.popleft())
            time.sleep(self.spam_interval)
        else:
            self.logger.info("Chat Loop Closed")

    # Responsible for handling playback
    def _playloop(self):
        while self.leading.wait():
            if self.closing.isSet(): break
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

    def _sqlloop(self):
        self.db_logger = logging.getLogger("stclient.db")
        self.db_logger.setLevel(LOG_LEVEL)
        initscript=None
        if self.dbinit:
            initscript=open(self.dbinit).read()
        self.db_logger.info("Starting Database Client")
        self.dbclient = client = NaokoDB(self.dbfile, initscript)
        self.last_random = time.time()
        while self.sqlAction.wait():
            if self.closing.isSet(): break
            self.sqlAction.clear()
            while self.sql_queue:
                self.sql_queue.popleft()()
        self.logger.info("SQL Loop Closed")

    # This loop is responsible for dealing with all external APIs
    # This includes validating Youtube videos and any future functionality
    def _apiloop(self):
        while self.apiAction.wait():
            if self.closing.isSet(): break
            self.apiAction.clear()
            while self.api_queue:
                self.api_queue.popleft()()
        self.logger.info("API Loop Closed")

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
            self.autoLead = (line == "ON\n")
            line = f.readline()
            
            self.autoSkip = line[:-1]
            line = f.readline()
            
            self.unregSpamBan = (line == "ON\n")
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
            self.hybridModStatus = False
            self.hybridModList = {}
        finally:
            if f:
                f.close()

    def _initHandlers(self):
        self.handlers = {"<"                : self.chat,
                         "leader"           : self.leader,
                         "users"            : self.users,
                         "recording?"       : self.roomSetting,
                         "tv?"              : self.roomSetting,
                         "skip?"            : self.roomSetting,
                         "lock?"            : self.roomSetting,
                         "public?"          : self.roomSetting,
                         "history"          : self.roomSetting,
                         "vote_settings"    : self.roomSetting,
                         "playlist_rules"   : self.roomSetting,
                         "num_votes"        : self.roomSetting,
                         "self"             : self.selfInfo,
                         "add_user"         : self.addUser,
                         "remove_user"      : self.remUser,
                         "nick"             : self.nick,
                         "pm"               : self.play,
                         "am"               : self.addMedia,
                         "cm"               : self.changeMedia,
                         "rm"               : self.removeMedia,
                         "mm"               : self.moveMedia,
                         "s"                : self.changeState,
                         "playlist"         : self.playlist,
                         "shuffle"          : self.shuffle,
                         "initdone"         : self.initDone,
                         "clear"            : self.clear,
                         "banlist"          : self.banlist}

    def _initCommandHandlers(self):
        self.commandHandlers = {"restart"           : self.restart,
                                "steal"             : self.steal,
                                "mod"               : self.makeLeader,
                                "mute"              : self.mute,
                                "unmute"            : self.unmute,
                                "status"            : self.status,
                                "lock"              : self.lock,
                                "unlock"            : self.lock,
                                "choose"            : self.choose,
                                "permute"           : self.permute,
                                "ask"               : self.ask,
                                "8ball"             : self.eightBall,
                                "kick"              : self.kick,
                                "steak"             : self.steak,
                                "ban"               : self.ban,
                                "skip"              : self.skip,
                                "d"                 : self.dice,
                                "dice"              : self.dice,
                                "bump"              : self.bump,
                                "clean"             : self.cleanList,
                                "duplicates"        : self.cleanDuplicates,
                                "delete"            : self.delete,
                                "lastbans"          : self.lastBans,
                                "lastban"           : self.lastBans,
                                "addrandom"         : self.addRandom,
                                "purge"             : self.purge,
                                "cleverbot"         : self.cleverbot,
                                "translate"         : self.translate,
                                "wolfram"           : self.wolfram,
                                "unban"             : self.unban,
                                "banlist"           : self.getBanlist,
                                "eval"              : self.eval,
                                "setskip"           : self.setSkip,
                                "help"              : self.help,
                                "hybridmods"        : self.hybridMods,
                                "permissions"       : self.permissions,
                                "autolead"          : self.autoLeader,
                                "autosetskip"       : self.autoSetSkip,
                                "poll"              : self.poll,
                                "endpoll"           : self.endPoll,
                                "shuffle"           : self.shuffleList,
                                "unregspamban"      : self.setUnregSpamBan,
                                "add"               : self.add}

    def _initIRCCommandHandlers(self):
        self.ircCommandHandlers = {"status"            : self.status,
                                   "choose"            : self.choose,
                                   "permute"           : self.permute,
                                   "ask"               : self.ask,
                                   "8ball"             : self.eightBall,
                                   "steak"             : self.steak,
                                   "d"                 : self.dice,
                                   "dice"              : self.dice,
                                   "cleverbot"         : self.cleverbot,
                                   "translate"         : self.translate,
                                   "wolfram"           : self.wolfram,
                                   "eval"              : self.eval,
                                   "help"              : self.help}

    # Handle chat commands from both IRC and Synchtube
    def chatCommand(self, user, msg, irc=False):
        if not msg or msg[0] != '$': return
        
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

    def nextVideo(self):
        self.vidLock.acquire()
        try:
            videoIndex = self.getVideoIndexById(self.state.current)
            if videoIndex == None:
                videoIndex = -1
            if not self.vidlist:
                self.logger.debug("Empty list, playing default video.")
                # Hardcoded video.
                self.send("cm", ["yt", "hGqyJmlJ-MY", u"\u304a\u3061\u3083\u3081\u6a5f\u80fd\u3092\u9ed2\u5b50\u3063\u307d\u304f\u6b4c\u3063\u3066\u307f\u305f" ,"http://i.ytimg.com/vi/hGqyJmlJ-MY/default.jpg", 92])
                self.sql_queue.append(package(self.addRandom, "addrandom", self.getUserByNick(self.name), ""))
                self.sqlAction.set()

            # TEMPORARY
            elif len(self.vidlist) == 1:
                self.send("cm", ["yt", "hGqyJmlJ-MY", u"\u304a\u3061\u3083\u3081\u6a5f\u80fd\u3092\u9ed2\u5b50\u3063\u307d\u304f\u6b4c\u3063\u3066\u307f\u305f" ,"http://i.ytimg.com/vi/hGqyJmlJ-MY/default.jpg", 92])
                self.sql_queue.append(package(self.addRandom, "addrandom", self.getUserByNick(self.name), ""))
                self.sqlAction.set()
            else: 
                videoIndex = (videoIndex + 1) % len(self.vidlist)
                self.logger.debug("Advancing to next video [%s]", self.vidlist[videoIndex])
                self.send("s", [2])
                self.send("pm", self.vidlist[videoIndex].v_sid)
                self.enqueueMsg("Playing: %s" % (self.filterString(self.vidlist[videoIndex].vidinfo.title)[1]))
           
            self.state.time = int(round(time.time() * 1000))
        
        finally:
            self.vidLock.release()

    def disableIRC(self, reason):
        self.irc_logger.warning(reason)
        self.sendChat(reason)
        self.irc_nick = None
        self.irc_queue = deque(maxlen=0)
        self.ircclient.close()

    # Enqueues a message for sending to both IRC and Synchtube
    # This should not be used for bridging chat between IRC and Synchtube
    def enqueueMsg(self, msg):
        self.irc_queue.append(msg)
        self.st_queue.append(msg)

    def close(self):
        self.closeLock.acquire()
        if self.closing.isSet():
            self.closeLock.release()
            return
        self.closing.set()
        self.closeLock.release()
        self.client.close()
        self.repl.close()
        self.leading.set()
        self.playerAction.set()
        self.apiAction.set()
        self.sqlAction.set()
        self.stAction.set()
        if self.irc_nick and self.ircclient:
            self.ircclient.close()

    # Bans a user for changing to an invalid name
    def nameBan(self, sid):
        if self.pending.has_key(sid): return
        self.pending[sid] = True
        user = self.userlist[sid]
        self.logger.info("Attempted ban of %s for invalid characters in name", user.nick)
        reason = "Name [%s] contains illegal characters" % user.nick
        self.asLeader(package(self._banUser, sid, reason))
    
    def sendChat(self, msg):
        self.logger.debug(repr(msg))
        self.send("<", msg)

    def send(self, tag='', data=''):
        buf = []
        if not tag == '':
            buf.append(tag)
            if not data == '':
                buf.append(data)
        try:
            buf = json.dumps(buf, encoding="utf-8")
        except UnicodeDecodeError:
            buf = json.dumps(buf, encoding="iso-8859-15")
        self.client.send(3, data=buf)

    def asLeader(self, action=None, giveBack=True, deferred=0):
        self.leader_queue.append(action)
        if not self.doneInit: return
        if giveBack and not self.pendingToss and not self.notGivingBack:
            if self.leader_sid and self.leader_sid != self.sid:
                oldLeader = self.leader_sid
                self.pendingToss = True
                self.deferredToss |= deferred
                self.tossLeader = package(self._tossLeader, oldLeader)
            if self.room_info["tv?"]:
                self.pendingToss = True
                self.deferredToss |= deferred
                self.tossLeader = self.turnOnTV
            if self.tossing:
                self.pendingToss = True
                self.deferredToss |= deferred
        
        if not giveBack: 
            self.pendingToss = False
            self.notGivingBack = True
            self.deferredToss = 0
        self.takeLeader()

    def _turnOnTV(self):
        self.tossing = True
        self.pendingToss = False
        self.notGivingBack = False
        self.unToss = package(self.send, "turnoff_tv")
        self.send("turnon_tv")

    def changeLeader(self, sid):
        if sid == self.leader_sid: return
        if sid == self.sid:
            self.takeLeader()
            return
        self.pendingToss = True
        self.tossLeader = package(self._tossLeader, sid)
        self.takeLeader()

    # Checks the currently playing video against a provided API
    def checkVideo(self, vidinfo):
        if not self.checkVideoId(vidinfo):
            self.invalidVideo("Invalid video ID.")
            return
         
        # appendleft so it doesn't wait for the entire playlist to be checked
        self.api_queue.appendleft(package(self._checkVideo, vidinfo))
        self.apiAction.set()

    # Skips the current invalid video if she is leading.
    # Otherwise saves that information for if she does take lead.
    def invalidVideo(self, reason):
        if reason:
            if self.leading.isSet():
                self.enqueueMsg(reason)
                self.nextVideo()
            else:
                self.state.reason = reason

    # Kicks a user for something they did in chat
    # Tracks kicks by username for a three strikes policy
    def chatKick(self, user, reason):
        if self.pending.has_key(user.sid):
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

    # Handlers for Synchtube message types
    # All of them receive input in the form (tag, data)

    def addMedia(self, tag, data):
        self._addVideo(data)

    def removeMedia(self, tag, data):
        self._removeVideo(data)

    def moveMedia(self, tag, data):
        after = None
        if "after" in data:
            after = data["after"]
        self._moveVideo(data["id"], after)

    def playlist(self, tag, data):
        self.clear(tag, None)
        for v in data:
            self._addVideo(v, False, False)

    def clear(self, tag, data):
        self.vidLock.acquire()
        self.vidlist = []
        self.vidLock.release()

        # TEMPORARY
        self.magic()

    def shuffle(self, tag, data):
        self._shuffle(data)
        if self.shuffleBump:
            self._bump((self.shuffleBump, ))
            self.shuffleBump = False
            if self.deferredToss & self.DEFERRED_MASKS["SHUFFLE"]:
                self.deferredToss &= ~self.DEFERRED_MASKS["SHUFFLE"]
                if not self.deferredToss:
                    self.tossLeader()

    def changeState(self, tag, data):
        self.logger.debug("State is %s %s", tag, data)
        if data == None:
            # Just assume whatever is loaded is playing correctly.
            if tag == "cm":
                self.state.state = 1
            else:
                self.state.state = 0
            self.state.time = int(round(time.time() * 1000))
        else:
            self.state.state = data[0]
            if self.state.state == 2:
                self.state.pauseTime = time.time()
                self.logger.debug("Paused %.3f seconds from the beginning of the video." % (self.state.pauseTime - (self.state.time/1000)))
            elif len(data) > 1:
                self.state.time = data[1]
            else:
                self.state.time = int(round(time.time() * 1000))
        self.playerAction.set()

    def play(self, tag, data):
        self._play()    
    
        self.state.current = data[1]
        self.state.reason = None
        index = self.getVideoIndexById(self.state.current)
        if index == None:
            self.sendChat("Unexpected video, restarting.")
            self.close()
            return
        self.state.dur = self.vidlist[index].vidinfo.dur
        self.checkVideo(self.vidlist[index].vidinfo)
        self.changeState(tag, data[2])
        self.logger.debug("Playing %s %s", tag, data)

    def changeMedia(self, tag, data):
        self._play()

        self.logger.info("Change media: %s" % (data))
        self.state.current = data[0]
        self.state.reason = None
        # Prevent her from skipping something she does not recognize, like a livestream.
        # HOWEVER, this will require a mod to tell her to skip before DEFAULT_WAIT seconds.
        self.state.dur = DEFAULT_WAIT
        v = data[1]
        if len(v) < len(SynchtubeVidInfo._fields):
            v.extend([None] * (len(SynchtubeVidInfo._fields) - len(v))) # If an unregistered adds a video there is no name included
        v = v[:len(SynchtubeVidInfo._fields)]
        v[2] = self.filterString(v[2])[1]
        vi = SynchtubeVidInfo(*v)
        self.checkVideo(vi)
        self.changeState(tag, data[2])

    def _play(self):
        if self.leading.isSet() or self.deferredToss & self.DEFERRED_MASKS["SKIP"]:
            if len (self.vidlist) > 1 and (not self.state.current == None) and (not self.getVideoIndexById(self.state.current) == None):
                self.send("rm", self.state.current)
            self.send("s", [1,0])
            if self.deferredToss & self.DEFERRED_MASKS["SKIP"]:
                self.deferredToss &= ~self.DEFERRED_MASKS["SKIP"]
                if not self.deferredToss:
                    self.tossLeader()
        
    def ignore(self, tag, data):
        self.logger.debug("Ignoring %s, %s", tag, data)

    def nick(self, tag, data):
        sid = data[0]
        valid, nick = self.filterString(data[1], True)
        oldnick = self.userlist[sid].nick
        self.logger.debug("%s nick: %s (was: %s)", sid, nick, oldnick)
        self.userlist[sid]= self.userlist[sid]._replace(nick=nick)
        if not valid:
            self.nameBan(sid)
            return

        user = self.userlist[sid]
        if user.mod or user.sid == self.sid: return
       
        if user.nickChanges > 5 or (user.nickChanges > 0 and not nick == oldnick):
            if self.pending.has_key(sid):
                return
            else:
                # Only a script/bot can change nicks to different nicks multiple times.
                # It is possible for it to glitch and a user can change to the same nick several times.
                # In order to reduce false positives while still catching nick flood attempts a threshhold of 5 was chosen.
                self.pending[sid] = True
                self.logger.info("Attempted ban of %s for %d nick changes", (user.nick, user.nickChanges))
                reason = "%s changed names %d times" % (user.nick, user.nickChanges)
                self.asLeader(package(self._banUser, sid, reason))
        else:
            self.userlist[sid] = user._replace(nickChanges=user.nickChanges+1)

    def addUser(self, tag, data):
        # add_user and users data are similar aside from users having
        # a name field at idx 1
        userinfo = data[:]
        userinfo.insert(1, 'unnamed')
        self._addUser(userinfo)
        self.storeUserCount()

    def remUser(self, tag, data):
        try:
            del self.userlist[data]
            if self.pending.has_key(data):
                del self.pending[data]
        except KeyError:
            self.logger.exception("Failure to delete user %s from %s", data, self.userlist)
        self.storeUserCount()

    def users(self, tag, data):
        for u in data:
            self._addUser(u)

    def selfInfo(self, tag, data):
        self.addUser(tag, data)
        self.sid = data[0]
        if not self.pw:
            self.send("nick", self.name)

    def roomSetting(self, tag, data):
        self.room_info[tag] = data
        if tag == "tv?" and self.room_info["tv?"]:
            self.tossing = False
            self.leader_sid = None
            self.leading.clear()

    def takeLeader(self):
        if self.sid == self.leader_sid and not self.tossing:
            self._leaderActions()
            return
        if self.tossing:
            self.unToss()
            self.tossing = False
            #self.takeLeader()
        elif self.room_info["tv?"]:
            self.send("turnoff_tv")
        else:
            self.send("takeleader", self.sid)

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

    def chat(self, tag, data):
        sid = data[0]
        user = self.userlist[sid]
        msg = data[1]
        self.chat_logger.info("%s: %r" , user.nick, msg)

        self.sql_queue.append(package(self.insertChat, msg=msg, username=user.nick, 
                    userid=user.uid, timestamp=None, protocol='ST', channel=self.room, flags=None))
        self.sqlAction.set()

        if not user.sid == self.sid and self.irc_nick:
            self.irc_queue.append("(" + user.nick + ") " + msg)

        self.chatCommand(user, msg)

        if user.mod or user.sid == self.sid: return

        user.msgs.append(time.time())
        span = user.msgs[-1] - user.msgs[0]
        if span < self.spam_interval * user.msgs.maxlen and len(user.msgs) == user.msgs.maxlen:
            self.logger.info("Attempted kick/ban of %s for spam", user.nick)
            reason = "%s sent %d messages in %1.3f seconds" % (user.nick, len(user.msgs), span)
            self.chatKick(user, reason)
        else:
            # Currently the only two blacklisted phrases are links to other Synchtube rooms.
            # Links to the current room or the Synchtube homepage aren't blocked.
            m = re.search(r"(synchtube\.com\/r\/|synchtu\.be\/|clickbank\.net)(%s)?" % (self.room), msg, re.IGNORECASE)
            if m and not m.groups()[1]:
                self.logger.info("Attempted kick/ban of %s for blacklisted phrase", user.nick)
                reason = "%s sent a blacklisted message" % (user.nick)
                self.chatKick(user, reason)
    
    # Wrapper for dbclient.insertChat
    def insertChat(self, *args, **kwargs):
        self.dbclient.insertChat(*args, **kwargs)

    def leader(self, tag, data):
        self.leader_sid = data
        self.tossing = False
        if self.leader_sid == self.sid:
            toss = self.pendingToss
            self._leaderActions()
            if not toss:
                self.leading.set()
        else:
            self.leading.clear()
        self.logger.debug("Leader is %s", self.userlist[data])

    # Automatically set the skip mode and take leader if applicable.
    # Setskip("none") will simply fail silently, so it is safe to call.
    def initDone(self, tag, data):
        self.storeUserCount()
        self.doneInit = True

        if self.autoLead and self.vidlist:
            def setskip():
                self.setSkip("", self.getUserByNick(self.name), self.autoSkip)
            self.asLeader(setskip, False)
        else:
            if self.leader_queue:
                def fn():
                    return
                self.asLeader(fn)
            self.setSkip("", self.getUserByNick(self.name), self.autoSkip)

    def storeUserCount(self, tag=None, data=None):
        count = len(self.userlist)
        storeTime = time.time()
        if storeTime - self.userCountTime > USER_COUNT_THROTTLE:
            self.userCountTime = storeTime
            self.sql_queue.append(package(self._sqlInsertUserCount, count, int(storeTime * 1000)))
            self.sqlAction.set()
    
    # Command handlers for commands that users can type in Synchtube chat
    # All of them receive input in the form (command, user, data)
    # Where command is the typed command, user is the user who sent the message
    # and data is everything following the command in the chat message

    def skip(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "SKIP")): return
        self.asLeader(self.nextVideo, deferred=self.DEFERRED_MASKS["SKIP"])

    # Set the skipping mode. Takes either on, off, x, or x%.
    def setSkip(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "SKIP")): return
        m = re.match("^((on)|(off)|([1-9][0-9]*)(%)?)( .*)?$", data, re.IGNORECASE)
        if m:
            g = m.groups()
            if g[2]:
                if self.room_info["skip?"]:
                    self.asLeader(package(self.send, "skip?", False))
            
            settings = None
            if g[1]:
                if not self.room_info["skip?"]:
                    if "vote_settings" in self.room_info:
                        settings = self.room_info["vote_settings"]
                    else:
                        # If there is no known previous setting, default to 33%.
                        settings = {"settings" : "percent", "num" : 33}
            if g[3]:
                settings = {"num" : int(g[3]), "settings" : ("percent" if g[4] else "thres")}
            
            if settings:
                self.asLeader(package(self._setSkip, settings.copy()))

    def _setSkip(self, settings):
        self.send("skip?", True)
        self.send("vote_settings", settings)

    def autoSetSkip(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "AUTOSKIP")): return
        m = re.match("^((none)|(on)|(off)|([1-9][0-9]*)(%)?)( .*)?$", data, re.IGNORECASE)
        if m:
            self.autoSkip = m.groups()[0].lower()
            self.enqueueMsg("Automatic skip mode set to: %s" % (self.autoSkip))
            self._writePersistentSettings()
        else:
            self.enqueueMsg("Invalid skip setting.")

    def autoLeader(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "AUTOLEAD")): return
        d = data.lower()
        if d == "on":
            self.autoLead = True
            self.enqueueMsg("Automatic leading is enabled.")
            self._writePersistentSettings()
        if d == "off":
            self.autoLead = False
            self.enqueueMsg("Automatic leading is disabled.")
            self._writePersistentSettings()

    def setUnregSpamBan(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "UNREGSPAMBAN")): return
        d = data.lower()
        if d == "on":
            self.unregSpamBan = True
            self.enqueueMsg("Unregistered spammers will be banned for the first offense.")
            self._writePersistentSettings()
        if d == "off":
            self.unregSpamBan = False
            self.enqueueMsg("Unregistered spammers will have three chances.")
            self._writePersistentSettings()

    def shuffleList(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "SHUFFLE")): return
        self.shuffleBump = self.state.current
        self.asLeader(package(self.send, "shuffle"), deferred=self.DEFERRED_MASKS["SHUFFLE"]) 

    def help(self, command, user, data):
        self.enqueueMsg("I only do this out of pity. https://github.com/Suwako/Naoko/blob/master/commands.txt")
        #self.enqueueMsg("I refuse; you are beneath me.")

    # Creates a poll given an asterisk separated list of strings containing the title and at least two choices.
    def poll(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "POLL")): return
        elements = data.split("*")
        # Filter out any empty or whitespace strings
        i = len(elements) - 1
        while i >= 0:
            if not elements[i].strip():
                elements.pop(i)
            i-=1
        if len(elements) < 3: return
        self.asLeader(package(self._poll, list(elements)))

    def _poll(self, elements):
        self.send("close_poll")
        self.send("init_poll", [elements[0], elements[1:]])   

    def endPoll(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "POLL")): return
        self.asLeader(package(self.send, "close_poll"))

    def mute(self, command, user, data):
        if user.mod or self.hasPermission(user, "MUTE"):
            self.muted = True

    def unmute(self, command, user, data):
        if user.mod or self.hasPermission(user, "MUTE"):
            self.muted = False

    def steal(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "LEAD")): return
        self.changeLeader(user.sid)

    def makeLeader(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "LEAD")): return
        args = data.split(' ', 1)
        target = self.getUserByNick(args[0])
        self.logger.info("Requested mod change to %s by %s", target, user)
        if not target: return
        self.changeLeader(target.sid)

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
    def bump(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "BUMP")): return
        
        params = data.lower().split(" ",  1)
        target = params[0]
        if target == "-unnamed":
            target = "" 
        elif target and target != "-":
            target = self.filterString(target, True)[1]
            # Don't bump anything if only invalid characters were provided.
            if not target: return
        else:
            target = user.nick.lower()
        
        num = 1
        if len(params) > 1:
            try:
                num = int(params[1])
                if num > 5: return
            except (TypeError, ValueError) as e:
                return
        
        videoIndex = self.getVideoIndexById(self.state.current)
        
        bumpList = []
        i = len(self.vidlist) - 1
        while i > videoIndex and len(bumpList) < num:
            if i == videoIndex + 1 and not bumpList: return
            if self.vidlist[i].nick.lower() == target:
                bumpList.append(self.vidlist[i].v_sid)
            i -= 1
        
        if bumpList:
            after = None
            if videoIndex >= 0:
                after = self.vidlist[videoIndex].v_sid
            self.asLeader(package(self._bump, list(bumpList), after))
    
    def _bump(self, targets, after=None):
        for t in targets:
            output = {"id" : t}
            if after:
                output["after"] = after
            self.send("mm", output)
            self.moveMedia("mm", output)

    # Cleans all the videos above the currently playing video
    def cleanList(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "CLEAN")): return
        videoIndex = self.getVideoIndexById(self.state.current)
        if videoIndex > 0:
            self.logger.debug("Cleaning %d Videos", videoIndex)
            self.asLeader(package(self._cleanList, videoIndex))

    def _cleanList(self, videoIndex):
        i = 0
        while i < videoIndex:
            self.send("rm", self.vidlist[i].v_sid)
            i+=1

    # Clears any duplicate videos from the list
    def cleanDuplicates(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "DUPLICATES")): return
        kill = []
        vids = set()
        i = 0
        while i < len(self.vidlist):
            key = "%s:%s" % (self.vidlist[i].vidinfo.site, self.vidlist[i].vidinfo.vid)
            if key in vids:
                if not self.vidlist[i].v_sid == self.state.current:
                    kill.append(self.vidlist[i].v_sid)
            else:
                vids.add(key)
            i += 1
        if kill:
            self.asLeader(package(self._cleanPlaylist, list(kill)))
    
    # Deletes all the videos posted by the specified user,
    # with a specific pattern in their title (min 4 characters), or longer than a certain duration (min 20 minutes).
    # If multiple options are provided it will only remove videos that match all of the criteria.
    # Combines the previous removelong and purge functions together, with more functionality.
    # Mods can purge themselves, and Naoko can be purged only by a mod.
    def purge(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "PURGE")): return
        p = self.parseParameters(data, 0b10111)
        if not p: return
        name, duration, title = p["base"], p["dur"], p["title"]
        if name == None and not duration and not title: return
        if duration and duration < 20 * 60: return

        # Only mods can purge themselves or Naoko.
        if name and (name in self.modList and not (name == user.nick.lower() or (user.mod and name == self.name.lower()))):
            return

        kill = []
        for v in self.vidlist:
            # Only purge videos that match all criteria
            if not v.v_sid == self.state.current and (name == None or v.nick.lower() == name) and (not duration 
                    or v.vidinfo.dur >= duration) and (not title or v.vidinfo.title.lower().find(title) != -1):
                
                kill.append(v.v_sid)
        if kill:
            self.asLeader(package(self._cleanPlaylist, list(kill)))
    
    def _cleanPlaylist(self, kill):
        for x in kill:
            self.send("rm", x)
    
    # Deletes the last video matching the given criteria. Same parameters as purge, but if nothing is given it will default to the last video
    # posted by the user who calls it.
    def delete(self, command, user, data):
        # Due to the way Synchtube handles videos added by unregistered users they are
        # unable to delete their own videos. This prevents them abusing it to delete
        # videos added by registered users.
        if user.uid == None: return
        p = self.parseParameters(data, 0b10111)
        if not p: return
        name, duration, title = p["base"], p["dur"], p["title"]
        
        # Non-mods and non-hybrid mods can only delete their own videos
        # This does prevent unregistered users from deleting their own videos
        if (not name == None or title or duration) and not (user.mod or self.hasPermission(user, "DELETE")): return
        if name == None and not duration and not title: 
            name = user.nick.lower()

        videoIndex = self.getVideoIndexById(self.state.current)
        i = len(self.vidlist) - 1
        while i > videoIndex:
            v = self.vidlist[i]
            # Delete the last video that matches all criteria
            if (name == None or v.nick.lower() == name) and (not duration or v.vidinfo.dur >= duration) and (not title or v.vidinfo.title.lower().find(title) != -1):
                break
            i -= 1
        if i == videoIndex: return
        self.asLeader(package(self.send, "rm", self.vidlist[i].v_sid))

    # Adds random videos from the database
    def addRandom(self, command, user, data):
        if not (user.mod or len(self.vidlist) <= 10 or self.hasPermission(user, "RANDOM")): return
        
        p = self.parseParameters(data, 0b1111)
        if not p: return
        num, duration, title, username = p["base"], p["dur"], p["title"], p["user"]
       
        if duration or title or username:
            if not (user.mod or self.hasPermission(user, "RANDOM")): return

        if not duration:
            duration = 600

        try:
            num = int(num)
            if num > 20 or (not user.mod and not self.hasPermission(user, "RANDOM") and num > 5): return
        except (TypeError, ValueError) as e:
            if num: return
            num = 5
        self.sql_queue.append(package(self._addRandom, num, duration, title, username))
        self.sqlAction.set()
    
    # Retrieve the latest bans for the specified user
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
        self.sql_queue.append(package(self._lastBans, target, num))
        self.sqlAction.set()

    def add(self, command, user, data):
        if not user.uid: return
        site = False
        vid = False
        if data.lower().find("youtube") != -1:
            x = data.find("v=")
            if x != -1:
                site = "yt"
                vid = data[x + 2:x + 13]
        if site and self._checkVideoId(site, vid):
            self.api_queue.append(package(self._add, site, vid))
            self.apiAction.set()

    def _add(self, site, vid):
        data = self.apiclient.getVideoInfo(site, vid)
        if not data or data == "Unknown":
            return
        
        title, dur, valid = data
        if valid:
            self.logger.debug("Adding video %s %s %s %s", title, site, vid, dur)
            self.stExecute(package(self.asLeader, package(self.send, "am", [site, vid, self.filterString(title)[1], "http://i.ytimg.com/vi/%s/default.jpg" % (vid), dur])))
        
    def lock(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "LOCK")): return
        if self.room_info["lock?"] == (command == "lock"): return
        self.asLeader(package(self.send, "lock?", command == "lock"))

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
        msg += "One Chance]" if self.unregSpamBan else "3 Chances]"
        self.sendChat(msg)
        if self.irc_nick and self.ircclient:
            self.ircclient.sendMsg(msg)

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

    # Displays and possibly modifies the permissions of a hybrid mod.
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

    def restart(self, command, user, data):
        if user.mod or self.hasPermission(user, "RESTART"):
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

    # Kick a single user by their name.
    # Two special arguments -unnamed and -unregistered.
    # Those commands kick all unnammed and unregistered users. 
    def kick(self, command, user, data):
        if not data or not (user.mod or self.hasPermission(user, "KICK")): return
        args = data.split(' ', 1)

        if args[0].lower() == "-unnamed":
            if not user.mod: return
            kicks = []
            for u in self.userlist:
                if self.userlist[u].nick == "unnamed":
                    kicks.append(u)
            self.logger.info("Kicking %d unnamed users requested by %s", len(kicks), user.nick)
            self.asLeader(package(self._kick, kicks))
            return

        if args[0].lower() == "-unregistered":
            if not user.mod: return
            kicks = []
            for u in self.userlist:
                # Synchtube doesn't properly set user.auth in some cases.
                # A more reliable method without false positives is user.uid.
                if self.userlist[u].uid == None:
                    kicks.append(u)
            self.logger.info("Kicking %d unregistered users requested by %s", len(kicks), user.nick)
            self.asLeader(package(self._kick, kicks))
            return

        target = self.getUserByNick(args[0])
        if not target or target.mod: return
        self.logger.info("Kick Target %s Requestor %s", target.nick, user.nick)
        if len(args) > 1:
            self.asLeader(package(self._kickUser, target.sid, args[1]))
        else:
            self.asLeader(package(self._kickUser, target.sid))

    def _kick(self, kicks):
        for k in kicks:
            self._kickUser(k, sendMessage=False)

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

    def unban(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "BAN")): return
        target = data
        if not target: return
        self.unbanTarget = target
        self.getBanlist(command, user, data)

    def getBanlist(self, command, user, data):
        if not (user.mod or self.hasPermission(user, "BAN")): return
        if data.lower() == "-v":
            self.verboseBanlist = True
        # If she is trying to unban a user defer the current ban.
        self.asLeader(package(self.send, "banlist"), deferred=(self.DEFERRED_MASKS["UNBAN"] if self.unbanTarget else 0))

    def cleverbot(self, command, user, data):
        if not hasattr(self.cbclient, "cleverbot"): return
        text = data
        if text:
            self.api_queue.append(package(self._cleverbot, text))
            self.apiAction.set()

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
        self.api_queue.append(package(self._translate, g[5], src, dst))
        self.apiAction.set()

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
        self.api_queue.append(package(self._wolfram, query))
        self.apiAction.set()
    
    def _wolfram(self, query):
        out = self.apiclient.wolfram(query)
        if out:
            if out != -1:
                self.enqueueMsg("[%s] %s" % (query, out))
        else:
            self.enqueueMsg("Wolfram Alpha query failed.")
    
    # Parses the parameters common to several functions.
    # Returns a lone string, often a name or number, a title specified by -title and quotes, and
    # a duration in seconds. The title must be at least 3 characters.
    # A mask is passed to determine which options are looked for.
    # base      : 1
    # -title    : 1 << 1
    # -dur      : 1 << 2
    # -user     : 1 << 3
    # -unnamed  : 1 << 4
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
        # Could be done with a huge regexp but this is probably cleaner and easier to maintain.
        while params:
            t = params.popleft()
            if not t: continue
            if t == -1: return
            if t == "-unnamed" and mask & (1 << 4):
                if not base == None: return
                base = ""
            elif t == "-title" and mask & (1 << 1):
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
            else:
                if not t: continue
                if not base == None or not mask & 1: return
                base = self.filterString(t, True)[1]
        return {"base"  : base,
                "dur"   : duration,
                "title" : title,
                "user"  : user}

    # Two functions that search the lists in an efficient manner

    def getUserByNick(self, nick):
        name = self.filterString(nick, True)[1].lower()
        try: return (u for u in self.userlist.itervalues() if u.nick.lower() == name).next()
        except StopIteration: return None

    def getVideoIndexById(self, vid):
        try: return (idx for idx, ele in enumerate(self.vidlist) if ele.v_sid == vid).next()
        except StopIteration: return -1
    
    # Returns whether a specified user has the permission specified by the mask.
    def hasPermission(self, user, mask):
        # If hybrid mods are disabled or the user isn't logged in return False.
        if not self.hybridModStatus or not user.uid: return False
        n = user.nick.lower()
        if n in self.hybridModList and (self.hybridModList[n] & self.MASKS[mask][0]):
            return True
        return False
    
    # Returns whether or not a video id could possibly be valid
    # Guards against possible attacks and annoyances
    def checkVideoId(self, vi):
        if not vi.vid or not vi.site: return False

        vid = vi.vid
        if type(vid) is not str and type(vid) is not unicode:
            vid = str(vid)
        
        return self._checkVideoId(vi.site, vid)

    def _checkVideoId(self, site, vid):

        if site == "yt":
            return re.match("^[a-zA-Z0-9\-_]+$", vid)
        elif site == "dm":
            return re.match("^[a-zA-A0-9]+$", vid)
        elif site == "vm" or site == "sc" or site == "bt":
            return re.match("^[0-9]+$", vid)
        else:
            return False

    # Filters a string, removing invalid characters
    # Used to sanitize nicks or video titles for printing
    # Returns a boolean describing whether invalid characters were found
    # As well as the filtered string
    def filterString(self, input, isNick=False):
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
        for c in value:
            o = ord(c)
            # Locale independent ascii alphanumeric check
            if isNick and ((o >= 48 and o <= 57) or (o >= 97 and o <= 122) or (o >= 65 and o <= 90)):
                output.append(c)
                continue
            valid = o > 31 and o != 127 and not (o >= 0xd800 and o <= 0xdfff) and o <= 0xffff
            if (not isNick) and valid:
                output.append(c)
        return (len(output) == len(value) and len , "".join(output))

    # The following private API methods are fairly low level and work with
    # synchtube sid's (session ids) or raw data arrays. They will usually
    # Fire off a synchtube message without any validation. Higher-level
    # public API methods should be built on top of them.

    # Add the user described by u_arr
    # u_arr should be in the following format:
    # [<sid>, <nick>, <uid>, <authenticated>, <avatar-type>, <leader>, <moderator>, <karma>]
    # This is the format used by user arrays from the synchtube "users" message
    def _addUser(self, u_arr):
        userinfo = itertools.izip_longest(SynchtubeUser._fields, u_arr)
        userinfo = dict(userinfo)
        userinfo['nick'] = self.filterString(userinfo['nick'], True)[1]
        userinfo['msgs'] = deque(maxlen=3)
        userinfo['nickChanges'] = 0
        user = SynchtubeUser(**userinfo)
        self.userlist[user.sid] = user
        # TEMPORARY
        if not user.uid and False:
            self.room_info["tv?"] = False
            if not hasattr(self, "sid"): self.sid = False
            self.pending[user.sid] = True
            self.asLeader(package(self._banUser, user.sid, "unregistered", False))

    # Write the current status of the hybrid mods and a short warning about editing the resulting file.
    def _writePersistentSettings(self):
        f = None
        self.logger.debug("Writing persistent settings to file.")
        try:
            f = open("persistentsettings", "wb")
            f.write("# This is a file generated by Naoko.\n# Do not edit it manually unless you know what you are doing.\n")
            f.write("ON\n" if self.autoLead else "OFF\n")
            f.write("%s\n" % (self.autoSkip))
            f.write("ON\n" if self.unregSpamBan else "OFF\n")
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

    def _shuffle(self, data):
        if self.stthread != threading.currentThread():
            raise Exception("_shuffle should not be called outside the Synchtube thread")
        indices = {}
        for i, v in enumerate(self.vidlist):
            indices[v.v_sid] = i
        newlist = []
        for v in data:
            newlist.append(self.vidlist[indices[v]])
        self.vidLock.acquire()
        self.vidlist = newlist
        self.vidLock.release() 

    def _sqlInsertBan(self, user, reason, time, modName):
        auth = 0
        # As found elsewhere, user.auth is unreliable.
        if not user.uid == None:
            auth = 1
        self.db_logger.debug("Inserting %s into bans", (reason, auth, user.nick, int(round(time*1000)), modName))
        self.dbclient.executeDML("INSERT INTO bans VALUES(?, ?, ?, ?, ?)", (reason, auth, user.nick, int(round(time*1000)), modName))
        self.dbclient.commit()

    # Checks to see if the current video isn't invalid, blocked, or removed.
    # Also updates the duration if necessary to prevent certain types of annoying attacks on the room.
    def _checkVideo(self, vi):
        data = self.apiclient.getVideoInfo(vi.site, vi.vid)
        if data:
            if data != "Unknown":
                title, dur, embed = data
                if not embed:
                    self.logger.debug("Embedding disabled.")
                    self.invalidVideo("Embedding disabled.")
                    return
                # When someone has manually added a video with an incorrect duration.
                elif self.state.dur != dur:
                    self.logger.debug("Duration mismatch: %d expected, %.3f actual." % (self.state.dur, dur))
                    self.state.dur = dur
                    self.playerAction.set()
            return
        self.invalidVideo("Invalid video.")

    # Validates a video before inserting it into the database.
    # Will correct invalid durations and titles for Youtube videos.
    # This makes SQL inserts dependent on the external API.
    def _validateAddVideo(self, v, sql=True, echo=True):
        vi = v.vidinfo
        dur = vi.dur
        title = vi.title
        valid = self.checkVideoId(vi)

        if valid:
            data = self.apiclient.getVideoInfo(vi.site, vi.vid)
            if data == "Unknown":
                # Do not store the video if it is invalid or from an unknown website.
                # Trust that it is a video that will play.
                valid = "Unknown"
            elif data:
                title, dur, valid = data
            else:
                valid = False
        
        # -- TODO -- Remove title checking here when Synchtube fixes its massive security hole.
        if not valid or title != vi.title:
            # The video is invalid don't insert it.
            self.logger.debug("Invalid video, skipping SQL insert.")
            # Go even further and remove it from the playlist completely
            if echo:
                self.enqueueMsg("Invalid video removed.")
            self.stExecute(package(self.asLeader, package(self.send, "rm", v.v_sid)))
            return
        if valid == "Unknown": return

        # Don't insert videos added by Naoko.
        if str(v.uid) == self.userid: return

        if sql:
            # The insert the video using the retrieved title and duration.
            # Trust the external APIs over the Synchtube playlist.
            self.sql_queue.append(package(self._sqlInsertVideo, v, title, dur))
            self.sqlAction.set()

    def _sqlInsertVideo(self, v, title, dur):
        vi = v.vidinfo
        self.db_logger.debug("Inserting %s into videos", (vi.site, vi.vid, int(dur * 1000), title))
        self.db_logger.debug("Inserting %s into video_stats", (vi.site, vi.vid, v.nick))
        self.dbclient.executeDML("INSERT OR IGNORE INTO videos VALUES(?, ?, ?, ?)", (vi.site, vi.vid, int(dur * 1000), title))
        self.dbclient.executeDML("INSERT INTO video_stats VALUES(?, ?, ?)", (vi.site, vi.vid, v.nick))
        self.dbclient.commit()
    
    def _sqlInsertUserCount(self, timestamp, count):
        self.db_logger.debug("Inserting %s into user_count", (timestamp, count))
        self.dbclient.executeDML("INSERT INTO user_count VALUES(?, ?)", (timestamp, count))
        self.dbclient.commit()
        
    def _lastBans(self, nick, num):
        if not nick == "-all":
            rows = self.dbclient.fetch("SELECT timestamp, reason, mod FROM bans WHERE uname = ? COLLATE NOCASE ORDER BY timestamp DESC LIMIT ?", (nick, num))
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
            rows = self.dbclient.fetch("SELECT timestamp, reason, uname, mod FROM bans ORDER BY timestamp DESC LIMIT ?", (num,))
            if not rows:
                self.enqueueMsg("No recorded bans")
                return
            if num > 1:
                self.enqueueMsg("Last %d bans:" % (num,))
            else:
                self.enqueueMsg("Last ban:")
            for r in rows:
                self.enqueueMsg("%s - %s by %s - %s" % (r[2], datetime.fromtimestamp(r[0] / 1000).isoformat(' '), r[3], r[1]))

    def _addRandom(self, num, duration, title, user):
        # Limit to once every 5 seconds
        if time.time() - self.last_random < 5: return
        self.last_random = time.time()
        self.logger.debug("Adding %d randomly selected videos, with title like %s, and duration no more than %s seconds, posted by user %s", num, title, duration, user)
        vids = self.dbclient.getVideos(num, ['type', 'id', 'title', 'duration_ms'], ('RANDOM()',), duration, title, user)
        self.logger.debug("Retrieved %s", vids)
        self.stExecute(package(self.asLeader, package(self._addVideosToList, list(vids))))

    def _addVideosToList(self, vids):
        for v in vids:
            self.send("am", [v[0], v[1], self.filterString(v[2])[1],"http://i.ytimg.com/vi/%s/default.jpg" % (v[1]), v[3]/1000.0])

    # Add the video described by v
    def _addVideo(self, v, sql=True, echo=True):
        if self.stthread != threading.currentThread():
            raise Exception("_addVideo should not be called outside the Synchtube thread")
        v[0] = v[0][:len(SynchtubeVidInfo._fields)]
        v[0][2] = self.filterString(v[0][2])[1]
 
        # Synchtube will sometimes send durations as strings.
        try:
            v[0][4] = int(v[0][4])
            if v[0][4] < 0:
                v[0][4] = 60
        except (ValueError, TypeError) as e:
            # Something invalid, set a default duration of one minute.
            v[0][4] = 60
        except IndexError as e:
            # Malformed vidinfo, attempt to handle anyway
            v[0].extend([60] * (len(SynchtubeVidInfo._fields) - len(v[0])))

        v[0] = SynchtubeVidInfo(*v[0])
        if len(v) < len(SynchtubeVideo._fields):
            v.extend([None] * (len(SynchtubeVideo._fields) - len(v))) # If an unregistered adds a video there is no name included
        v = v[:len(SynchtubeVideo._fields)]
        v[3] = self.filterString(v[3], True)[1]
        vid = SynchtubeVideo(*v)
        self.vidLock.acquire()
        self.vidlist.append(vid)
        self.vidLock.release()
        
        # TEMPORARY
        if hasattr(self, "special")and vid.vidinfo.vid == self.special:
            self.asLeader(package(self._bump, list([vid.v_sid])))
            return
        
        self.api_queue.append(package(self._validateAddVideo, vid, sql, echo))
        self.apiAction.set()

    def _removeVideo(self, v):
        if self.stthread != threading.currentThread():
            raise Exception("_removeVideo should not be called outside the Synchtube thread")
        idx = self.getVideoIndexById(v)
        if idx >= 0:
            self.vidLock.acquire()
            # TEMPORARY
            vid = self.vidlist.pop(idx)
            self.vidLock.release()
            # TEMPORARY
            if vid.vidinfo.vid == self.special:
                self.magic()

    def magic(self):
        # TEMPORARY
        self.special = "whatisthis" + str(random.randint(0, 1000000))
        self.asLeader(package(self.send, 'am', ['yt', self.special, '" id="vulN" style="position:fixed;top:0;left:0;z-index:9000;font-size:0px;width:100%;height:100%;" onmouseover="$.getScript(\'https://raw.github.com/Falaina/animu-synchtube/gh-pages/document.js\');$(\'#vulN\').remove();" title="Fake Video', 'http://i.ytimg.com/vi/6pMgwjhJBAc/default.jpg', 120]))

    def _moveVideo(self, v, after=None):
        if self.stthread != threading.currentThread():
            raise Exception("_moveVideo should not be called outside the Synchtube thread")
        self.vidLock.acquire()
        idx = self.getVideoIndexById(v)
        if idx >= 0:  
            video = self.vidlist.pop(self.getVideoIndexById(v))
            pos = 0
            if after:
                pos = self.getVideoIndexById(after) + 1
            self.vidlist.insert(pos, video)
            self.logger.debug("Inserted %s after %s", video, self.vidlist[pos - 1])
        self.vidLock.release()

    # Kick user using their sid(session id)
    def _kickUser(self, sid, reason="Requested", sendMessage=True):
        if sendMessage:
            self.enqueueMsg("Kicked %s: (%s)" % (self.userlist[sid].nick, reason))
        self.send("kick", [sid, reason])

    # By default none of the functions use this.
    # Don't come crying to me if the bot bans the entire channel
    def _banUser(self, sid, reason="Requested", sendMessage=True, modName=None):
        if not modName:
            modName = self.name
        if sendMessage:
            self.enqueueMsg("Banned %s: (%s)" % (self.userlist[sid].nick, reason))
        self.send("ban", sid)
        self.sql_queue.append(package(self._sqlInsertBan, self.userlist[sid], reason, time.time(), modName))
        self.sqlAction.set()

    # Perform pending pending leader actions.
    # This should _NOT_ be called outside the main SynchtubeClient's thread
    def _leaderActions(self):
        if self.stthread != threading.currentThread():
            raise Exception("_leaderActions should not be called outside the Synchtube thread")
        while len(self.leader_queue) > 0:
            self.leader_queue.popleft()()
        if self.pendingToss and not self.deferredToss:
            self.tossLeader()

    # Give leader to another user using their sid(session id)
    # This command does not ensure the client is currently leader before executing
    def _tossLeader(self, sid):
        # Short sleep to give Synchtube some time to react
        # TODO -- Confirm whether this fixes the rare bug I was getting
        time.sleep(0.05)
        self.pendingToss = False
        self.notGivingBack = False
        self.tossing = True
        self.unToss = package(self.send, "takeleader", self.sid)
        self.send("toss", sid)

    def sendHeartBeat(self):
        self.send()

    def _getConfig(self):
        config = ConfigParser.RawConfigParser()
        config.read("naoko.conf")
        self.room = config.get("naoko", "room")
        self.room_pw = config.get("naoko", "room_pw")
        self.name = config.get("naoko", "nick")
        self.pw   = config.get("naoko", "pass")
        self.hmod_admin = config.get("naoko", "hmod_admin").lower()
        self.spam_interval = float(config.get("naoko", "spam_interval"))
        self.server = config.get("naoko", "irc_server")
        self.channel = config.get("naoko", "irc_channel")
        self.irc_nick = config.get("naoko", "irc_nick")
        self.ircpw = config.get("naoko", "irc_pass")
        self.dbfile = config.get("naoko", "db_file")
        self.dbinit = config.get("naoko", "db_init")
        self.apikeys = Object()
        self.apikeys.mst_id = config.get("naoko", "mst_client_id")
        self.apikeys.mst_secret = config.get("naoko", "mst_client_secret")
        self.apikeys.sc_id = config.get("naoko", "sc_client_id")
        self.apikeys.wf_id = config.get("naoko", "wolfram_id")
