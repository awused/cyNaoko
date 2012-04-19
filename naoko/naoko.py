#!/usr/bin/env python
# Naoko - A prototype synchtube bot
# Written in 2011 by Falaina falaina@falaina.net
# Forked and continued in 2012 by Desuwa
# To the extent possible under law, the author(s) have dedicated all
# copyright and related and neighboring rights to this software to the
# public domain worldwide. This software is distributed without any
# warranty.  You should have received a copy of the CC0 Public Domain
# Dedication along with this software. If not, see
# <http://creativecommons.org/publicdomain/zero/1.0/>.

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

try:
    from lib.cbclient import CleverbotClient
except ImportError:
    class CleverbotClient(object):
        pass

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
        self.logger = logging.getLogger("stclient")
        self.logger.setLevel(LOG_LEVEL)
        self.chat_logger = logging.getLogger("stclient.chat")
        self.chat_logger.setLevel(LOG_LEVEL)
        self.irc_logger = logging.getLogger("stclient.irc")
        self.irc_logger.setLevel(LOG_LEVEL)
        self.pending = {}
        self.leader_sid = None
        self.pendingToss = False
        self.muted = False
        self.banTracker = {}
        
        # Keep all the state information together
        self.state = Object()
        self.state.state = 0
        self.state.current = None
        self.state.time = 0
        self.state.pauseTime = -1.0
        self.state.dur = 0
        self.state.previous = None
        self.state.reason = None

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
        room_req = Request("http://www.synchtube.com/r/%s" % (self.room), headers=self._HEADERS)
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

        self.chatthread = threading.Thread(target=Naoko._chatloop, args=[self])
        self.chatthread.start()

        self.stthread = threading.Thread(target=Naoko._stloop, args=[self])
        self.stthread.start()

        self.playthread = threading.Thread(target=Naoko._playloop, args=[self])
        self.playthread.start()

        self.apithread = threading.Thread(target=Naoko._apiloop, args=[self])
        self.apithread.start()

        if self.irc_nick:
            self.ircthread = threading.Thread(target=Naoko._ircloop, args=[self])
            self.ircthread.start()

        if self.dbfile:
            self.sqlthread = threading.Thread(target=Naoko._sqlloop, args=[self])
            self.sqlthread.start()

        # Start a REPL on port 5001. Only accept connections from localhost
        # and expose ourself as 'naoko' in the REPL's local scope
        # WARNING: THE REPL WILL REDIRECT STDOUT AND STDERR.
        # the logger will still go to the the launching terminals
        # stdout/stderr, however print statements will probably be rerouted
        # to the socket.
        self.repl = Repl(port=5001, host='localhost', locals={'naoko': self})

        while not self.closing.wait(5):
            # Sleeping first lets everything get initialized
            # The parent process will wait
            try:
                status = self.stthread.isAlive()
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
            self.logger.debug("Status is %s", status)
            if status and pipe:
                pipe.send("HEALTHY")
            if not status:
                self.close()
        else:
            if pipe:
                self.logger.warn("Restarting")
                pipe.send("RESTART")

    # Responsible for listening to ST chat and responding with appropriate actions
    def _stloop(self):
        client = self.client
        client.connect()
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
                fn(st_type, arg)
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
        else:
            self.logger.info("IRC Loop Closed")
            self.close()

    # Responsible for sending chat messages to IRC and Synchtube
    # Only the $status command and error messages should send a chat message to Synchtube or IRC outside this thread
    def _chatloop(self):
        while not self.closing.isSet():
            if self.muted:
                self.irc_queue.clear()
                self.st_queue.clear()
            else:
                if len(self.irc_queue) > 0:
                    self.ircclient.sendMsg(self.irc_queue.popleft())
                if len(self.st_queue) > 0:
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
                self.enqueueMsg("Unknown video playing, skipping")
                self.nextVideo()
                self.state.state = -1
                sleepTime = 60
            if self.state.reason:
                self.enqueueMsg(self.state.reason)
                self.state.reason = None
                self.nextVideo()
                self.state.state = -1
                sleepTime = 60
            # If the video is paused, unpause it
            if self.state.state == 2:
                unpause = 0
                if not self.state.pauseTime < 0:
                    unpause = self.state.pauseTime - (self.state.time / 1000)
                self.pauseTime = -1.0
                self.logger.info("Unpausing video %f seconds from the beginning" % (unpause))
                self.send("s", [1, unpause])
                sleepTime = 60
            if self.state.state == 0:
                if not self.leading.isSet(): continue
                self.send("s", [1,0])
                sleepTime = 60
            self.logger.debug("Waiting %f seconds for the end of the video" % (sleepTime))
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
        self.sql_queue = deque()
        self.dbclient = client = NaokoDB(self.dbfile, initscript)
        self.last_random = time.time()
        self.sql_queue = deque()
        while self.sqlAction.wait():
            if self.closing.isSet(): break
            self.sqlAction.clear()
            while len(self.sql_queue) > 0:
                self.sql_queue.popleft()()
        self.logger.info("SQL Loop Closed")

    # This loop is responsible for dealing with all external APIs
    # This includes validating Youtube videos and any future functionality
    def _apiloop(self):
        while self.apiAction.wait():
            if self.closing.isSet(): break
            self.apiAction.clear()
            while len(self.api_queue) > 0:
                self.api_queue.popleft()()
        self.logger.info("API Loop Closed")

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
                         "initdone"         : self.ignore,
                         "clear"            : self.clear}

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
                                "addrandom"         : self.addRandom,
                                "purge"             : self.purge,
                                "cleverbot"         : self.cleverbot,
                                "translate"         : self.translate}

    def _initIRCCommandHandlers(self):
        self.ircCommandHandlers = {"status"            : self.status,
                                   "choose"            : self.choose,
                                   "ask"               : self.ask,
                                   "8ball"             : self.eightBall,
                                   "steak"             : self.steak,
                                   "d"                 : self.dice,
                                   "dice"              : self.dice,
                                   "addrandom"         : self.addRandom,
                                   "cleverbot"         : self.cleverbot,
                                   "translate"         : self.translate}

    # Handle chat commands from both IRC and Synchtube
    def chatCommand(self, user, msg, irc=False):
        if len(msg) == 0 or  msg[0] != '$': return
        
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



    def nextVideo(self):
        self.vidLock.acquire()
        videoIndex = self.getVideoIndexById(self.state.current)
        if videoIndex == None:
            videoIndex = -1
        if len(self.vidlist) == 0:
            self.sendChat("Video list is empty, restarting.")
            self.close()
        videoIndex = (videoIndex + 1) % len(self.vidlist)
        if len(self.vidlist) > 1:
            self.state.previous = self.state.current
        else:
            self.state.previous = None
        self.logger.debug("Advancing to next video [%s]", self.vidlist[videoIndex])
        self.state.time = int(round(time.time() * 1000))
        self.send("s", [2])
        self.send("pm", self.vidlist[videoIndex].v_sid)
        self.enqueueMsg("Playing: %s" % (self.filterString(self.vidlist[videoIndex].vidinfo.title)[1]))
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
        if self.irc_nick:
            self.ircclient.close()

    # Bans a user for changing to an invalid name
    def nameBan(self, sid):
        if self.pending.has_key(sid): return
        self.pending[sid] = True
        user = self.userlist[sid]
        self.logger.info("Attempted ban of %s for invalid characters in name", user.nick)
        reason = "Name [%s] contains illegal characters" % user.nick
        def banUser():
            self._banUser(sid, reason)
        self.asLeader(banUser)
    
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

    def asLeader(self, action=None, giveBack=True):
        self.leader_queue.append(action)
        if self.leader_sid and self.leader_sid != self.sid and giveBack and not self.pendingToss:
            oldLeader = self.leader_sid
            def tossLeader():
                self._tossLeader(oldLeader)
            self.pendingToss = True
            self.tossLeader = tossLeader
        if self.room_info["tv?"] and giveBack and not self.pendingToss:
            def turnOnTV():
                self.send("turnon_tv")
            self.pendingToss = True
            self.tossLeader = turnOnTV
        self.takeLeader()

    def changeLeader(self, sid):
        if sid == self.leader_sid: return
        if sid == self.sid:
            self.takeLeader()
            return
        def tossLeader():
            self._tossLeader(sid)
        self.pendingToss = True
        self.tossLeader = tossLeader
        self.takeLeader()

    # Checks the currently playing video against a provided API
    def checkVideo(self, vidinfo):
        if not self.checkVideoId(vidinfo):
            self.invalidVideo("Invalid video ID.")
            return
            
        def check():
            self.invalidVideo(self._checkVideo(vidinfo))
        self.api_queue.append(check)
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
            if self.banTracker[user.nick] >= 3:
                def banUser():
                    self._banUser(user.sid, reason)
                self.asLeader(banUser)
            else:
                def kickUser():
                    self._kickUser(user.sid, reason)
                self.asLeader(kickUser)

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

    def changeMedia(self, tag, data):
        self.logger.info("Change media: %s" % (data))
        self.state.current = data[0]
        self.state.previous = None
        # Prevent her from skipping something she does not recognize, like a livestream.
        # HOWEVER, this will require a mod to tell her to skip before DEFAULT_WAIT seconds.
        self.state.dur = DEFAULT_WAIT
        v = data[1]
        v.append(None)
        v.append(None)
        v = v[:len(SynchtubeVidInfo._fields)]
        v[2] = self.filterString(v[2])[1]
        vi = SynchtubeVidInfo(*v)
        self.checkVideo(vi)
        self.changeState(tag, data[2])

    def playlist(self, tag, data):
        self.clear(tag, None)
        for v in data:
            self._addVideo(v, False)
        #self.logger.debug(pprint(self.vidlist))

    def clear(self, tag, data):
        self.vidLock.acquire()
        self.vidlist = []
        self.vidLock.release()

    def shuffle(self, tag, data):
        self._shuffle(data)

    def changeState(self, tag, data):
        self.logger.debug("State is %s %s", tag, data)
        if data == None:
            # Just assume whatever is loaded is playing correctly
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
        if self.leading.isSet() and (not self.state.previous == None) and (not self.getVideoIndexById(self.state.previous) == None):
            self.send("rm", self.state.previous)
        self.state.previous = None
        self.state.current = data[1]
        index = self.getVideoIndexById(self.state.current)
        if index == None:
            self.sendChat("Unexpected video, restarting.")
            self.close()
            return
        self.state.dur = self.vidlist[index].vidinfo.dur
        self.checkVideo(self.vidlist[index].vidinfo)
        self.changeState(tag, data[2])
        self.logger.debug("Playing %s %s", tag, data)

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
        if user.nickChanges > 3 or (user.nickChanges > 0 and not nick == oldnick):
            if self.pending.has_key(sid) or user.mod or user.sid == self.sid:
                return
            else:
                # Only a script/bot can change nicks multiple times
                self.pending[sid] = True
                self.logger.info("Attempted ban of %s for %d nick changes", (user.nick, user.nickChanges))
                reason = "%s changed names %d times" % (user.nick, user.nickChanges)
                def banUser():
                    self._banUser(sid, reason)
                self.asLeader(banUser)
        else:
            self.userlist[sid] = user._replace(nickChanges=user.nickChanges+1)

    def addUser(self, tag, data):
        # add_user and users data are similar aside from users having
        # a name field at idx 1
        userinfo = data[:]
        userinfo.insert(1, 'unnamed')
        self._addUser(userinfo)

    def remUser(self, tag, data):
        try:
            del self.userlist[data]
            if self.pending.has_key(data):
                del self.pending[data]
        except KeyError:
            self.logger.exception("Failure to delete user %s from %s", data, self.userlist)

    def users(self, tag, data):
        for u in data:
            self._addUser(u)

    def selfInfo(self, tag, data):
        self._addUser(data)
        self.sid = data[0]
        if not self.pw:
            self.send("nick", self.name)

    def roomSetting(self, tag, data):
        self.room_info[tag] = data
        if tag == "tv?" and self.room_info["tv?"]:
            self.leader_sid = None
            self.leading.clear()

    def takeLeader(self):
        if self.sid == self.leader_sid:
            self._leaderActions()
            return
        if self.room_info["tv?"]:
            self.send("turnoff_tv")
        else:
            self.send("takeleader", self.sid)

    def chat(self, tag, data):
        sid = data[0]
        user = self.userlist[sid]
        msg = data[1]
        self.chat_logger.info("%s: %r" , user.nick, msg)

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
        elif re.search(r"(synchtube\.com\/r|synchtu\.be\/)", msg): 
            self.logger.info("Attempted kick/ban of %s for blacklisted phrase", user.nick)
            reason = "%s sent a blacklisted message" % (user.nick)
            self.chatKick(user, reason)
    
    def leader(self, tag, data):
        self.leader_sid = data
        if self.leader_sid == self.sid:
            toss = self.pendingToss
            self._leaderActions()
            if not toss:
                self.leading.set()
        else:
            self.leading.clear()
        self.logger.debug("Leader is %s", self.userlist[data])

    # Command handlers for commands that users can type in Synchtube chat
    # All of them receive input in the form (command, user, data)
    # Where command is the typed command, user is the user who sent the message
    # and data is everything following the command in the chat message

    def skip(self, command, user, data):
        if not user.mod: return
        # Due to the complexities of switching videos she does not give back the leader after this
        # TODO - Make it so she does
        self.asLeader(self.nextVideo, False)

    def mute(self, command, user, data):
        if user.mod:
            self.muted = True

    def unmute(self, command, user, data):
        if user.mod:
            self.muted = False

    def steal(self, command, user, data):
        if not user.mod: return
        self.changeLeader(user.sid)

    def makeLeader(self, command, user, data):
        if not user.mod: return
        args = data.split(' ', 1)
        target = self.getUserByNick(args[0])
        self.logger.info("Requested mod change to %s by %s", target, user)
        if not target: return
        self.changeLeader(target.sid)

    def dice(self, command, user, data):
        if not data: return
        params = data.strip().split()
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
        if not user.mod: return
        target = data.strip()
        if target:
            target = self.filterString(data, True)[1]
        else:
            target = user.nick
        target = target.lower()
        videoIndex = self.getVideoIndexById(self.state.current)
        i = len(self.vidlist) - 1
        while i > videoIndex:
            if self.vidlist[i].nick.lower() == target:
                break
            i -= 1
        if i == videoIndex: return
        if i > videoIndex + 1:
            output = dict()
            output["id"] = self.vidlist[i].v_sid
            if videoIndex >= 0:
                output["after"] = self.vidlist[videoIndex].v_sid
            def move():
               self.send("mm", output)
               self.moveMedia("mm", output)
            self.asLeader(move)

    # Cleans all the videos above the currently playing video
    def cleanList(self, command, user, data):
        if not user.mod: return
        videoIndex = self.getVideoIndexById(self.state.current)
        if videoIndex > 0:
            self.logger.debug("Cleaning %d Videos", videoIndex)
            def clean():
                i = 0
                while i < videoIndex:
                   self.send("rm", self.vidlist[i].v_sid)
                   i+=1
            self.asLeader(clean)

    # Clears any duplicate videos from the list
    def cleanDuplicates(self, command, user, data):
        if not user.mod: return
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
        if len(kill) > 0:
            def clean():
                for x in kill:
                    self.send("rm", x)
            self.asLeader(clean)

    # Adds random videos from the database
    def addRandom(self, command, user, data):
        if not (user.mod or len(self.vidlist) <= 10): return
        num = None
        try:
            num = int(data.strip())
        except (TypeError, ValueError) as e:
            self.logger.debug(e)
        # Default to 5, which is also the most non-mods can add at once 
        if num is None:
            num = 5
        if num > 20 or (not user.mod and num > 5): return
        def add():
            self._addRandom(num)
        self.sql_queue.append(add)
        self.sqlAction.set()
    
    # Retrieve the latest bans for the specified user
    def lastBans(self, command, user, data):
        params = data.split()
        target = user.nick
        num = 1
        if len(params) > 0 and user.mod:
            target = params[0]
            num = 3
            if len(params) > 1:
                try:
                    num = int(params[1])
                except (TypeError, ValueError) as e:
                    self.logger.debug(e)
        if num > 5 or num < 1: return
        def fetchBans():
            self._lastBans(target, num)
        self.sql_queue.append(fetchBans)
        self.sqlAction.set()

    # Deletes the last video added by the provided user
    def delete(self, command, user, data):
        target = self.filterString(data, True)[1]
        # Non-mods can only delete their own videos
        # This does prevent unregistered users from deleting their own videos
        if not user.mod and not target == "": return
        if target == "":
            target = user.nick
        if user.mod and data.lower() == "-unnamed":
            target = ""
        target = target.lower()
        videoIndex = self.getVideoIndexById(self.state.current)
        i = len(self.vidlist) - 1
        while i > videoIndex:
            if self.vidlist[i].nick.lower() == target:
                break
            i -= 1
        if i == videoIndex: return
        def clean():
            self.send("rm", self.vidlist[i].v_sid)
        self.asLeader(clean)
    
    # Deletes all the videos posted by the specified user
    def purge(self, command, user, data):
        if not user.mod: return
        target = self.getUserByNick(data)
        if target == None:
            target = self.filterString(data, True)[1].lower()
            # Don't default to purging unregistered users
            if target == '':
                return
        else:
            if target.mod: return
            target = target.nick.lower()
        if user.mod and data.lower() == "-unnamed":
            target = ''
        kill = []
        for v in self.vidlist:
            if v.nick.lower() == target and not v.v_sid == self.state.current:
                kill.append(v.v_sid)
        if len(kill) > 0:
            def purge():
                for x in kill:
                    self.send("rm", x)
            self.asLeader(purge)

    def lock(self, command, user, data):
        if not user.mod: return
        if self.room_info["lock?"] == (command == "lock"): return
        def changeLock():
            self.send("lock?", command == "lock")
        self.asLeader(changeLock)

    def status(self, command, user, data):
        msg = "Status = ["
        if not self.muted:
            msg += "Not "
        msg += "Muted]"
        self.sendChat(msg)
        if self.irc_nick:
            self.ircclient.sendMsg(msg)

    def restart(self, command, user, data):
        if user.mod:
            self.close()

    def choose(self, command, user, data):
        if not data: return
        choices = data.strip()
        if len(choices) == 0: return
        self.enqueueMsg("[Choose: %s] %s" % (choices, random.choice(choices.split())))

    def steak(self, command, user, data):
        self.enqueueMsg("There is no steak.")

    def ask(self, command, user, data):
        if not data: return
        question = data.strip()
        if len(question) == 0: return
        self.enqueueMsg("[%s] %s" % (question, random.choice(["Yes", "No"])))

    def eightBall(self, command, user, data):
        if not data: return
        question = data.strip()
        if len(question) == 0: return
        self.enqueueMsg("[8ball %s] %s" % (user.nick, random.choice(eight_choices)))

    # Kick a single user by their name.
    # Two special arguments -unnamed and -unregistered.
    # Those commands kick all unnammed and unregistered users. 
    def kick(self, command, user, data):
        if not user.mod or not data: return
        args = data.split(' ', 1)

        if args[0].lower() == "-unnamed":
            kicks = []
            for u in self.userlist:
                if self.userlist[u].nick == "unnamed":
                    kicks.append(u)
            def kickUsers():
                for k in kicks:
                    self._kickUser(k, sendMessage=False)
            self.logger.info("Kicking %d unnamed users requested by %s", len(kicks), user.nick)
            self.asLeader(kickUsers)
            return

        if args[0].lower() == "-unregistered":
            kicks = []
            for u in self.userlist:
                # Synchtube doesn't properly set user.auth in some cases.
                # A more reliable method without false positives is user.uid.
                if self.userlist[u].uid == None:
                    kicks.append(u)
            def kickUsers():
                for k in kicks:
                    self._kickUser(k, sendMessage=False)
            self.logger.info("Kicking %d unregistered users requested by %s", len(kicks), user.nick)
            self.asLeader(kickUsers)
            return

        target = self.getUserByNick(args[0])
        if not target or target.mod: return
        self.logger.info("Kick Target %s Requestor %s", target.nick, user.nick)
        if len(args) > 1:
            def kickUser():
                self._kickUser(target.sid, args[1], False)
            self.asLeader(kickUser)
        else:
            def kickUser():
                self._kickUser(target.sid, sendMessage=False)
            self.asLeader(kickUser)

    def ban(self, command, user, data):
        if not user.mod or not data: return
        args = data.split(' ', 1)
        target = self.getUserByNick(args[0])
        if not target or target.mod: return
        self.logger.info("Ban Target %s Requestor %s", target, user)
        if len(args) > 1:
            def banUser():
                self._banUser(target.sid, args[1], modName=user.nick)
            self.asLeader(banUser)
        else:
            def banUser():
                self._banUser(target.sid, modName=user.nick)
            self.asLeader(banUser)

    def cleverbot(self, command, user, data):
        if not hasattr(self.cbclient, "cleverbot"): return
        text = data.strip()
        if text:
            def clever():
                self.enqueueMsg("[%s] %s" % (user.nick, self.cbclient.cleverbot(text)))
            self.api_queue.append(clever)
            self.apiAction.set()

    # Translate a given string.
    # Defaults to translating to English and detecting the source language.
    # If the string starts with [src->dst], [src>dst], or [dst] where src and dst
    # are ISO two letter language code it will attempt to translate using those codes.
    def translate(self, command, user, data):
        m = re.match("^(\[(([a-zA-Z]{2})|([a-zA-Z]{2})-?>([a-zA-Z]{2}))\] ?)?(.+)$", data.strip())
        if not m: return
        g = m.groups()
        src = g[3] or None
        dst = g[2] or g[4] or "en"
        def trans():
            out = self.apiclient.translate(g[5], src, dst)
            if out:
                if not out == -1:
                    self.enqueueMsg("[%s] %s" % (dst.lower(), out))
            else:
                self.enqueueMsg("Translate Query Failed")
        self.api_queue.append(trans)
        self.apiAction.set()

    # Two functions that search the lists in an efficient manner

    def getUserByNick(self, nick):
        name = self.filterString(nick, True)[1].lower()
        try: return (u for u in self.userlist.itervalues() if u.nick.lower() == name).next()
        except StopIteration: return None

    def getVideoIndexById(self, vid):
        try: return (idx for idx, ele in enumerate(self.vidlist) if ele.v_sid == vid).next()
        except StopIteration: return -1

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
            # Synchtube can't handle code points above 0xfff
            valid = o > 31 and o != 127 and not (o >= 0xd800 and o <= 0xdfff) and o <= 0xffff
            if (not isNick) and valid:
                output.append(c)
        return (len(output) == len(value) and len , "".join(output))

    # Returns whether or not a video id could possibly be valid
    # Guards against possible attacks and annoyances
    def checkVideoId(self, vi):
        if type(vi.vid) is int:
            return True
        if type(vi.vid) is not str and type(vi.vid) is not unicode:
            return False
        if vi.site == "yt":
            return re.match("^[a-zA-Z0-9\-_]+$", vi.vid)
        elif vi.site == "dm":
            return re.match("^[a-zA-A0-9]+$", vi.vid)
        elif vi.site == "sc" or vi.site == "vm":
            return re.match("^[0-9]+$", vi.vid)
        else:
            return True

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
        # As found elsewhere, user.auth is unreliable
        if user.uid:
            auth = 1
        self.db_logger.debug("Inserting %s into bans", (reason, auth, user.nick, int(round(time*1000)), modName))
        self.dbclient.execute("INSERT INTO bans VALUES(?, ?, ?, ?, ?)", (reason, auth, user.nick, int(round(time*1000)), modName))
        self.dbclient.commit()

    # Checks to see if the current video isn't invalid, blocked, or removed
    # Also updates the duration if necessary to prevent certain types of annoying attacks on the room
    def _checkVideo(self, vi):
        data = self.apiclient.getVideoInfo(vi.site, vi.vid)
        if data:
            if data != "Unknown" and data != "TODO":
                title, dur, embed = data
                if not embed:
                    self.logger.debug("Embedding disabled.")
                    return "Embedding disabled." 
                # When someone has manually added a video with an incorrect duration
                elif self.state.dur != dur:
                    self.logger.debug("Duration mismatch: %d expected, %d actual." % (self.state.dur, dur))
                    self.state.dur = dur
                    self.playerAction.set()
            return None
        return "Invalid video."

    # Validates a video before inserting it into the database.
    # Will correct invalid durations and titles for Youtube videos.
    # This makes SQL inserts dependent on the external API.
    # TODO -- Maybe -- detect if there's a communication error/timeout and let the insertion go through anyway
    def _validateVideoSQLInsert(self, v):
        if str(v.uid) == self.userid: return
        vi = v.vidinfo
        dur = vi.dur
        title = vi.title
        valid = self.checkVideoId(vi)

        if valid:
            data = self.apiclient.getVideoInfo(vi.site, vi.vid)
            if data and data != "Unknown":
                if data != "TODO":
                    title, dur, valid = data
            else:
                # Do not store the video if it is invalid or from an unknown website.
                valid = False
        if not valid:
            # The video is invalid, don't insert it
            self.logger.debug("Invalid video, skipping SQL insert.")
            return
        # The insert the video using the retrieved title and duration
        # Trust the external APIs over Synchtube
        def insert():
            self._sqlInsertVideo(v, title, dur)
        self.sql_queue.append(insert)
        self.sqlAction.set()
    
    def _sqlInsertVideo(self, v, title, dur):
        vi = v.vidinfo
        self.db_logger.debug("Inserting %s into videos", (vi.site, vi.vid, dur * 1000, title))
        self.db_logger.debug("Inserting %s into video_stats", (vi.site, vi.vid, v.nick))
        self.dbclient.execute("INSERT OR IGNORE INTO videos VALUES(?, ?, ?, ?)", (vi.site, vi.vid, dur * 1000, title))
        self.dbclient.execute("INSERT INTO video_stats VALUES(?, ?, ?)", (vi.site, vi.vid, v.nick))
        self.dbclient.commit()
        
    def _lastBans(self, nick, num):
        if not nick == "-all":
            rows = self.dbclient.fetch("SELECT timestamp, reason, mod FROM bans WHERE uname = ? COLLATE NOCASE ORDER BY timestamp DESC LIMIT ?", (nick, num))
            if len(rows) == 0:
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
            if len(rows) == 0:
                self.enqueueMsg("No recorded bans")
                return
            if num > 1:
                self.enqueueMsg("Last %d bans:" % (num,))
            else:
                self.enqueueMsg("Last ban:")
            for r in rows:
                self.enqueueMsg("%s - %s by %s - %s" % (r[2], datetime.fromtimestamp(r[0] / 1000).isoformat(' '), r[3], r[1]))

    def _addRandom(self, num):
        # Limit to once every 5 seconds
        if time.time() - self.last_random < 5: return
        self.last_random = time.time()
        self.logger.debug("Adding %d randomly selected videos", num)
        vids = self.dbclient.getVideos(num, ['type', 'id', 'title', 'duration_ms'], ('RANDOM()',))
        self.logger.debug("Retrieved %s", vids)
        for v in vids:
            self.send("am", [v[0], v[1], self.filterString(v[2])[1],"http://i.ytimg.com/vi/%s/default.jpg" % (v[1]), v[3]/1000])

    # Add the video described by v
    def _addVideo(self, v, sql=True):
        if self.stthread != threading.currentThread():
            raise Exception("_addVideo should not be called outside the Synchtube thread")
        v[0] = v[0][:len(SynchtubeVidInfo._fields)]
        v[0][2] = self.filterString(v[0][2])[1]
        v[0] = SynchtubeVidInfo(*v[0])
        v.append(None) # If an unregistered adds a video there is no name included
        v = v[:len(SynchtubeVideo._fields)]
        v[3] = self.filterString(v[3], True)[1]
        vid = SynchtubeVideo(*v)
        self.vidLock.acquire()
        self.vidlist.append(vid)
        self.vidLock.release()
        if sql:
            def check():
                self._validateVideoSQLInsert(vid)
            self.api_queue.append(check)
            self.apiAction.set()

    def _removeVideo(self, v):
        if self.stthread != threading.currentThread():
            raise Exception("_removeVideo should not be called outside the Synchtube thread")
        idx = self.getVideoIndexById(v)
        if idx >= 0:
            self.vidLock.acquire()
            self.vidlist.pop(idx)
            self.vidLock.release()

    def _moveVideo(self, v, after=None):
        if self.stthread != threading.currentThread():
            raise Exception("_moveVideo should not be called outside the Synchtube thread")
        self.vidLock.acquire()
        video = self.vidlist.pop(self.getVideoIndexById(v))
        pos = 0
        if after:
            pos = self.getVideoIndexById(after) + 1
        self.vidlist.insert(pos, video)
        self.vidLock.release()
        self.logger.debug("Inserted %s after %s", video, self.vidlist[pos - 1])

    # Kick user using their sid(session id)
    def _kickUser(self, sid, reason="Requested", sendMessage=True):
        if sendMessage:
            self.enqueueMsg("Kicked %s: (%s)" % (self.userlist[sid].nick, reason))
        self.send("kick", [sid, reason])

    # By default none of the functions use this.
    # Don't come crying to me if the bot bans the entire channel
    def _banUser(self, sid, reason="Requested", sendMessage=True, modName=None):
        if not modName:
            modName = self.nick
        if sendMessage:
            self.enqueueMsg("Banned %s: (%s)" % (self.userlist[sid].nick, reason))
        self.send("ban", sid)
        def insert():
            self._sqlInsertBan(self.userlist[sid], reason, time.time(), modName)
        self.sql_queue.append(insert)
        self.sqlAction.set()

    # Perform pending pending leader actions.
    # This should _NOT_ be called outside the main SynchtubeClient's thread
    def _leaderActions(self):
        if self.stthread != threading.currentThread():
            raise Exception("_leaderActions should not be called outside the Synchtube thread")
        while len(self.leader_queue) > 0:
            self.leader_queue.popleft()()
        if self.pendingToss:
            self.tossLeader()
            self.pendingToss = False

    # Give leader to another user using their sid(session id)
    # This command does not ensure the client is currently leader before executing
    def _tossLeader(self, sid):
        # Short sleep to give Synchtube some time to react
        # TODO -- Confirm whether this fixes the rare bug I was getting
        time.sleep(0.05)
        self.send("toss", sid)

    def sendHeartBeat(self):
        self.send()

    def _getConfig(self):
        config = ConfigParser.RawConfigParser()
        config.read("naoko.conf")
        self.room = config.get('naoko', 'room')
        self.name = config.get('naoko', 'nick')
        self.pw   = config.get('naoko', 'pass')
        self.spam_interval = float(config.get('naoko', 'spam_interval'))
        self.server = config.get('naoko', 'irc_server')
        self.channel = config.get('naoko', 'irc_channel')
        self.irc_nick = config.get('naoko', 'irc_nick')
        self.ircpw = config.get('naoko', 'irc_pass')
        self.dbfile = config.get('naoko', 'db_file')
        self.dbinit = config.get('naoko', 'db_init')
        self.apikeys = Object()
        self.apikeys.mst_id = config.get('naoko', 'mst_client_id')
        self.apikeys.mst_secret = config.get('naoko', 'mst_client_secret')
