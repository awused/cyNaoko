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
import urllib, urlparse
import re
from urllib2 import Request, urlopen
from collections import namedtuple, deque
import ConfigParser
import random

from settings import *

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

# Implementation of WebSocket client as per draft-ietf-hybi-thewebsocketprotocol-00
# http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-00
class WebSocket(object):
    version = 0
    # Socket states
    _DISCONNECTED = 0
    _CONNECTING = 1
    _CONNECTED  = 2

    def __init__(self, host, port, resource, origin=None):
        if not origin:
            origin = "http://" + host
        self.host = host
        self.port = port
        self.value = ''
        self.resource = resource
        self.origin = origin
        self.state  = self._DISCONNECTED
        self.fields = {}
        self.field = ''
        self.last_byte = 0
        self.logger =logging.getLogger("websocket")
        self.logger.setLevel(logLevel)
        self.pkt_logger =logging.getLogger("websocket.pkt")
        self.pkt_logger.setLevel(logLevel)
        self.closing = False

    def handle_read(self):
        if state == self._CONNECTING:
            data = self.recv(1)
            if data == "\n":
                if self.last_byte == "\r":
                    self.fields[field] = value
                    self.field = ''
                    self.value = ''
                else:
                    print "Invalid Newline"
            elif data == ":":
                self.field = value
                self.value = ''
            else:
                value += data
            last_byte = data
        print repr(data)

    def _makeHeaders(self, key1, key2):
        self.headers = {'Upgrade'            : 'WebSocket',
                        'Connection'         : 'Upgrade',
                        'Host'               : self.host + ":" + str(self.port),
                        'Origin'             : self.origin,
                        'Sec-WebSocket-Key1' : key1,
                        'Sec-WebSocket-Key2' : key2}
        return self.headers

    def send(self, data):
        frame = '\x00' + data + '\xff'
        self.pkt_logger.debug("Sending frame: %r", frame)
        self.sock.sendall(frame)

    def createSecretKey(self):
        self.state = self._CONNECTING
        spaces = random.randint(1,12)
        max   = (2**32-1)/spaces
        number = random.randint(1, max+1)
        product = spaces * number
        key     = list(str(product))
        randomChrs = []
        #21. Insert between one and twelve random characters from the ranges
        #    U+0021 to U+002F and U+003A to U+007E into /key_1/ at random
        #    positions.
        for x in range(0x21,0x2F+1) + range(0x3A,0x7E+1):
            randomChrs.append(unichr(x))
        randomCnt = random.randint(1,12)

        for j in xrange(randomCnt):
            pos = random.randint(0, len(key)-1)
            key.insert(pos, random.choice(randomChrs))

        for j in xrange(spaces):
            pos = random.randint(1, len(key)-2)
            key.insert(pos, ' ')
        key = ''.join(key)
        return (number, key)

    def processFields(self):
        heading = ''
        value = []
        field = ''

        #Process response heading
        c = self.sock.recv(1)
        while c != "\n":
            heading += c
            c = self.sock.recv(1)
        self.logger.debug("Received response %s", heading)
        self.logger.debug("Processing Fields")
        while True:
            c = self.sock.recv(1)
            if c == "\n":
                if value[-1] == "\r":
                    value.pop()
                    self.fields[field] = "".join(value)
                    if len(value) == 0:
                        self.logger.debug("Received fields: ", self.fields)
                        return
                    field = ''
                    value = []
                else:
                    print "Invalid Newline"
            elif c == " " and value[-1] == ":":
                value.pop()
                field = "".join(value)
                value = []
            else:
                value.append(c)

    def handshake(self):
        (number1, key1) = self.createSecretKey()
        (number2, key2) = self.createSecretKey()
        number3 = random.getrandbits(63)
        key3    = struct.pack(">q", number3);
        headers = self._makeHeaders(key1, key2)
        headers_str = ""
        for k in headers.keys():
            headers_str += "%s: %s\r\n" % (k, headers[k])
        headers_str += "\r\n"
        get_str = "GET " + self.resource + " HTTP/1.1\r\n"

        self.logger.info("Connecting to %s", self.host)
        self.sock = sock = socket.socket()
        sock.settimeout(TIMEOUT)
        sock.connect((self.host, self.port))

        self.pkt_logger.debug("Sending %s", get_str)
        sock.sendall(get_str)

        self.pkt_logger.debug("Sending %s", headers_str)
        sock.sendall(headers_str)

        self.pkt_logger.debug("Sending key3: %s", repr(key3))
        sock.sendall(key3)

        self.processFields();

        actual = sock.recv(16)
        challenge = struct.pack('>IIq',number1,number2, number3)
        expected  = hashlib.md5(challenge).digest()
        assert repr(actual) == repr(expected), "Challenged failed. \n\tExpected: %s\n\tActual: %s" %(repr(actual), repr(expected))
        self.logger.info("Connected to %s", self.host)

    def readFrame(self):
        frame_type = self.sock.recv(1)
        if len(frame_type) is 0:
            raise Exception("Socket closed")
        frame_type = ord(frame_type)
        if (frame_type & 0x80) == 0x80: # Special frame type?
            raise Exception("No clue")
        frame = []
        while not self.closing:
            c = self.sock.recv(1)
            if c == '\xff':
                frame = "".join(frame)
                self.pkt_logger.debug("Received frame: %r", frame)
                return frame
            else:
                # Filter out invalid characters
                if ord(c) > 31 and ord(c) != 127:
                    frame.append(c)
        else:
            self.sock.close()

    def recvFrame(self):
        return self.readFrame()

    def close(self):
        self.sock.settimeout(0)
        self.closing = True

# Simple Record Types for variable synchtube constructs
SynchtubeUser = namedtuple('SynchtubeUser',
                           ['sid', 'nick', 'uid', 'auth', 'ava', 'lead', 'mod', 'karma', 'msgs', 'nickChange'])

SynchtubeVidInfo = namedtuple('SynchtubeVidInfo',
                            ['site', 'vid', 'title', 'thumb', 'dur'])

SynchtubeVideo = namedtuple('SynchtubeVideo',
                              ['vidinfo', 'v_sid', 'uid', 'nick'])

# SocketIO "client" built on top of a raw underlying WebSocket
# Implemented as per https://github.com/LearnBoost/socket.io-spec
class SocketIOClient(object):
    protocol = 1

    # Socket IO Message types. There are more, but these are the bare minimum.
    HEARTBEAT = "2"
    MESSAGE   = "3"

    def __init__(self, host, port, resource="socket.io", params={}, https=False):
        self.host = host
        self.port = port
        self.resource = resource
        self.params = params
        self.logger = logging.getLogger("socketio")
        self.logger.setLevel(logLevel)
        self.pkt_logger = logging.getLogger("socketio.pkt")
        self.pkt_logger.setLevel(logLevel)
        self.ip = socket.gethostbyname(socket.gethostname())
        self.sched = sched.scheduler(time.time, time.sleep)
        self.heartBeatEvent = False
        if https:
            self.proto = "https://"
        else:
            self.proto = "http://"
        self.url = "%s%s:%s/%s/%s/?%s" % (self.proto,
                                          host,
                                          port,
                                          resource,
                                          self.protocol,
                                          urllib.urlencode(params))
        self.hbthread = threading.Thread(target=SocketIOClient._heartbeat, args=[self])

    def _heartbeat(self):
        self.sendHeartBeat(5)
        self.sched.run()

    def __getSessionInfo(self):
        stinfo = urllib.urlopen(self.url).read()
        self.sock_info = dict(zip(['sid', 'hb', 'to', 'xports'],
                                  urllib.urlopen(self.url).read().split(':')))
        self.sid = self.sock_info['sid']
        return self.sid

    def close(self):
        if self.heartBeatEvent:
            self.sched.cancel(self.heartBeatEvent)
            self.logger.info ("Heartbeats Stopped")
        self.ws.close()


    def send(self, msg_type=3, sock_id='', end_pt='', data=''):
        buf = "%s:%s:%s:%s" % (msg_type, sock_id, end_pt, data)
        #self.pkt_logger.debug("Sending %s", buf)
        self.ws.send(buf)

    def sendHeartBeat(self, next_sec=None):
        if next_sec:
            self.heartBeatEvent = self.sched.enter(next_sec, 1, SocketIOClient.sendHeartBeat, [self, next_sec])
        if not self.ws:
            raise Exception("No WebSocket")
        now = time.time()
        hb_diff = now - self.last_hb
        self.pkt_logger.debug("Time since last heartbeat %.3f", hb_diff)
        if hb_diff > TIMEOUT:
            raise Exception("Socket.IO Timeout, %.3f since last heartbeat" % (hb_diff))
        self.send(2)
        self.send(3, data='{}')

    def connect(self):
        sid =  self.__getSessionInfo()
        self.logger.debug("Received session ID: %s", sid)
        sock_resource = "/%s/%s/%s/%s?%s" % ("socket.io",
                                             1,
                                             "websocket",
                                             sid,
                                             urllib.urlencode(self.params))
        self.ws = WebSocket(self.host, self.port, sock_resource)
        self.ws.handshake()
        self.last_hb = time.time()
        self.hbthread.start()

    def recvMessage(self):
        while True:
            frame = self.ws.recvFrame()
            (msg_type, data) =  self.processFrame(frame)
            if msg_type == self.MESSAGE:
                return data

    def processFrame(self, frame):
        frame = frame.split(':', 3)
        msg_type = frame[0]
        if len(frame) > 3:
            data = frame[3]
        else:
            data = None
        if msg_type == self.HEARTBEAT:
            self.last_hb = time.time()
            self.sendHeartBeat()
        return (msg_type, data)

# Generic object that can be assigned attributes
class Object(object):
    pass

#Basic IRC client
#Built upon the instructions provided by http://wiki.shellium.org/w/Writing_an_IRC_bot_in_Python
class IRCClient(object):
    def __init__ (self, server, channel, nick, pw):
        # NOTE: Doesn't currently confirm any joins, nick changes, or identifies
        # If an IRC name is set and this fails, the entire bot will restart
        # IRC pings can be unpredictable, so a timeout (except when closing) isn't practical
        self.logger = logging.getLogger("ircclient")
        self.logger.setLevel(logLevel)
        self.server = server
        self.channel = channel
        self.nick = nick

        #self.logger.debug ("%s %s %s %s", self.server, self.channel, self.nick, pw)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server, 6667)) # Here we connect to the server using port 6667
        self.send("USER "+ self.nick +" "+ self.nick +" "+ self.nick +" :"+ self.nick +"\n") # user authentication
        self.send("NICK "+ self.nick +"\n") # here we actually assign the nick to the bot
        if pw:
            self.send ("PRIVMSG nickserv :id " + pw + "\n")
        self.send ("JOIN " + self.channel + "\n")

    def ping (self):
        self.send ("PONG :pingis\n")

    def close (self):
        self.sock.settimeout(0)
        self.send ("QUIT :quit\n")
        self.sock.close()

    def sendmsg (self, msg):
        self.send("PRIVMSG " + self.channel + " :" + msg + "\n")

    def recvMessage (self):
        frame = self.sock.recv(2048)
        frame = frame.strip("\n\r")
        self.logger.debug ("Received IRC Frame %s", frame)
        return frame

    def send (self, msg):
        self.logger.debug ("IRC Send %s", msg.encode("utf-8"))
        self.sock.send (msg.encode("utf-8"))


# Synchtube  "client" built on top of a socket.io socket
# Synchtube messages are generally of the form:
#   ["TYPE", DATA]
# e.g., The self message (describes current client)
#   ["self" ["bbc2c922",22262,true,"jpg",false,true,21]]
# Which describes a particular connection for the user Naoko
# (uid 22262). The first field is the session identifier,
# second is uid, third is whether or not client is authenticated
# fourth is avatar type, and so on.
class SynchtubeClient(object):
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
        self.logger.setLevel(logLevel)
        self.chat_logger = logging.getLogger("stclient.chat")
        self.chat_logger.setLevel(logLevel)
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

        if self.pw:
            self.logger.info("Attempting to login")
            login_url = "http://www.synchtube.com/user/login"
            login_body = {'email' : self.name, 'password' : self.pw};
            login_data = urllib.urlencode(login_body).encode('utf-8')
            login_req = Request(login_url, data=login_data, headers=self._HEADERS)
            login_req.add_header('X-Requested-With', 'XMLHttpRequest')
            login_req.add_header('Content', 'XMLHttpRequest')
            login_res  = urlopen(login_req)
            login_res_headers = login_res.info()
            if(login_res_headers['Status'] != '200'):
                raise Exception("Could not login")

            if(login_res_headers.has_key('Set-Cookie')):
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
            if(config['room'].has_key('port')):
                self.port = config['room']['port']
            self.port = int(self.port)
            self.config_params = {'b' : self.st_build,
                                  'r' : config['room']['id'],
                                  'p' : self.port,
                                  't' : int (round(time.time()*1000)),
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
        self.playerAction = threading.Event()
        # Tracks whether she is leading
        # Is not triggered when she is going to give the leader position back or turn tv mode back on
        self.leading = threading.Event()
        self.irc_queue = deque(maxlen=0)

        self.chatthread = threading.Thread (target=SynchtubeClient._chatloop, args=[self])
        self.chatthread.start()

        self.stthread = threading.Thread (target=SynchtubeClient._stloop, args=[self])
        self.stthread.start()

        self.playthread = threading.Thread (target=SynchtubeClient._playloop, args=[self])
        self.playthread.start()

        if self.irc_nick:
            self.ircthread = threading.Thread(target=SynchtubeClient._ircloop, args=[self])
            self.ircthread.start()

        while not self.closing.wait(5):
            # Sleeping first lets everything get initialized
            # The parent process will wait
            try:
                status = self.stthread.isAlive()
                status = status and (not self.irc_nick or self.ircthread.isAlive())
                status = status and self.chatthread.isAlive()
                # Catch the case where the client is still connecting after 5 seconds
                status = status and (not self.client.heartBeatEvent or self.client.hbthread.isAlive())
                status = status and self.playthread.isAlive()
            except Exception as e:
                self.logger.error (e)
                status = False
            self.logger.debug ("Status is %s", status)
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
                print "Failed to parse", data
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
            self.logger.info ("Synchtube Loop Closed")
            self.close()

    # Responsible for communicating with IRC
    def _ircloop(self):
        time.sleep(5)
        self.logger.info("Starting IRC Client")
        self.ircclient = client = IRCClient(self.server, self.channel, self.irc_nick, self.ircpw)
        self.irc_queue = deque()
        while not self.closing.isSet():
            frame = deque(client.recvMessage().split("\n"))
            while len(frame) > 0:
                data = frame.popleft().strip("\r")
                if data.find("PING :") != -1:
                    client.ping()
                if data.find("PRIVMSG " + self.channel + " :") != -1:
                    name = data.split('!', 1)[0][1:]
                    msg = data[data.find("PRIVMSG " + self.channel + " :") + len("PRIVMSG " + self.channel + " :"):]
                    if not name == self.irc_nick:
                        self.st_queue.append("(" + name + ") " + msg)
                    self.logger.info ("IRC %s:%s", name, msg)
        else:
            self.logger.info ("IRC Loop Closed")
            self.close()

    # Responsible for sending chat messages to IRC and Synchtube
    # Only the $status command and error messages should send a chat message to Synchtube or IRC outside this thread
    def _chatloop(self):
        while not self.closing.isSet():
            if self.muted:
                self.irc_queue.clear()
                self.st_queue.clear()
            else:
                if len (self.irc_queue) > 0:
                    self.ircclient.sendmsg(self.irc_queue.popleft())
                if len (self.st_queue) > 0:
                    self.sendChat(self.st_queue.popleft())
            time.sleep(self.spam_interval)
        else:
            self.logger.info ("Chat Loop Closed")

    # Responsible for handling playback
    def _playloop(self):
        while True:
            self.leading.wait()
            if self.closing.isSet(): break
            if not self.state.current:
                self.enqueueMsg("Unknown video playing, skipping")
                self.nextVideo()
                time.sleep(0.05) # Sleep a bit, though yielding would be enough
                continue
            sleepTime = self.state.dur + (self.state.time / 1000) - time.time()
            if sleepTime < 0:
                sleepTime = 0
            # If the video is paused, unpause it
            if self.state.state == 2:
                unpause = 0
                if not self.state.pauseTime < 0:
                    unpause = self.state.pauseTime - (self.state.time / 1000)
                self.pauseTime = -1.0
                self.logger.info ("Unpausing video %f seconds from the beginning" % (unpause))
                self.send("s", [1, unpause])
                sleepTime = 60
            if self.state.state == 0:
                if not self.leading.isSet(): continue
                self.send ("s", [1,0])
                sleepTime = 60
            self.logger.debug ("Waiting %f seconds for the end of the video" % (sleepTime))
            if not self.playerAction.wait (sleepTime):
                if self.closing.isSet(): break
                if not self.leading.isSet(): continue
                self.nextVideo()
            self.playerAction.clear()
        self.logger.info("Playback Loop Closed")

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
                         "initdone"         : self.ignore}

    def _initCommandHandlers(self):
        self.commandHandlers = {"restart"           : self.restart,
                                "steal"             : self.steal,
                                "mod"               : self.makeLeader,
                                "mute"              : self.mute,
                                "unmute"            : self.unmute,
                                "status"            : self.status,
                                "lock"              : self.lock,
                                "unlock"            : self.unlock,
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
                                "duplicates"        : self.cleanDuplicates}

    def getUserByNick(self, nick):
        (valid, name) = self.filterString(nick, True)
        try: return self.userlist[(i for i in self.userlist if self.userlist[i].nick.lower() == name.lower()).next()]
        except StopIteration: return None

    def getVideoIndexById(self, vid):
        try: return (idx for idx, ele in enumerate(self.vidlist) if ele.v_sid == vid).next()
        except StopIteration: return -1

    def nextVideo(self):
        self.vidLock.acquire()
        videoIndex = self.getVideoIndexById(self.state.current)
        if videoIndex == None:
            videoIndex = -1
        if len (self.vidlist) == 0:
            self.sendMsg("Video list is empty, restarting")
            self.close()
        videoIndex = (videoIndex + 1) % len(self.vidlist)
        if len(self.vidlist) > 1:
            self.state.previous = self.state.current
        else:
            self.state.previous = None
        self.logger.debug ("Advancing to next video [%s]", self.vidlist[videoIndex])
        self.state.time = int(round(time.time() * 1000))
        self.send("s", [2])
        self.send("pm", self.vidlist[videoIndex].v_sid)
        self.vidLock.release()

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
        self.leading.set()
        self.playerAction.set()
        if self.irc_nick:
            self.ircclient.close()

    def addMedia(self, tag, data):
        self._addVideo(data)

    def removeMedia(self, tag, data):
        self._removeVideo(data)

    def moveMedia(self, tag, data):
        after = None
        if "after" in data:
            after = data["after"]
        self._moveVideo(data["id"], after)

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

    def changeMedia(self, tag, data):
        self.state.current = None
        self.playerAction.set()
        self.logger.info("Ignoring cm (change media) message: %s" % (data))

    def playlist(self, tag, data):
        for v in data:
            self._addVideo(v)
        #self.logger.debug(pprint(self.vidlist))

    def changeState(self, tag, data):
        self.logger.debug("State is %s %s", tag, data)
        if data == None:
            self.state.state = 0
            self.state.time = int(round(time.time() * 1000))
        else:
            self.state.state = data[0]
            if self.state.state == 2:
                self.state.pauseTime = time.time()
                return
            elif len (data) > 1:
                self.state.time = data[1]
            else:
                self.state.time = int(round(time.time() * 1000))
        self.playerAction.set()

    def play(self, tag, data):
        if self.leading.isSet() and (not self.state.previous == None) and (not self.getVideoIndexById(self.state.previous) == None):
            self.send ("rm", self.state.previous)
        self.state.previous = None
        self.state.current = data [1]
        index = self.getVideoIndexById(self.state.current)
        if index == None:
            self.sendMsg("Unexpected video, restarting")
            self.close()
            return
        self.state.dur = self.vidlist[index].vidinfo.dur
        self.changeState(tag, data[2])
        self.logger.debug("Playing %s %s", tag, data)

    def ignore(self, tag, data):
        self.logger.debug("Ignoring %s, %s", tag, data)

    def nick(self, tag, data):
        sid = data[0]
        (valid, nick) = self.filterString(data[1], True)
        self.logger.debug("%s nick: %s (was: %s)", sid, nick, self.userlist[sid].nick)
        self.userlist[sid]= self.userlist[sid]._replace(nick=nick)
        if not valid:
            self.nameBan(sid)

        user = self.userlist[sid]
        if user.nickChange:
            if self.pending.has_key(sid) or user.mod or user.sid == self.sid:
                return
            else:
                # Only a script/bot can change nicks multiple times
                # TODO -- Change to ban once I confirm there are no false positives
                self.pending[sid] = True
                self.logger.info("Attempted kick of %s for multiple nick changes", user.nick)
                reason = "%s changed names multiple times" % ( user.nick)
                def kickUser():
                    self._kickUser(sid, reason)
                self.asLeader(kickUser)
        else:
            self.userlist[sid] = self.userlist[sid]._replace(nickChange=True)

    def addUser(self, tag, data):
        # add_user and users data are similar aside from users having
        # a name field at idx 1
        userinfo = data[:]
        userinfo.insert(1, 'unnamed')
        self._addUser(userinfo)

    def remUser(self, tag, data):
        try:
            del self.userlist[data]
            if (self.pending.has_key(data)):
                del self.pending[data]
        except KeyError:
            self.logger.exception("Failure to delete user %s from %s", data, self.userlist)

    def sendChat(self, msg):
        self.logger.debug(msg)
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
            self.send ("turnoff_tv")
        else:
            self.send("takeleader", self.sid)

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

    def users(self, tag, data):
        for u in data:
            self._addUser(u)

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

    def skip(self, command, user, data):
        if not user.mod: return
        # Due to the complexities of switching videos, she does not give back the leader after this
        # TODO - Make it so she does
        self.asLeader(self.nextVideo, False)

    def chat(self, tag, data):
        sid = data[0]
        user = self.userlist[sid]
        msg = data[1]
        self.chat_logger.info("%s: %s" , user.nick, msg)

        if not user.sid == self.sid and self.irc_nick:
            self.irc_queue.append("(" + user.nick + ") " + msg)

        if len(msg) > 0 and msg[0] == '$':
            line = msg[1:].split(' ', 1)
            command = line [0]
            try:
                if len(line) > 1:
                    arg = line[1].strip()
                else:
                    arg = ''
                fn = self.commandHandlers[command]
            except KeyError:
                # Dice is a special case
                if re.match(r"^[0-9]+d[0-9]+$", command):
                    self.dice(command, user, " ".join(command.split('d')))
                else:
                    self.logger.warn("No handler for %s [%s]", command, arg)
            else:
                fn(command, user, arg)

        user.msgs.append(time.time())
        span = user.msgs[-1] - user.msgs[0]
        if span < self.spam_interval * user.msgs.maxlen and len(user.msgs) == user.msgs.maxlen:
            if self.pending.has_key(sid) or user.mod or user.sid == self.sid:
                return
            else:
                self.pending[sid] = True
                if self.banTracker.has_key(user.nick):
                    self.banTracker[user.nick] = self.banTracker[user.nick] + 1
                else:
                    self.banTracker[user.nick] = 1
                self.logger.info("Attempted kick of %s for spam", user.nick)
                reason = "[%d times] %s sent %d messages in %1.3f seconds" % (self.banTracker[user.nick], user.nick, len(user.msgs), span)
                if self.banTracker[user.nick] >= 3:
                    def banUser():
                        self._banUser(sid, reason)
                    self.asLeader(banUser)
                else:
                    def kickUser():
                        self._kickUser(sid, reason)
                    self.asLeader(kickUser)

    def leader(self, tag, data):
        self.leader_sid = data
        if self.leader_sid == self.sid:
            self._leaderActions()
            if not self.pendingToss:
                self.leading.set()
        else:
            self.leading.clear()
        self.logger.debug("Leader is %s", self.userlist[data])

    # Command handlers for commands that users can type in Synchtube chat
    # All of them receive input in the form (command, user, data)
    # Where command is the typed command, user is the user who sent the message
    # and data is everything following the command in the chat message

    def mute(self, command, user, data):
        if user.mod:
            self.muted = True

    def unmute (self, command, user, data):
        if user.mod:
            self.muted = False

    def steal(self, command, user, data):
        if not user.mod: return
        self.changeLeader(user.sid)

    def makeLeader(self, command, user, data):
        if not user.mod: return
        args = data.split(' ', 1)
        target = self.getUserByNick(args[0])
        self.logger.info ("Requested mod change to %s by %s", target, user)
        if not target: return
        self.changeLeader(target.sid)

    def dice(self, command, user, data):
        if not data: return
        params = data
        if type (params) is not str and type(params) is not unicode:
            params = str(params)
        params = params.strip().split(' ')
        if len (params) < 2: return
        num = 0
        size = 0
        try:
            num = int(params[0])
            size = int (params[1])
            if num < 1 or size < 1 or num > 1000 or size > 1000: return # Limits
            sum = 0
            i = 0
            output = []
            while i < num:
                rand = random.randint (1, size)
                if i < 5:
                    output.append(str(rand))
                if i == 5:
                    output.append("...")
                sum = sum + rand
                i = i+1
            self.enqueueMsg("%dd%d: %d [%s]" % (num, size, sum, ",".join (output)))
        except Exception as e:
            self.logger.debug (e)

    # Bumps the last video added by the specificied user
    # If no name is provided it bumps the last video by the user who sent the command
    def bump(self, command, user, data):
        if not user.mod: return
        (valid, target) = self.filterString(data, True)
        if target == "":
            target = user.nick
        target = target.lower()
        videoIndex = self.getVideoIndexById(self.state.current)
        i = len(self.vidlist) - 1
        while i >= 0:
            if self.vidlist[i].nick.lower() == target:
                break
            i -= 1
        if i <= videoIndex: return
        # The case where i == 0 requires no action
        if i > 0:
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

    def lock (self, command, user, data):
        if not user.mod: return
        def changeLock():
            self.send ("lock?", True)
        self.asLeader(changeLock)

    def unlock (self, command, user, data):
        if not user.mod: return
        def changeLock():
            self.send ("lock?", False)
        self.asLeader(changeLock)

    def status (self, command, user, data):
        msg = "Status = ["
        if not self.muted:
            msg += "Not "
        msg += "Muted]"
        self.sendChat(msg)

    def restart(self, command, user, data):
        if user.mod:
            self.close()

    def choose(self, command, user, data):
        if not data: return
        choices = data
        if type (choices) is not str and type(choices) is not unicode:
            choices = str(choices)
        choices = choices.strip()
        if len (choices) == 0: return
        self.enqueueMsg("[Choose: %s] %s" % (choices, random.choice(choices.split(' '))))

    def steak(self, command, user, data):
        self.enqueueMsg("There is no steak.")

    def ask(self, command, user, data):
        if not data: return
        question = data
        if type (question) is not str and type(question) is not unicode:
            question = str(question)
        question = question.strip()
        if len (question) == 0: return
        self.enqueueMsg("[%s] %s" % (question, random.choice(["Yes", "No"])))

    def eightBall(self, command, user, data):
        if not data: return
        question = data
        if type (question) is not str and type(question) is not unicode:
            question = str(question)
        question = question.strip()
        if len (question) == 0: return
        self.enqueueMsg("[8ball %s] %s" % (user.nick, random.choice(eight_choices)))

    def kick(self, command, user, data):
        if not user.mod: return
        args = data.split(' ', 1)
        target = self.getUserByNick(args[0])
        if not target or target.mod: return
        self.logger.info ("Kick Target %s Requestor %s", target, user)
        if len(args) > 1:
            def kickUser():
                self._kickUser(target.sid, args[1], False)
            self.asLeader(kickUser)
        else:
            def kickUser():
                self._kickUser(target.sid, sendMessage=False)
            self.asLeader(kickUser)

    def ban(self, command, user, data):
        if not user.mod: return
        args = data.split(' ', 1)
        target = self.getUserByNick(args[0])
        if not target or target.mod: return
        self.logger.info ("Ban Target %s Requestor %s", target, user)
        if len(args) > 1:
            def banUser():
                self._banUser(target.sid, args[1], False)
            self.asLeader(banUser)
        else:
            def banUser():
                self._banUser(target.sid, sendMessage=False)
            self.asLeader(banUser)

    # Filters a string, removing invalid characters
    # Used to sanitize nicks or video titles for printing
    # Returns a boolean describing whether invalid characters were found
    # As well as the filtered string
    def filterString(self, input, isNick=False):
        if input == None: return (False, "")
        output = []
        value = input
        if type (value) is not str and type(value) is not unicode:
            value = str(value)
        for c in value:
            o = ord(c)
            # Locale independent ascii alphanumeric check
            if isNick and ((o >= 48 and o <= 57) or (o >= 97 and o <= 122) or (o >= 65 and o <= 90)):
                output.append(c)
            if (not isNick) and o > 31 and o != 127:
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
        (valid, nick) = self.filterString(userinfo['nick'], True)
        userinfo['nick'] = nick
        userinfo['msgs'] = deque(maxlen=3)
        userinfo['nickChange'] = False
        user = SynchtubeUser(**userinfo)
        self.userlist[user.sid] = user

    # Add the video described by v
    def _addVideo(self, v):
        if self.stthread != threading.currentThread():
            raise Exception("_addVideo should not be called outside the SynchtubeClient thread")
        v[0] = v[0][:len(SynchtubeVidInfo._fields)]
        (valid, title) = self.filterString(v[0][2])
        v[0][2] = title
        v[0] = SynchtubeVidInfo(*v[0])
        v.append(None) # If an unregistered adds a video there is no name included
        v = v[:len(SynchtubeVideo._fields)]
        (valid, name) = self.filterString(v[3], True)
        v[3] = name
        vid = SynchtubeVideo(*v)
        self.vidLock.acquire()
        self.vidlist.append(vid)
        self.vidLock.release()

    def _removeVideo(self, v):
        if self.stthread != threading.currentThread():
            raise Exception("_removeVideo should not be called outside the SynchtubeClient thread")
        idx = self.getVideoIndexById (v)
        if idx >= 0:
            self.vidLock.acquire()
            self.vidlist.pop(idx)
            self.vidLock.release()

    def _moveVideo(self, v, after=None):
        if self.stthread != threading.currentThread():
            raise Exception("_moveVideo should not be called outside the SynchtubeClient thread")
        self.vidLock.acquire()
        video = self.vidlist.pop(self.getVideoIndexById(v))
        pos = 0
        if after:
            pos = self.getVideoIndexById(after) + 1
        self.vidlist.insert(pos, video)
        self.vidLock.release()
        self.logger.debug ("Inserted %s after %s", video, self.vidlist[pos - 1])

    # Kick user using their sid(session id)
    def _kickUser(self, sid, reason="Requested", sendMessage=True):
        if sendMessage:
            self.enqueueMsg("Kicked %s: (%s)" % (self.userlist[sid].nick, reason))
        self.send("kick", [sid, reason])

    # By default none of the functions use this.
    # Don't come crying to me if the bot bans the entire channel
    def _banUser(self, sid, reason="Requested", sendMessage=True):
        if sendMessage:
            self.enqueueMsg("Banned %s: (%s)" % (self.userlist[sid].nick, reason))
        self.send("ban", sid)

    # Perform pending pending leader actions.
    # This should _NOT_ be called outside the main SynchtubeClient's thread
    def _leaderActions(self):
        if self.stthread != threading.currentThread():
            raise Exception("_leaderActions should not be called outside the SynchtubeClient thread")
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
