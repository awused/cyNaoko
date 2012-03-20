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
from pprint import pprint
import ConfigParser

# Default Timeout.
TIMEOUT   = 25

#Logging Level
logLevel = logging.WARNING

# Set up logging
logging.basicConfig(format='%(name)-15s:%(levelname)-8s - %(message)s')
logger = logging.getLogger("socket.io client")
logger.setLevel(logLevel)
(info, debug, warning, error) = (logger.info, logger.debug, logger.warning, logger.error)

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
        self.pkt_logger.debug("Sending frame: %s", repr(frame))
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
        while True:
            c = self.sock.recv(1)
            if c == '\xff':
                frame = "".join(frame)
                self.pkt_logger.debug("Received frame: %s", frame)
                return frame
            else:
                frame.append(c)

    def recvFrame(self):
        return self.readFrame()

    def close(self):
        self.sock.close()

# Simple Record Types for variable synchtube constructs
SynchtubeUser = namedtuple('SynchtubeUser',
                           ['sid', 'nick', 'uid', 'auth', 'ava', 'lead', 'mod', 'karma', 'msgs'])

SynchtubeVidInfo = namedtuple('SynchtubeVidInfo',
                            ['site', 'vid', 'title', 'thumb', 'dur'])

SynchtubeVideo = namedtuple('SynchtubeVideo',
                              ['vidinfo', 'v_sid', 'uid', 'nick'])

class SynchtubePlaylist(list):
    def __getitem__(self, key):
        if isinstance(key, int):
            return list.__getitem__(self, key)

        for l in self:
            if l.v_sid == key:
                return l

    def __setitem__(self, key, value):
        if isinstance(key, int):
            return list.__setitem__(self, key, value)

        for i in range(len(self)):
            if self[i].v_sid == key:
                self[i] = value
                return
        self.append(value)


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
        self.ws.close()
        if self.heartBeatEvent:
            self.sched.cancel(self.heartBeatEvent)

    def send(self, msg_type=3, sock_id='', end_pt='', data=''):
        buf = "%s:%s:%s:%s" % (msg_type, sock_id, end_pt, data)
        self.pkt_logger.debug("Sending %s", buf)
        self.ws.send(buf)

    def sendHeartBeat(self, next_sec=None):
        #self.logger.debug("beat")
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
                                             "flashsocket",
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

#Basic IRC client
#Built upon the instructions provided by http://wiki.shellium.org/w/Writing_an_IRC_bot_in_Python
class IRCClient(object):
    def __init__ (self, server, channel, nick, pw):
        self.logger = logging.getLogger("ircclient")
        self.logger.setLevel(logLevel)
        self.server = server
        self.channel = channel
        self.nick = nick

        #self.logger.debug ("%s %s %s %s", self.server, self.channel, self.nick, pw)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server, 6667)) # Here we connect to the server using port 6667
        self.send("USER "+ self.nick +" "+ self.nick +" "+ self.nick +" :test\n") # user authentication
        self.send("NICK "+ self.nick +"\n") # here we actually assign the nick to the bot
        if pw:
            self.send ("PRIVMSG nickserv :id " + pw + "\n")
        self.send ("JOIN " + self.channel + "\n")

    def ping (self):
        self.send ("PONG :pingis\n")

    def close (self):
        self.send ("QUIT :quit\n")
        self.sock.close()

    def sendmsg (self, msg):
        self.send("PRIVMSG " + self.channel + " :" + msg + "\n")

    def recvMessage (self):
        while True:
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
# Which describes a particular connection for the user Denshi
# (uid 22262). The first field is the session identifier,
# second is uid, third is whether or not client is authenticated
# fourth is avatar type, and so on.
class SynchtubeClient(object):
    _ST_IP = "173.255.204.78"
    _HEADERS = {'User-Agent' : 'DenshiBot',
                'Accept' : 'text/html,application/xhtml+xml,application/xml;',
                'Host' : 'www.synchtube.com',
                'Connection' : 'keep-alive',
                'Origin' : 'http://www.synchtube.com',
                'Referer' : 'http://www.synchtube.com'}

    def __init__(self, room, name, pw, spam_interval, server, channel, irc_nick,  ircpw):
        self.thread = threading.currentThread()
        self.thread.st = self
        self.name = name
        self.room = room
        self.irc_nick = irc_nick
        self.server = server
        self.channel = channel
        self.leader_queue = deque()
        self.st_queue = deque()
        self.logger = logging.getLogger("stclient")
        self.logger.setLevel(logLevel)
        self.chat_logger = logging.getLogger("stclient.chat")
        self.chat_logger.setLevel(logLevel)
        self.spam_interval = spam_interval
        self.pending = {}
        self.pendingToss = False
        self.muted = False
        if pw:
            self.logger.info("Attempting to login")
            login_url = "http://www.synchtube.com/user/login"
            login_body = {'email' : name, 'password' : pw};
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
        room_req = Request("http://www.synchtube.com/r/%s" % (room), headers=self._HEADERS)
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

        config_url = "http://www.synchtube.com/api/1/room/%s" % (room)
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
        self.client = client = SocketIOClient(self._ST_IP, self.port, "socket.io",
                                              self.config_params)
        self._initHandlers()
        self._initCommandHandlers()
        self.room_info = {}
        self.vidlist = SynchtubePlaylist()
        self.thread.close = self.close
        self.closing = False
        client.connect()
        if irc_nick:
            self.irc_queue = deque()
            self.logger.info("Starting IRC Client")
            self.ircclient = IRCClient(server, channel, irc_nick, ircpw)
            self.ircthread = threading.Thread(target=SynchtubeClient._ircloop, args=[self])
            self.ircthread.start()

            self.bridgethread = threading.Thread (target=SynchtubeClient._bridgeloop, args=[self])
            self.bridgethread.start()
        else:
            self.irc_queue = deque(maxlen=0)

        while not self.closing:
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
            self.client.close()

    def _ircloop(self):
        client = self.ircclient
        while not self.closing:
            frame = deque(client.recvMessage().split("\n"))
            while len(frame) > 0:
                data = frame.popleft().strip("\r")
                if data.find("PING :") != -1:
                    client.ping()
                if data.find("PRIVMSG " + self.channel + " :") != -1:
                    #self.logger.info (repr(data))
                    name = data.split('!', 1)[0][1:]
                    msg = data[data.find("PRIVMSG " + self.channel + " :") + len("PRIVMSG " + self.channel + " :"):]
                    if not name == self.irc_nick:
                        self.st_queue.append("(" + name + ") " + msg)
                    self.logger.info ("IRC %s:%s", name, msg)
        else:
            self.ircclient.close()

    def _bridgeloop(self):
        while not self.closing:
            if self.muted:
                self.irc_queue.clear()
                self.st_queue.clear()
            else:
                if len (self.irc_queue) > 0:
                    self.ircclient.sendmsg(self.irc_queue.popleft())
                if len (self.st_queue) > 0:
                    self.sendChat(self.st_queue.popleft())
            time.sleep(self.spam_interval)

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
                         "playlist"         : self.playlist,
                         "initdone"         : self.ignore}

    def _initCommandHandlers(self):
        self.commandHandlers = {"kill"              : self.kill,
                                "steal"             : self.steal,
                                "mod"               : self.makeLeader,
                                "mute"              : self.mute,
                                "unmute"            : self.unmute,
                                "status"            : self.status,
                                "kick"              : self.kick}

    def getUserByNick(self, nick):
        try: return self.userlist[(i for i in self.userlist if self.userlist[i].nick.lower() == nick.lower()).next()]
        except StopIteration: return None

    def close(self):
        self.closing = True

    def addMedia(self, tag, data):
        self._addVideo(data)

    def changeMedia(self, tag, data):
        self.logger.info("Ignoring cm (change media) message: %s" % (data))

    def mute(self, command, user, data):
        if user.mod:
            self.muted = True

    def unmute (self, command, user, data):
        if user.mod:
            self.muted = False

    def status (self, command, user, data):
        msg = "Status = ["
        if not self.muted:
            msg += "Not "
        msg += "Muted]"
        self.sendChat(msg)

    def kill(self, command, user, data):
        if user.mod:
            self.close()

    def playlist(self, tag, data):
        for v in data:
            self._addVideo(v)
        #self.logger.debug(pprint(self.vidlist))

    def play(self, tag, data):
        self.logger.debug("Playing %s %s", tag, data)

    def ignore(self, tag, data):
        self.logger.debug("Ignoring %s, %s", tag, data)

    def nick(self, tag, data):
        sid = data[0]
        nick = data[1]
        #self.logger.debug("%s nick: %s (was: %s)", sid, nick, self.userlist[sid].nick)
        self.userlist[sid]= self.userlist[sid]._replace(nick=nick)

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
        self.logger.info(msg)
        self.send("<", msg)

    def send(self, tag='', data=''):
        buf = []
        if tag:
            buf.append(tag)
            if data:
                buf.append(data)
        buf = json.dumps(buf)
        self.client.send(3, data=buf)

    def selfInfo(self, tag, data):
        self._addUser(data)
        self.sid = data[0]
        self.send("nick", self.name)

    def roomSetting(self, tag, data):
        self.room_info[tag] = data

    def takeLeader(self):
        if self.sid == self.leader:
            self._leaderActions()
            return
        self.send("takeleader")

    def asLeader(self, action=None, giveBack=True):
        self.leader_queue.append(action)
        if self.leader != self.sid and giveBack and not self.pendingToss:
            oldLeader = self.leader
            def tossLeader():
                self._tossLeader(oldLeader)
            self.pendingToss = True
            self.tossLeader = tossLeader
        self.takeLeader()

    def users(self, tag, data):
        for u in data:
            self._addUser(u)

    def kick(self, command, user, data):
        if not user.mod: return
        args = data.split(' ', 1)
        target = self.getUserByNick(args[0])
        if not target or target.mod: return
        self.logger.info ("Kick Target %s Requestor %s", target, user)
        if len(args) > 1:
            def kickUser():
                self._kickUser(target.sid, args[1])
            self.asLeader(kickUser)
        else:
            def kickUser():
                self._kickUser(target.sid)
            self.asLeader(kickUser)

    def changeLeader(self, sid):
        if sid == self.leader: return
        if sid == self.sid:
            self.takeLeader()
            return
        def tossLeader():
            self._tossLeader(sid)
        self.pendingToss = True
        self.tossLeader = tossLeader
        self.takeLeader()

    def steal(self, command, user, data):
        if not user.mod: return
        self.changeLeader(user.sid)

    def makeLeader(self, command, user, data):
        if not user.mod: return
        args = data.split(' ', 1)
        target = self.getUserByNick(args[0])
        if not target: return
        self.changeLeader(target.sid)

    def chat(self, tag, data):
        sid = data[0]
        user = self.userlist[sid]
        msg = data[1]
        self.chat_logger.info("%s: %s" , user.nick, msg)

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
                self.logger.warn("No handler for %s [%s]", command, arg)
            else:
                fn(command, user, arg)

        if not user.sid == self.sid and self.irc_nick:
            self.irc_queue.append("(" + user.nick + ") " + msg)

        user.msgs.append(time.time())
        span = user.msgs[-1] - user.msgs[0]
        if span < self.spam_interval * 3 and len(user.msgs) > 2:
            if self.pending.has_key(sid) or user.mod or user.sid == self.sid:
                return
            else:
                self.pending[sid] = True
                self.logger.info("attempted kick")
                reason = "%s sent %d messages in %1.3f seconds" % (user.nick, len(user.msgs), span)
                def kickUser():
                    self._kickUser(sid, reason)
                self.asLeader(kickUser)

    def leader(self, tag, data):
        self.leader = data
        if self.leader == self.sid:
            self._leaderActions()
        self.logger.debug("Leader is %s", self.userlist[data])

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
        userinfo['msgs'] = deque(maxlen=3)
        user = SynchtubeUser(**userinfo)
        self.userlist[user.sid] = user

    # Add the video described by v
    def _addVideo(self, v):
        v[0] = v[0][:len(SynchtubeVidInfo._fields)]
        v[0] = SynchtubeVidInfo(*v[0])
        v.append(None) # If an unregistered adds a video there is no name included
        v = v[:len(SynchtubeVideo._fields)]
        vid = SynchtubeVideo(*v)
        self.vidlist.append(vid)

    # Kick user using their sid(session id)
    def _kickUser(self, sid, reason="Requested"):
        self.sendChat("Kicked %s: (%s)" % (self.userlist[sid].nick, reason))
        self.send("kick", [sid, reason])

    # By default none of the functions use this.
    # Don't come crying to me if the bot bans the entire channel
    def _banUser(self, sid, reason="Requested"):
        self.sendChat("Banned %s: (%s)" % (self.userlist[sid].nick, reason))
        self.send("ban", [sid, reason])

    # Perform pending pending leader actions.
    # This should _NOT_ be called outside the main SynchtubeClient's thread
    def _leaderActions(self):
        if self.thread != threading.currentThread():
            raise Exception("_leaderActions should not be called outside the SynchtubeClient thread")
        while len(self.leader_queue) > 0:
            self.leader_queue.popleft()()
        if self.pendingToss:
            self.tossLeader()
            self.pendingToss = False

    # Give leader to another user using their sid(session id)
    # This command does not ensure the client is currently leader before executing
    def _tossLeader(self, sid):
        self.send("toss", sid)

    def sendHeartBeat(self):
        self.send()

# replace "ROOMNAME" with the name of the room
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
    print '\n Shutting Down'
except (KeyboardInterrupt, SystemExit):
    print '\n! Received keyboard interrupt'

