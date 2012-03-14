# Denshi - A prototype synchtube bot
# Written in 2011 by falaina falaina@falaina.net
# To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide. This software is distributed without any warranty.
# You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

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

from collections import namedtuple
from pprint import pprint

# Set up logging
logging.basicConfig(format='%(name)-15s:%(levelname)-8s - %(message)s')
logger = logging.getLogger("socket.io client")
logger.setLevel(logging.DEBUG)
(info, debug, warning, error) = (logger.info, logger.debug, logger.warning, logger.error)

# Implementation of WebSocket client as per draft-ietf-hybi-thewebsocketprotocol-00
# http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-00
class WebSocket:
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
        self.logger.setLevel(logging.DEBUG)
        self.pkt_logger =logging.getLogger("websocket.pkt")
        self.pkt_logger.setLevel(logging.DEBUG)

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
        print "key3", repr(key3), repr(key3)
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
                           ['sid', 'nick', 'uid', 'auth', 'ava', 'lead', 'mod', 'karma'])

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
class SocketIOClient:
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
        self.logger.setLevel(logging.DEBUG)
        self.pkt_logger = logging.getLogger("socketio.pkt")
        self.pkt_logger.setLevel(logging.INFO)
        self.ip = socket.gethostbyname(socket.gethostname())        
        self.sched = sched.scheduler(time.time, time.sleep)
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

    def __getSessionInfo(self):
        stinfo = urllib.urlopen(self.url).read()
        print stinfo
        self.sock_info = dict(zip(['sid', 'hb', 'to', 'xports'],
                                  urllib.urlopen(self.url).read().split(':')))
        print self.sock_info
        self.sid = self.sock_info['sid']
        return self.sid

    def close(self):
        self.ws.close()

    def send(self, msg_type=3, sock_id='', end_pt='', data=''):
        buf = "%s:%s:%s:%s" % (msg_type, sock_id, end_pt, data)
        self.pkt_logger.debug("Sending %s", buf)
        self.ws.send(buf)

    def sendHeartBeat(self, next_sec=None):
        self.send(2)
        if next_sec:
            self.sched.enter(next_sec, 1, SocketIOClient.sendHeartBeat, (self, next_sec))
            
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
        self.sendHeartBeat()

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
            self.sendHeartBeat()
        return (msg_type, data)

# Synchtube  "client" built on top of a socket.io socket
# Synchtube messages are generally of the form:
#   ["TYPE", DATA]
# e.g., The self message (describes current client)
#   ["self" ["bbc2c922",22262,true,"jpg",false,true,21]]
# Which describes a particular connection for the user Denshi
# (uid 22262). The first field is the session identifier,
# second is uid, third is whether or not client is authenticated
# fourth is avatar type, and so on.    
class SynchtubeClient():
    _ST_IP = "173.255.204.78"

    def __init__(self, room, name):
        self.name = name
        self.room = room
        self.thread = threading.currentThread()
        self.thread.st = self
        config_url = "http://www.synchtube.com/api/1/room/%s" % (room)
        config_info = urllib.urlopen(config_url).read()
        config = json.loads(config_info)
        config['room']['port'] = int(config['room']['port'])
        self.config_params = {'b' : 15,  # This might need updating at some point
                              'r' : config['room']['id'], 
                              'p' : config['room']['port'],
                              'i' : socket.gethostbyname(socket.gethostname())}
        self.logger =logging.getLogger("stclient")
        self.logger.setLevel(logging.DEBUG)
        self.chat_logger = logging.getLogger("stclient.chat")
        self.chat_logger.setLevel(logging.DEBUG)
        self.userlist = {}

        self.client = client = SocketIOClient(self._ST_IP, config['room']['port'], "socket.io",
                                              self.config_params)
        self._initHandlers()
        self.room_info = {}
        self.vidlist = SynchtubePlaylist()
        self.thread.close = self.close
        self.closing = False       
        print self.thread
        client.connect()

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

    def _initHandlers(self):        
        self.handlers = {"<"              : self.chat, 
                         "leader"         : self.leader,
                         "users"          : self.users,
                         "recording?"     : self.roomSetting,
                         "tv?"            : self.roomSetting,
                         "skip?"          : self.roomSetting,
                         "lock?"          : self.roomSetting,
                         "public?"        : self.roomSetting,
                         "history"        : self.roomSetting,
                         "vote_settings"  : self.roomSetting,
                         "playlist_rules" : self.roomSetting,
                         "num_votes"      : self.roomSetting,
                         "self"           : self.selfInfo,
                         "add_user"       : self.addUser,
                         "remove_user"    : self.remUser,
                         "nick"           : self.nick,
                         "pm"             : self.play,
                         "playlist"       : self.playlist,
                         "initdone"       : self.ignore}

    def _addVideo(self, v):
        v[0] = SynchtubeVidInfo(*v[0])
        vid = SynchtubeVideo(*v)
        self.vidlist.append(vid)

    def close(self):
        self.closing = True

    def playlist(self, tag, data):
        for v in data:
            self._addVideo(v)
        self.logger.debug(pprint(self.vidlist))

    def play(self, tag, data):
        self.logger.debug("Playing %s %s", tag, data)
        

    def ignore(self, tag, data):
        self.logger.debug("Ignoring %s, %s", tag, data)


    def nick(self, tag, data):
        sid = data[0]
        nick = data[1]
        self.logger.debug("%s nick: %s (was: %s)", 
                          sid, nick, self.userlist[sid].nick)
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
        except KeyError:
            self.logger.exception("Failure to delete user %s from %s", data, self.userlist)

    def sendChat(self, msg):
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
        self.send("nick", self.name)

    def roomSetting(self, tag, data):
        self.room_info[tag] = data

    def _addUser(self, u_arr):
        userinfo = itertools.izip_longest(SynchtubeUser._fields, u_arr)
        userinfo = dict(userinfo)
        user = SynchtubeUser(**userinfo)
        self.userlist[user.sid] = user
        
    def users(self, tag, data):
        for u in data:
            self._addUser(u)
        
    def chat(self, tag, data):
        sid = data[0]
        user = self.userlist[sid]
        msg = data[1]
        self.chat_logger.info("%s: %s" , user.nick, msg)
    
    def leader(self, tag, data):
        self.leader = data
        self.logger.debug("Leader is %s", self.userlist[data])
        
    def sendHeartBeat(self):
        self.send()

# replace "ROOMNAME" with the name of the room
t = threading.Thread(target=SynchtubeClient, args=["ROOMNAME", "DenshiBot"])

# Spin off the socket thread from the main thread.
t.start()
st = t.st

