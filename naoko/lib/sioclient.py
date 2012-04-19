#!/usr/bin/env python

import hashlib
import json
import logging
import random
import sched, time
import socket
import struct
import threading
from urllib import urlopen, urlencode

from settings import *

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
        self.logger.setLevel(LOG_LEVEL)
        self.pkt_logger =logging.getLogger("websocket.pkt")
        self.pkt_logger.setLevel(LOG_LEVEL)
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
                    self.logger.warn("Invalid Newline")
            elif data == ":":
                self.field = value
                self.value = ''
            else:
                value += data
            last_byte = data
        self.logger.debug(repr(data))

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
                    self.logger.warn("Invalid Newline")
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
        self.logger.setLevel(LOG_LEVEL)
        self.pkt_logger = logging.getLogger("socketio.pkt")
        self.pkt_logger.setLevel(LOG_LEVEL)
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
                                          urlencode(params))
        self.hbthread = threading.Thread(target=SocketIOClient._heartbeat, args=[self])

    def _heartbeat(self):
        self.sendHeartBeat(5)
        self.sched.run()

    def __getSessionInfo(self):
        stinfo = urlopen(self.url).read()
        self.sock_info = dict(zip(['sid', 'hb', 'to', 'xports'],
                                  urlopen(self.url).read().split(':')))
        self.sid = self.sock_info['sid']
        return self.sid

    def close(self):
        if self.heartBeatEvent:
            self.sched.cancel(self.heartBeatEvent)
            self.logger.info("Heartbeats Stopped")
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
                                             urlencode(self.params))
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
