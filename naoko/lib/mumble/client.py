#!/usr/bin/env python

import sched, time
import platform
import socket
import ssl
import struct
import threading
import Mumble_pb2
import logging
from collections import namedtuple
import asdfasdfaas

from settings import *

_messageTypeLookup = {
    Mumble_pb2.Version: 0,
    Mumble_pb2.UDPTunnel: 1,
    Mumble_pb2.Authenticate: 2,
    Mumble_pb2.Ping: 3,
    Mumble_pb2.Reject: 4,
    Mumble_pb2.ServerSync: 5,
    Mumble_pb2.ChannelRemove: 6,
    Mumble_pb2.ChannelState: 7,
    Mumble_pb2.UserRemove: 8,
    Mumble_pb2.UserState: 9,
    Mumble_pb2.BanList: 10,
    Mumble_pb2.TextMessage: 11,
    Mumble_pb2.PermissionDenied: 12,
    Mumble_pb2.ACL: 13,
    Mumble_pb2.QueryUsers: 14,
    Mumble_pb2.CryptSetup: 15,
    Mumble_pb2.ContextActionModify: 16,
    Mumble_pb2.ContextAction: 17,
    Mumble_pb2.UserList: 18,
    Mumble_pb2.VoiceTarget: 19,
    Mumble_pb2.PermissionQuery: 20,
    Mumble_pb2.CodecVersion: 21,
    Mumble_pb2.UserStats: 22,
    Mumble_pb2.SuggestConfig: 23,
    Mumble_pb2.RequestBlob: 24
}

_messageNumberLookup = {}

MumbleUser = namedtuple("MumbleUser", ["name", "session"])

# Implementation of a Mumble Client
# Used https://github.com/Underyx/mumblebot/blob/master/mumbleConnection.py as a starting point.
class ProtobufSocket(object):
    version = 0
    # Socket states
    _DISCONNECTED = 0
    _CONNECTING = 1
    _CONNECTED  = 2

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.state = self._DISCONNECTED
        self._pingTotal = 0
        
        self.logger = logging.getLogger("mumble")
        self.logger.setLevel(LOG_LEVEL)
        self.pkt_logger =logging.getLogger("mumble.pkt")
        self.pkt_logger.setLevel(LOG_LEVEL)
        self.closing = False
        
        for i in _messageTypeLookup.keys():
            _messageNumberLookup[_messageTypeLookup[i]] = i
    
    def prepare(self, pb):
        string = pb.SerializeToString()
        return struct.pack(">HI", _messageTypeLookup[type(pb)], len(string)) + string

    def send(self, data, log=True):
        #if log:
            #self.pkt_logger.debug("Sending frame: %r", data)
        self.sock.sendall(data)

    def connect(self):
        self.logger.info("Connecting to %s", self.host)

        self.sock = socket.socket(type=socket.SOCK_STREAM)
        self.sock = sock = ssl.wrap_socket(self.sock, ssl_version=ssl.PROTOCOL_TLSv1)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        sock.settimeout(TIMEOUT)
        
        self.sock.connect((self.host, self.port))

        self.logger.info("Connected to %s", self.host)
        self.state = self._CONNECTED

    def _read(self, length):
        packet = ""
        while len(packet) < length:
            a = self.sock.recv(length - len(packet))
            if (len(a) == 0):
                raise Exception("Error reading from Mumble socket.")
            packet += a
        return packet

    def readPacket(self):
        meta = self.sock.read(6)
        if not self.closing and meta:
            msgType, length = struct.unpack(">HI", meta)

            packet = self._read(length)
            return (msgType, packet)
             
    def recvPacket(self):
        return self.readPacket()

    def sendPing(self):
        pingPacket = Mumble_pb2.Ping()
        pingPacket.timestamp = (self._pingTotal * 5000000)
        pingPacket.good = 0
        pingPacket.late = 0
        pingPacket.lost = 0
        pingPacket.resync = 0
        pingPacket.udp_packets = 0
        pingPacket.tcp_packets = self._pingTotal
        pingPacket.udp_ping_avg = 0
        pingPacket.udp_ping_var = 0.0
        pingPacket.tcp_ping_avg = 50
        pingPacket.tcp_ping_var = 50
        self._pingTotal += 1
        self.send(self.prepare(pingPacket))

    def close(self):
        self.sock.settimeout(0)
        self.closing = True

# Mumble IO Client
class MumbleClient(object):
    protocol = 1

    # Socket IO Message types. There are more, but these are the bare minimum.
    HEARTBEAT = 3
    MESSAGE   = 11

    def __init__(self, host, port, name, pw, channel):
        self.host = host
        self.port = port
        self.name = name
        self.pw = pw
        self.channel = channel
        if not self.channel: self.channel = "Root"
        self.channel_id = False
        self.session = False
        self.users = {}

        self.logger = logging.getLogger("mumbleclient")
        self.logger.setLevel(LOG_LEVEL)
        self.pkt_logger = logging.getLogger("mumbleclient.pkt")
        self.pkt_logger.setLevel(LOG_LEVEL)
        self.sched = sched.scheduler(time.time, time.sleep)
        self.heartBeatEvent = False
        
        self.connectTime = time.time()
        self.doneInit = False

        self.hbthread = threading.Thread(target=MumbleClient._heartbeat, args=[self])
        
    def _heartbeat(self):
        self.heartBeat()
        self.sched.run()

    def close(self):
        if self.heartBeatEvent:
            self.sched.cancel(self.heartBeatEvent)
            self.logger.info("Mumble Heartbeats Stopped")
        self.ps.close()

    def heartBeat(self):
        self.ps.sendPing()
        hb_diff = time.time() - self.last_hb
       # self.pkt_logger.debug("Time since last heartbeat %.3f", hb_diff)
        if hb_diff > TIMEOUT:
            raise Exception("Mumble Timeout, %.3f since last heartbeat" % (hb_diff))
        self.heartBeatEvent = self.sched.enter(1, 1, MumbleClient.heartBeat, [self]) 

    def connect(self):
        self.ps = ProtobufSocket(self.host, self.port)
        self.ps.connect()

        versionPacket = Mumble_pb2.Version()
        versionPacket.release = "1.2.0"
        versionPacket.version = 66048
        versionPacket.os = platform.system()
        versionPacket.os_version = "Naoko"

        authPacket = Mumble_pb2.Authenticate()
        authPacket.username = self.name
        if self.pw:
            authPacket.password = self.pw

        self.ps.send(self.ps.prepare(versionPacket) + self.ps.prepare(authPacket))
        
        self.logger.info("Authenticated")

        self.last_hb = time.time()
        self.hbthread.start()

    def sendChat(self, text):
        textPacket = Mumble_pb2.TextMessage()
        textPacket.session.append(self.session)
        textPacket.channel_id.append(self.channel_id)
        textPacket.message = text
        
        self.ps.send(self.ps.prepare(textPacket))

    def recvMessage(self):
        while True:
            (msgType, packet) = self.ps.recvPacket()
            data = self.processPacket(msgType, packet)
            if msgType == self.MESSAGE:
                try:
                    actor = self.users[data.actor].name
                except Exception:
                    continue
                self.logger.debug("(" + actor + ") " +  data.message)
                return (actor, data.message)

    def _joinChannel(self):
        if not self.channel_id: return
        joinPacket = Mumble_pb2.UserState()
        joinPacket.session = self.session
        joinPacket.channel_id = self.channel_id

        self.ps.send(self.ps.prepare(joinPacket))

    def processPacket(self, msgType, packet):
        if msgType == self.HEARTBEAT:
            self.last_hb = time.time()

        data = _messageNumberLookup[msgType]()

        if not self.session and msgType == 5:
            data.ParseFromString(packet)
            self.session = data.session
            self._joinChannel()

        if msgType == 7:
            data.ParseFromString(packet)
            if data.name == self.channel:
                self.channel_id = data.channel_id

        if msgType == 9:
            data.ParseFromString(packet)
            self.users[data.session] = MumbleUser(data.name, data.session)

        if msgType == 8:
            data.ParseFromString(packet)
            del(self.users[data.session])

        if msgType == 11:
            data.ParseFromString(packet)
            return data

        return False


