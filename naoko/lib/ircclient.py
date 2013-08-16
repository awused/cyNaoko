#!/usr/bin/env python

import logging
import socket
import re
import time

from settings import *

#Basic IRC client
#Built upon the instructions provided by http://wiki.shellium.org/w/Writing_an_IRC_bot_in_Python
class IRCClient(object):
    def __init__(self, server, channel, nick, pw):
        # NOTE: Doesn't currently confirm any joins, nick changes, or identifies
        # If an IRC name is set and this fails, the entire bot will restart
        # IRC pings can be unpredictable, so a timeout (except when closing) isn't practical
        self.logger = logging.getLogger("ircclient")
        self.logger.setLevel(LOG_LEVEL)
        self.loggedIn = False
        self.inChannel = False
        self.server = server
        self.channel = channel
        self.nick = nick

        #self.logger.debug ("%s %s %s %s", self.server, self.channel, self.nick, pw)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server, 6667)) # Here we connect to the server using port 6667
        self.sock.settimeout(10*60) # Ten minute timeout to detect disconnects
        time.sleep(2)
        self.send("USER "+ self.nick +" "+ self.nick +" "+ self.nick +" :"+ self.nick +"\n") # user authentication
        self.send("NICK "+ self.nick +"\n") # here we actually assign the nick to the bot
        time.sleep(1)
        if pw:
            self.send("PRIVMSG nickserv :id " + pw + "\n")
        self.send("JOIN " + self.channel + "\n")

    def ping(self):
        self.send("PONG :pingis\n")

    def close(self):
        self.sock.settimeout(0)
        self.send("QUIT :quit\n")
        self.sock.close()

    def filterMsg(self, msg):
        # Reverts some transformations performed by Synchtube. For now
        # Only converts youtube thumbnails to youtube video links.
        # (This also makes it impossible to legitimately link a
        # youtube thumbnail... but really?)

        msg = re.sub(r'http://i.ytimg.com/vi/([a-zA-Z0-9_\-\+\.]+)/default.jpg',
                     r'http://www.youtube.com/watch?v=\1',
                     msg)
        return msg

    def sendMsg (self, msg):
        msg = self.filterMsg(msg)
        self.send("PRIVMSG " + self.channel + " :" + msg + "\n")

    def recvMessage(self):
        frame = self.sock.recv(4096)
        if len(frame) == 0:
            raise Exception("IRC Socket closed")
        frame = frame.strip("\n\r")
        self.logger.debug("Received IRC Frame %r", frame)
        return frame

    def send(self, msg):
        self.logger.debug("IRC Send %r", msg.encode("utf-8"))
        self.sock.send(msg.encode("utf-8"))
