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

import json
import logging
from hashlib import md5
from urllib import urlencode
from httplib import HTTPConnection, HTTPSConnection
from collections import OrderedDict

from settings import *

cleverbot_keys = ["stimulus","start","sessionid","vText8","vText7","vText6","vText5",
                "vText4","vText3","vText2","icognoid","icognocheck","fno","prevref",
                "emotionaloutput","emotionalhistory","asbotname","ttsvoice",
                "typing","lineref","sub","islearning","cleanslate"]
cleverbot_response_keys = ["stimulus", "sessionid", "", "vText8", "vText7", "vText6", "vText5",
                        "vText4", "vText3", "vText2", "prevref","","","","","","","","","","","","",""]
cleverbot_start_vals = ["","y","","","","","","","","","wsf","","0","","","","","","","","Say","1","false"]

# A client for all the various APIs used by Naoko
# Responsible for making requests and returning responses
class APIClient(object):
    def __init__(self, keys):
        self.logger = logging.getLogger("apiclient")
        self.logger.setLevel(LOG_LEVEL)
        self.logger.debug("Initializing APIClient")
        self.keys = keys
        self.clever = OrderedDict(zip(cleverbot_keys, cleverbot_start_vals))
    
    def getVideoInfo(self, site, vid):
        if site == "yt":
            return self._getYoutubeVideoInfo(vid)
        elif site == "dm" or site == "sc" or site == "vm":
            # Support for these sites (and maybe blip.tv) forthcoming.
            return "TODO"
        else:
            return "Unknown"

    # Cleverbot
    # Some details taken from https://gist.github.com/967404
    def cleverbot(self, text):
        con = HTTPConnection("www.cleverbot.com", timeout=10)
        headers = { "Origin"        : "http://cleverbot.com",
                    "Referer"       : "http://cleverbot.com/",
                    "Content-Type"  : "application/x-www-form-urlencoded",
                    "Cache-Control" : "no-cache"}
        self.clever["stimulus"] = text
        data = None
        try:
            self.clever["icognocheck"] = md5(urlencode(self.clever)[9:29]).hexdigest()
            con.request("POST", "/webservicemin", urlencode(self.clever), headers)
            data = con.getresponse().read()
            if data.find("<!-- too busy -->") != -1:
                data = "Cleverbot is too busy."
            else:
                data = data.split("\r")
                self.clever.update(((k,v) for k, v in zip(cleverbot_response_keys, data) if k))
                data = self.clever["stimulus"]
        except Exception as e:
            self.logger.warning("Cleverbot Error")
            self.logger.debug(e)
            data = "Error communicating with Cleverbot."
        finally:
            con.close()
            return data

    # Translates text from src to dst.
    # If srcLang is None the Microsoft Translator will attempt to guess the language.
    # Returns -1 if there's no id or secret to use to get an access token.
    def translate(self, text, src, dst):
        if not self.keys.mst_id or not self.keys.mst_secret: return -1
        token = self._getMSTAccessToken()
        if not token: return ""
        out = (self._MSTranslate(token, text, src, dst) or "").decode("utf-8")
        # Highly unlikely that any valid translation contains the following
        if out.find("<h1>Argument Exception</h1>") != -1: return ""
        return out[out.find(">") + 1:out.rfind("<")]

    def _MSTranslate(self, token, text, src, dst):
        self.logger.debug("Attempting to translate %r from %s to %s" % (text, src, dst))
        con = HTTPConnection("api.microsofttranslator.com", timeout=10)
        params = {  "appId"         : "Bearer " + token,
                    "text"          : text.encode("utf-8"),
                    "to"            : dst.encode("utf-8"),
                    "contentType"   : "text/plain"}
        if src:
            params["from"] = src.encode("utf-8")
        out = None
        try:
            con.request("GET", "/V2/Http.svc/Translate?%s" % (urlencode(params)))
            out = con.getresponse().read()
        except Exception as e:
            self.logger.warning("Translation failed.")
            self.logger.debug(e)
        finally:
            con.close()
            return out

    # Get the temporary access token for Microsoft Translate using the provided client id and secret.
    def _getMSTAccessToken(self):
        self.logger.debug("Retrieving Microsoft Translate access token.")
        con = HTTPSConnection("datamarket.accesscontrol.windows.net", timeout=10)
        body = {"client_id"         : self.keys.mst_id.encode("utf-8"),
                "client_secret"     : self.keys.mst_secret.encode("utf-8"),
                "grant_type"        : "client_credentials",       
                "scope"             : "http://api.microsofttranslator.com"}
        accessToken = None
        try:
            con.request("POST", "/v2/OAuth2-13", urlencode(body))
            accessToken = json.loads(con.getresponse().read())["access_token"]
        except Exception as e:
            self.logger.warning("Failed to retrieve a valid access token.")
            self.logger.debug(e)
        finally:
            con.close()
            return accessToken

    # Get information on videos from various video APIs.
    # Take in video ids, and return a tuple containing the title, duration, and whether embedding is allowed.
    # Return False when a video is invalid or the API response is malformed.

    def _getYoutubeVideoInfo(self, vid):
        data = self._getYoutubeAPIVidInfo(vid) 
        if isinstance(data, dict) and not "error" in data:
            try:
                data = data["data"]
                return (data["title"], data["duration"], data["accessControl"]["embed"] == "allowed")
            except (TypeError, ValueError, KeyError) as e:
                # Improperly formed Youtube API response
                self.logger.warning("Invalid Youtube API response.")
        return False

    def _getYoutubeAPIVidInfo(self, vid):
        self.logger.debug("Retrieving video information from the Youtube API.")
        con = HTTPSConnection("gdata.youtube.com", 443, timeout=10)
        params = {'v' : 2, 'alt': 'jsonc'}
        data = None
        try:
            con.request("GET", "/feeds/api/videos/%s?%s" % (vid, urlencode(params)))
            data = json.loads(con.getresponse().read())
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Youtube API information.")
            self.logger.debug(e)
        finally:
            con.close()
            return data
