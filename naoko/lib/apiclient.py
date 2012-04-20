#!/usr/bin/env python

import json
import logging
import subprocess
from ssl import SSLError
from urllib import urlencode
from httplib import HTTPConnection, HTTPSConnection

from settings import *


# A client for all the various APIs used by Naoko
# Responsible for making requests and returning responses
class APIClient(object):
    def __init__(self, keys):
        self.logger = logging.getLogger("apiclient")
        self.logger.setLevel(LOG_LEVEL)
        self.logger.debug("Initializing APIClient")
        self.keys = keys
    
    def getVideoInfo(self, site, vid):
        if site == "yt":
            return self._getYoutubeVideoInfo(vid)
        elif site == "bt":
            return self._getBliptvVideoInfo(vid)
        elif site == "sc":
            return self._getSoundcloudVideoInfo(vid)
        elif site == "vm":
            return self._getVimeoVideoInfo(vid)
        elif site == "dm":
            # Support for these sites  forthcoming.
            return "TODO"
        else:
            return "Unknown"

    # Translates text from src to dst.
    # If src is None the Microsoft Translator will attempt to guess the language.
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
        body = {"client_id"         : self.keys.mst_id,
                "client_secret"     : self.keys.mst_secret,
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
        data = self._getYoutubeAPI(vid) 
        if isinstance(data, dict) and not "error" in data:
            try:
                data = data["data"]
                return (data["title"], data["duration"], data["accessControl"]["embed"] == "allowed")
            except (TypeError, ValueError, KeyError) as e:
                # Improperly formed Youtube API response
                self.logger.warning("Invalid Youtube API response.")
        return False

    def _getYoutubeAPI(self, vid):
        self.logger.debug("Retrieving video information from the Youtube API.")
        con = HTTPSConnection("gdata.youtube.com", timeout=10)
        params = {"v" : 2, "alt": "jsonc"}
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

    def _getDailymotionVideoInfo(self, vid):
        data = self._getDailymotionAPI(vid) 
        if isinstance(data, dict) and not "error" in data:
            try:
                return (data["title"], data["duration"], data["allow_embed"])
            except (TypeError, ValueError, KeyError) as e:
                self.logger.warning("Invalid Dailymotion API response.")
        # If 
        if data == "SSL Failure":
            return "Unknown"
        return False

    def _getDailymotionAPI(self, vid):
        self.logger.debug("Retrieving video information from the Dailymotion API.")
        con = HTTPSConnection("api.dailymotion.com", timeout=10)
        params = {"fields", "title,duration,allow_embed"}
        data = None
        try:
            con.request("GET", "/video/%s?fields=title,duration,allow_embed" % (vid))
            data = json.loads(con.getresponse().read())
            #a = subprocess.check_output(["curl", "-k", "-s", "-m 10", "https://api.dailymotion.com/video/xf0akg?fields=title,duration,allow_embed"])
        except SSLError as e:
            # There is a bug in OpenSSL 1.0.1 which affects Python 2.7 on systems that rely on it.
            # Attempt to use curl as a fallback.
            # Curl must be installed.
            # This is the worst hack I have ever coded.
            self.logger.warning("SSL Error, attempting to use curl as a fallback.")
            try:
                data = subprocess.check_output(["curl", "-k", "-s", "-m 10",
                        "https://api.dailymotion.com/video/%s?fields=title,duration,allow_embed" % (vid)])
                data = json.loads(data)
            except Exception as e:
                self.logger.warning("Fallback failed.")
                data = "SSL Failure"
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Dailymotion API information.")
            self.logger.debug(e)
        finally:
            con.close()
            return data

    def _getSoundcloudVideoInfo(self, vid):
        if not self.keys.sc_id: return "Unknown"
        data = self._getSoundcloudAPI(vid)
        if isinstance(data, dict):
            try:
                if not "errors" in data:
                    return (data["title"], data["duration"]/1000.0, data["sharing"] == "public")
                elif json.dumps(data, encoding="utf-8").find("401 - Unauthorized") != -1:
                    return "Unknown"
            except (TypeError, ValueError, KeyError, UnicodeDecodeError) as e:
                self.logger.warning("Invalid Soundcloud API response.")
        return False

    def _getSoundcloudAPI(self, vid):
        self.logger.debug("Retrieving track information from the Soundcloud API.")
        con = HTTPSConnection("api.soundcloud.com", timeout=10)
        params = {"client_id" : self.keys.sc_id}
        data = None
        try:
            con.request("GET", "/tracks/%s.json?%s" % (vid, urlencode(params)))
            data = json.loads(con.getresponse().read())
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Soundcloud API information.")
            self.logger.debug(e)
        finally:
            con.close()
            return data

    def _getVimeoVideoInfo(self, vid):
        data = self._getVimeoAPI(vid)
        if isinstance(data, list):
            try:
                data = data[0]
                return (data["title"], data["duration"], data["embed_privacy"] == "anywhere")
            except (TypeError, ValueError, KeyError) as e:
                self.logger.warning("Invalid Vimeo API response.")
        return False

    def _getVimeoAPI(self, vid):
        self.logger.debug("Retrieving video information from the Vimeo API.")
        con = HTTPConnection("vimeo.com")
        data = None
        try:
            con.request("GET", "/api/v2/video/%s.json" % (vid))
            data = json.loads(con.getresponse().read())
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Vimeo API information.")
            self.logger.debug(e)
        finally:
            con.close()
            return data

    def _getBliptvVideoInfo(self, vid):
        data = self._getBliptvAPI(vid)
        if isinstance(data, dict) and not "error" in data:
            try:
                data = data["Post"]
                return (data["title"], int(data["media"]["duration"]), data["hidden"] == "0")
            except (TypeError, ValueError, KeyError) as e:
                # Improperly formed Blip.tv API response
                self.logger.warning("Invalid Blip.tv API response.")
        return False

    def _getBliptvAPI(self, vid):
        self.logger.debug("Retrieving video information from the Blip.tv API.")
        con = HTTPConnection("blip.tv", timeout = 10)
        params = {"version" : 2, "skin" : "json"}
        data = None
        try:
            con.request("GET", "/posts/%s?%s" % (vid, urlencode(params)))
            data = con.getresponse().read()
            data = data[data.find("[") + 1:data.rfind("]")]
            data = json.loads(data)
        except Exception as e:
            self.logger.warning("Error retrieving Blip.tv API information.")
            self.logger.debug(e)
        finally:
            con.close()
            return data
