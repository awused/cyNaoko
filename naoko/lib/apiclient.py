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
import urllib, urlparse, httplib
from collections import namedtuple

from settings import *

# A client for all the various APIs used by Naoko
# Responsible for making requests and returning responses
class APIClient(object):
    def __init__(self, keys):
        self.logger = logging.getLogger("apiclient")
        self.logger.setLevel(logLevel)
        self.logger.debug("Initializing APIClient")
        self.keys = keys

    # Grab relevant information from a reponse from the Youtube API packed in a tuple
    # Returns False if there was an error of any kind
    def getYoutubeVideoInfo(self, vid):
        data = self._getYoutubeAPIVidInfo(vid) 
        if isinstance(data, dict) and not "error" in data:
            try:
                data = data["data"]
                return (data["title"], data["duration"], data["accessControl"]["embed"] == "allowed")
            except (TypeError, ValueError, KeyError) as e:
                # Improperly formed Youtube API response
                self.logger.warning("Invalid Youtube API response.")
        return False

    # Fetch Youtube API information for a single video and unpack it
    def _getYoutubeAPIVidInfo(self, vid):
        self.logger.debug("Retrieving video information from the Youtube API.")
        con = httplib.HTTPSConnection("gdata.youtube.com", 443, timeout=10)
        params = {'v' : 2, 'alt': 'jsonc'}
        data = None
        try:
            con.request("GET", "/feeds/api/videos/%s?%s" % (vid, urllib.urlencode(params)))
            data = json.loads(con.getresponse().read())
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Youtube API information.")
            self.logger.debug(e)
        finally:
            con.close()
            return data
