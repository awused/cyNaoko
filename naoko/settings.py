#!/usr/bin/env python
# Contains settings that are relevant in multiple places

import logging

# Default timeout for both the monitoring process and the heartbeat thread
TIMEOUT   = 30

LOG_LEVEL = logging.DEBUG

# Default wait when an unknown video is playing in seconds.
DEFAULT_WAIT = 3 * 60 * 60

# The minimum time, in seconds, between storing the count of users in the room.
# Only increase this if she is logging too often in a busy room and wasting too much space.
USER_COUNT_THROTTLE = 0

# The port used by the repl loop for debugging/etc. Do not use a port that is in use.
# If it is 0 the repl loop will be disabled.
REPL_PORT = 5002

# The time between status checks
HEARTBEAT_CHECK = 5

# The domain name Naoko connects to. Right now only www.synchtube.com is going to work.
DOMAIN = "cytube.calzoneman.net"
# Need to hardcode Synchtube's IP
SOCKET_IP = "173.255.204.78"

# The minimum time between API requests in seconds
API_THROTTLE = 0.5
