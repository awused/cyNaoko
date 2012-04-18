#!/usr/bin/env python
# Contains settings that are relevant in multiple places

import logging

# Default timeout for both the monitoring process and the heartbeat thread
TIMEOUT   = 30

LOG_LEVEL = logging.DEBUG

# Default Wait when an unknown video is playing in seconds.
DEFAULT_WAIT = 3 * 60 * 60
