# Naoko - A CyTube bot

## Requirements
- Naoko was developed using Python 2.7.2
- Naoko requires a registered CyTube account, and most functionality does not work properly without being a moderator.
- Due to a bug in OpenSSL 1.0.1 and its interface with Python 2.7.2 some functionality on Linux requires curl to be installed.
    Without curl installed Naoko will be unable to verify Dailymotion videos or properly handle removed videos or videos with embedding disabled.
    She will wait DEFAULT_WAIT, which is set to 3 hours, if a leader changes to a Dailymotion video bypassing the playlist, so curl is strongly recommended.
    This bug does not affect Windows users and they will not need to install any additional programs.
- Running the web server with the fastcgi protocol requires that flup be installed. It can be installed using pip flup or easy\_install flup
- Connecting to Mumble requires protobuf to be installed. See the mumble section for more instructions.

## Usage
<pre>
  git clone git://github.com/Suwako/cyNaoko.git
  cd cyNaoko
  python naoko/main.py
</pre>

Edit the included `naoko.conf` file to control the settings. By default the bot will join room "Science" with the nick "DenshiBot"

Use the `$help` command to get a list of commands and their usage. Rooms will typically want Naoko to clean the playlist and automatically add videos; this can be enabled with `$management on`.

## Interactive Console Usage
By default the interactive console is disabled. Change repl\_port in `naoko.conf` to enable it.
Telnet or another method of sending unencrypted messages to a port is required. Telnet is recommended.

Open an interactive python console with:
<pre>
    telnet localhost 5001
</pre>
- Replace 5001 with your repl\_port

This will open a python console where the object `naoko` is the current instance of the bot. You are able to access all of her member variables and functions. There are several functions designed to be used in the interactive console but most of them are not designed with this in mind. Some knowledge of Naoko and Python in general is necessary to perform more complex tasks.

## Web Server Usage
By default the web server is disabled. Configure the web server in `naoko.conf`
The webserver can be run in two modes: standalone, in which the web server is run as a separate daemon process, and embedded, in which the web server runs as part of Naoko.
Currently standalone mode only works on operating systems that supply a proper fork(), which does not include Windows.

To control standalone mode use:
<pre>
    python naoko/webserver.py start|stop|restart|status
</pre>

The web server can be run either as an http server using the bottle.py development server, which is slow but straightforward, or as a fastcgi server using flup. The fastcgi server only works in standalone mode. 

## Mumble Usage
By default Mumble support is disabled. Configure Mumble support in `naoko.conf`
Mumble support requires Google's protobuf and its python bindings.
Naoko was developed using protobuf 2.5.0. Mumble support was not tested on Windows.

I do not currently provide instructions to get Mumble support working on Windows, but I would be happy to hear about your success or failure on Windows.

See https://developers.google.com/protocol-buffers/docs/overview for instructions on installing protobuf.

After installing protobuf you must compile Mumble.proto in the naoko/lib/mumble directory.

<pre>
    protoc --python-out=. Mumble.proto
</pre>

If there is an error about missing shared libraries try:

<pre>
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
</pre>

Or, for a more permanent solution:

</pre>
    sudo ldconfig /usr/local/lib
</pre>


## History by Desuwa
With Synchtube's demise, our small animu community survived in IRC, waiting for a suitable replacement. Due to the work involved none of us were going to start our own replacement site. With CyTube being open source, actively developed, and not directly tied to any particular Synchtube room it seemed the obvious choice.

The process of porting Naoko to CyTube is ongoing with her most important functionality already reimplemented.

## History by Falaina
This is just a small explanation on how this code relates to the bot that used to be in the synchtube animu room.

I used to run a bot named "Denshi" in the animu synchtube room. Denshi was written in node.js and was written while I was learning the synchtube protocol. As a result Denshi's source is, in all honesty, a complete mess. I used random node.js modules to do silly things and hardcoded paths and values. I probably will not release that source code as it's so shoddy I don't want my named attached to it; additionally it'd be relatively hard to get working on any machine that wasn't her original VPS.

The code in this repository was the beginning of my attempt to rewrite Denshi in Python with minimal use of external libraries so it could be more easily used by others. I didn't get much farther than having it connect and print information. I've decided to release it as it should allow anyone with some knowledge of Python to program a working bot without worrying too much about the socket-level details. In its current state it isn't very useful though.

I encourage anyone to fork this and make a more useful base bot for other channels to use, as I don't have the time to do much other than small bug fixes on this base.
