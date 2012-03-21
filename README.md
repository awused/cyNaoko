# Naoko - A Synchtube bot

## Requirements
- Naoko was developed using Python 2.7.2

## Usage
<pre>
  git clone git://github.com/Suwako/Naoko.git
  cd Naoko
  python main.py
</pre>

Edit the included `naoko.conf` file to control the settings. By default the bot will join room "Denshi" with the nick "DenshiBot"

## History by Falaina
This is just a small explanation on how this code relates to the bot that used to be in the synchtube animu room.

I used to run a bot named "Denshi" in the animu synchtube room. Denshi was written in node.js and was written while I was learning the synchtube protocol. As a result Denshi's source is, in all honesty, a complete mess. I used random node.js modules to do silly things and hardcoded paths and values. I probably will not release that source code as it's so shoddy I don't want my named attached to it; additionally it'd be relatively hard to get working on any machine that wasn't her original VPS.

The code in this repository was the beginning of my attempt to rewrite Denshi in Python with minimal use of external libraries so it could be more easily used by others. I didn't get much farther than having it connect and print information. I've decided to release it as it should allow anyone with some knowledge of Python to program a working bot without worrying too much about the socket-level details. In its current state it isn't very useful though.

I encourage anyone to fork this and make a more useful base bot for other channels to use, as I don't have the time to do much other than small bug fixes on this base.