#!/bin/bash

CURL=`which curl`
if [ x$CURL == x ]; then
  echo 'error: curl required to use curlish.  Please install it first.'
  exit 1
fi

echo 'Downloading curlish...'
mkdir -p ~/.bin
curl -s https://raw.github.com/fireteam/curlish/master/curlish.py > ~/.bin/curlish
chmod +x ~/.bin/curlish
echo
echo "Curlish installed successfully to ~/.bin/curlish"
echo "Add ~/.bin to your PATH if you haven't so far:"
echo
echo $'  echo \'export PATH="$PATH:~/.bin"\' >> ~/.bashrc'
