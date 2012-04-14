#!/bin/bash

BIN_DIR="~/.bin";
if [ -n "$1" ]; then
  BIN_DIR="$1";
fi

echo $BIN_DIR;

CURL=curl

if [ -z $(which "$CURL") ]; then
  echo 'error: curl required to use curlish.  Please install it first.'
  exit 1
fi

echo 'Downloading curlish...'
mkdir -p $BIN_DIR
curl -s https://raw.github.com/fireteam/curlish/master/curlish.py > $BIN_DIR/curlish
chmod +x $BIN_DIR/curlish
echo
echo "Curlish installed successfully to $BIN_DIR/curlish"
echo "Add $BIN_DIR to your PATH if you haven't so far:"
echo
echo -n $'  echo \'export PATH="$PATH:';
echo "$BIN_DIR\"' >> ~/.bashrc";
