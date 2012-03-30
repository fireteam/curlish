#!/bin/bash

VIRTUALENV=`which virtualenv`
VIRTUALENV_PATH=~/.ftcurlishvenv

if [ x$VIRTUALENV == x ]; then
  echo "Install script requires virtualenv.  Please install it first"
  echo "You can do so with the following command:"
  echo

  HAS_PIP=`which pip`
  if [ x$HAS_PIP == x ]; then
    echo "    sudo easy_install virtualenv"
  else
    echo "    sudo pip install virtualenv"
  fi
  
  echo
  echo "Afterwards run this script again"
  exit
fi

if [ -d $VIRTUALENV_PATH ]; then
  echo "Looks like you already have curlish installed"
  exit
fi

virtualenv --distribute $VIRTUALENV_PATH
. $VIRTUALENV_PATH/bin/activate
pip install curlish

# Link the script to ~/.bin
mkdir -p ~/.bin
ln -s $VIRTUALENV_PATH/bin/curlish ~/.bin
echo "Curlish installed to $VIRTUALENV_PATH"
echo "We also symlinked it to ~/.bin"
echo "Add it to your PATH if you haven't so far"
