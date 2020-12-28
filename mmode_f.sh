#!/usr/bin/env bash

ip link set  wlx34080432263f down
iw wlx34080432263f set monitor none
ip link set wlx34080432263f up
