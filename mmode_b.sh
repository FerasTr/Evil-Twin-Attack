#!/usr/bin/env bash

ip link set wlxf4ec388d723b down
iw wlxf4ec388d723b set monitor none
ip link set wlxf4ec388d723b up
