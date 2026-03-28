#!/bin/sh
set -e

CONNECT="${CONNECT_ADDR:?CONNECT_ADDR is required}"

exec ./vk-turn-proxy -listen 0.0.0.0:56000 -connect "$CONNECT"
