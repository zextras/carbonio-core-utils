#!/bin/bash
# SPDX-FileCopyrightText: 2026 Zextras <https://www.zextras.com>
# SPDX-License-Identifier: GPL-2.0-only
# Compatibility wrapper — delegates zmcontrol to configd control.

CONFIGD=/opt/zextras/bin/configd

if [ ! -x "$CONFIGD" ]; then
  echo "Error: configd binary not found at $CONFIGD" >&2
  exit 1
fi

# Map zmcontrol flags/commands to configd equivalents
case "$1" in
  -v) exec "$CONFIGD" release ;;
  -V) exec "$CONFIGD" release --packages ;;
  -h | --help)
    echo "Usage: zmcontrol <start|stop|restart|status> [-v|-V|-h]"
    exit 0
    ;;
  -H)
    echo "Warning: remote execution (-H) is not supported by configd" >&2
    exit 1
    ;;
  start | startup) exec "$CONFIGD" control start ;;
  stop | shutdown) exec "$CONFIGD" control stop ;;
  restart) exec "$CONFIGD" control restart ;;
  status) exec "$CONFIGD" control status ;;
  *)
    echo "Usage: zmcontrol <start|stop|restart|status> [-v|-V|-h]" >&2
    exit 1
    ;;
esac
