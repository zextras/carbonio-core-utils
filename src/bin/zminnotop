#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ "$(whoami)" != zextras ]; then
  echo "Error: must be run as zextras user"
  exit 1
fi

if [ ! -x /opt/zextras/common/bin/mysql ]; then
  echo "Error: mariadb not available"
  exit 1
fi

if [ "$1" = "-h" ]; then
  echo "Usage"
  echo "zminnotop [-h] [-r]"
  echo "-h: Display this message"
  echo "-r: Connect as root user (Default: connect as Zimbra user)"
  echo "--[no]color   -C   Use terminal coloring (default)"
  echo "--count            Number of updates before exiting"
  echo "--delay       -d   Delay between updates in seconds"
  echo "--[no]inc     -i   Measure incremental differences"
  echo "--mode        -m   Operating mode to start in"
  echo "--nonint      -n   Non-interactive, output tab-separated fields"
  echo "--spark            Length of status sparkline (default 10)"
  echo "--timestamp   -t   Print timestamp in -n mode (1: per iter; 2: per line)"
  echo "--version          Output version information and exit"
  exit 0
fi

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars

if [ -x "/opt/zextras/common/bin/innotop" ]; then
  if [ "$1" = "-r" ]; then
    shift
    /opt/zextras/common/bin/innotop \
      --socket /run/carbonio/mysql.sock \
      --user root --password "$mysql_root_password" "$@"
  else
    /opt/zextras/common/bin/innotop \
      --socket /run/carbonio/mysql.sock \
      --user "$zimbra_mysql_user" \
      --password "$zimbra_mysql_password" "$@"
  fi
fi
