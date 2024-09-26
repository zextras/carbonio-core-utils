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
  echo "zmmytop [-h] [-r]"
  echo "-h: Display this message"
  echo "-r: Connect as root user (Default: connect as Zimbra user)"
  echo "--[no]color : Use color Default: use color if available"
  echo "--delay <seconds>: How long between display refreshes. Default: 5"
  echo "--batch : In batch mode, mytop runs only once, does not clear the screen, and places no limit on the number of lines it will print."
  echo "--[no]header : Display header"
  echo "--[no]idle : Specify if you want idle (sleeping) threads to appear in the list."
  echo "--[no]resolve : If you have skip-resolve set on MySQL (to keep it from doing a reverse"
  echo "                DNS lookup on each inbound connection), mytop can replace IP addresses with hostnames"
  echo "                Default: noresolve"
  exit 0
fi

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars

if [ -x "/opt/zextras/common/bin/mytop" ]; then
  if [ "$1" = "-r" ]; then
    shift
    /opt/zextras/common/bin/mytop \
      -u root -S /run/carbonio/mysql.sock -p "$mysql_root_password" "$@"
  else
    /opt/zextras/common/bin/mytop \
      -u "$zimbra_mysql_user" \
      -S /run/carbonio/mysql.sock \
      -p "$zimbra_mysql_password" "$@"
  fi
fi
