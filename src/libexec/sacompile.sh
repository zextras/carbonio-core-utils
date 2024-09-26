#!/bin/bash

# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ ! -x /opt/zextras/common/sbin/amavisd ]; then
  echo "Error: Must be run on an MTA"
  exit 1
fi

if [ "$(whoami)" != zextras ]; then
  echo Error: must be run as zextras user
  exit 1
fi

re2c=$(which re2c)
if [ "$re2c" = "" ]; then
  echo "Error: re2c is required to compile rules"
  exit 1
fi

make=$(which make)
if [ "$make" = "" ]; then
  echo "Error: make is required to compile rules"
  exit 1
fi

NICE=$(which nice)
if [ "$NICE" = "" ]; then
  /opt/zextras/common/bin/sa-compile >/dev/null 2>&1
else
  NICED="$NICE -n 19"
  $NICED /opt/zextras/common/bin/sa-compile >/dev/null 2>&1
fi
