#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars

while getopts "h" flag; do
  if [ "$flag" == "h" ]; then
    echo "Usage: $0 [-h]"
    echo "    Dumps various environment information"
    echo "    -h: This help information"
    exit 0
  fi
done

echo "----------------"
date +%Y%m%d%H%M%S
echo "----------------"
id
echo "----------------"
uname -a
echo "----------------"
hostname
echo "----------------"
H=$(/opt/zextras/bin/zmhostname)
echo "$H"
echo "----------------"
host "$H"
echo "----------------"
df -h
echo "----------------"
/sbin/ifconfig
echo "----------------"

echo "----------------"
ls -l /opt/zextras
echo "----------------"
uptime
echo "----------------"
memkb=$(zmsysmemkb)
echo "$memkb KB"
echo "----------------"
echo "----------------"
freemem=$(free -m)
echo "FREE $freemem KB"
echo "----------------"
echo "----------------"
cat /etc/hosts
echo "----------------"
cat /etc/resolv.conf
echo "----------------"
cat /etc/nsswitch.conf
echo "----------------"
if [ -x "/usr/sbin/selinux" ]; then
  /usr/sbin/selinux
fi
echo "----------------"
ls -ld /usr/lib/libstdc++*
if [ -d "/usr/lib64" ]; then
  ls -ld /usr/lib64/libstdc++*
fi
echo "----------------"
