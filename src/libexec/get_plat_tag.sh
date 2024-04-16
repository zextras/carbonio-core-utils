#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ -f /etc/redhat-release ]; then
  i=$(uname -i)
  if [[ "$i" == "x86_64" ]] || [[ "$i" == "ppc64"* ]]; then
    i="_64"
  else
    i=""
  fi

  grep "Red Hat Enterprise Linux.*release 8" /etc/redhat-release >/dev/null 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "RHEL8${i}"
    exit 0
  fi

  grep "CentOS Linux release 8" /etc/redhat-release >/dev/null 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "RHEL8${i}"
    exit 0
  fi

  grep "Red Hat Enterprise Linux.*release" /etc/redhat-release >/dev/null 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "RHELUNKNOWN${i}"
    exit 0
  fi
  grep "CentOS release" /etc/redhat-release >/dev/null 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "CentOSUNKNOWN${i}"
    exit 0
  fi
fi

if [ -f /etc/lsb-release ]; then
  LSB="lsb_release"
  i=$(dpkg --print-architecture)
  if [ "$i" = "amd64" ]; then
    i="_64"
  else
    i=""
  fi
  RELEASE=$($LSB -s -c)
  DISTRIBUTOR=$($LSB -s -i)
  if [ "$DISTRIBUTOR" = "Ubuntu" ]; then
    echo -n "UBUNTU"
    if [ "$RELEASE" = "jammy" ]; then
      echo "22${i}"
      exit 0
    fi
    if [ "$RELEASE" = "focal" ]; then
      echo "20${i}"
      exit 0
    fi
    echo "UNKNOWN${i}"
    exit 0
  fi
fi

if [ -f /etc/debian_version ]; then
  echo "DEBIANUNKNOWN${i}"
  exit 0
fi

echo "UNKNOWN${i}"
exit 1
