#!/bin/bash

# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

add_dns() {
  if [ -x /opt/zextras/common/sbin/unbound ]; then
    /opt/zextras/common/sbin/unbound-checkconf -o interface | (
      while read -r interface; do
        if [ "$interface" = 127.0.0.1 ]; then
          if ! grep -q 127.0.0.1 /etc/resolv.conf; then
            sed -i '1s|^|nameserver 127.0.0.1\n|' /etc/resolv.conf
          fi
        elif [ "$interface" = ::1 ]; then
          if ! grep -q ::1 /etc/resolv.conf; then
            sed -i '1s|^|nameserver ::1\n|' /etc/resolv.conf
          fi
        fi
      done
    )
  fi
}

remove_dns() {
  if [ -x /opt/zextras/common/sbin/unbound ]; then
    /opt/zextras/common/sbin/unbound-checkconf -o interface | (
      while read -r interface; do
        if [ "$interface" = 127.0.0.1 ]; then
          if ! grep -q 127.0.0.1 /etc/resolv.conf; then
            sed -i '/nameserver 127.0.0.1/d' /etc/resolv.conf
          fi
        elif [ "$interface" = ::1 ]; then
          if ! grep -q ::1 /etc/resolv.conf; then
            sed -i '/nameserver ::1/d' /etc/resolv.conf
          fi
        fi
      done
    )
  fi
}

case "$1" in
  add)
    add_dns
    ;;
  remove)
    remove_dns
    ;;
  *)
    echo "Usage: $0 add|remove"
    exit 1
    ;;
esac
