#!/bin/bash
# SPDX-FileCopyrightText: 2026 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Compatibility wrapper — translates legacy zmconfigdctl commands to systemctl.

case "$1" in
  start) exec systemctl start carbonio-configd.service ;;
  stop) exec systemctl stop carbonio-configd.service ;;
  restart) exec systemctl restart carbonio-configd.service ;;
  reload) exec systemctl reload carbonio-configd.service ;;
  status) exec systemctl is-active --quiet carbonio-configd.service ;;
  *)
    echo "Usage: $0 {start|stop|restart|reload|status}" >&2
    exit 1
    ;;
esac
