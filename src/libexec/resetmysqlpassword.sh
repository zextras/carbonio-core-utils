#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ "$(whoami)" != root ]; then
  echo "Error: must be run as root user"
  exit 1
fi

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars -f

#
# Sanity checks
#
assert -x /opt/zextras/common/bin/mysqladmin
assert -x /opt/zextras/common/bin/mysql
assert -x /opt/zextras/bin/zmlocalconfig
assert -x /opt/zextras/bin/zmcontrol
assert -r "${zimbra_db_directory}/db.sql"
if [ ! -x /opt/zextras/common/bin/mysql ]; then
  echo "Mysql not found on this host."
  exit 1
fi

usage() {
  echo "$0 [-help] password"
}

ask() {
  PROMPT=$1
  DEFAULT=$2

  echo ""
  echo -n "$PROMPT [$DEFAULT] "
  read -r response

  if [ -z "$response" ]; then
    response=$DEFAULT
  fi
}
askYN() {
  PROMPT=$1
  DEFAULT=$2

  if [ "$DEFAULT" = "yes" ] || [ "$DEFAULT" = "Yes" ] || [ "$DEFAULT" = "y" ] || [ "$DEFAULT" = "Y" ]; then
    DEFAULT="Y"
  else
    DEFAULT="N"
  fi

  while true; do
    ask "$PROMPT" "$DEFAULT"
    response=$(perl -e "print lc(\"$response\");")
    if [ -z "$response" ]; then
      :
    else
      if [ "$response" = "yes" ] || [ "$response" = "y" ]; then
        response="yes"
        break
      else
        if [ "$response" = "no" ] || [ "$response" = "n" ]; then
          response="no"
          break
        fi
      fi
    fi
    echo "A Yes/No answer is required"
  done
}

for opt in "$@"; do
  case "$opt" in
    -help | --help | -h)
      usage
      exit 0
      ;;
    --* | -*)
      echo "Unknown option $opt"
      usage
      exit 1
      ;;
    *)
      password=$1
      shift
      ;;
  esac
done

if [ "$password" = "" ]; then
  usage
  exit 1
fi

askYN "WARNING: All zimbra services will be stopped.  Would you like to continue?" "N"
if [ "$response" != "yes" ]; then
  echo "All services must be stopped in order to reset mysql password. Exiting."
  exit
fi

if is_systemd; then
  stop_all_systemd_targets
else
  /opt/zextras/bin/zmcontrol stop
fi

echo "Starting mysqld"
/opt/zextras/common/bin/mysqld_safe --defaults-file="${mysql_mycnf}" --skip-grant-tables --ledir=/opt/zextras/common/sbin &
sleep 10

echo "Changing zextras passwd"
/opt/zextras/bin/mysql -Dmysql -P "${mysql_port}" -e "update user set password=PASSWORD(\"$password\") where user = 'zextras';"
/opt/zextras/bin/zmlocalconfig -f -e zimbra_mysql_password="$password"

echo "Changing root passwd"
/opt/zextras/bin/mysql -Dmysql -P "${mysql_port}"-e "update user set password=PASSWORD(\"$password\") where user = 'root';"
/opt/zextras/bin/zmlocalconfig -f -e mysql_root_password="$password"

echo "Flushing privileges"
/opt/zextras/bin/mysql -Dmysql -P "${mysql_port}"-e "flush privileges;"
if is_systemd; then
  systemctl stop carbonio-appserver-db.service
else
  /opt/zextras/bin/mysql.server stop
fi

echo "Restarting carbonio services"
if is_systemd; then
  start_all_systemd_targets
else
  /opt/zextras/bin/zmcontrol start
fi
