#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# shellcheck disable=SC1091
# shellcheck disable=SC2154

if [ "$(whoami)" != "root" ]; then
  echo "Error: must be run as user root"
  exit 1
fi

usage() {
  echo "$0 [--help] [--sql_root_pw <password>] [--mysql_memory_percent 30]"
  echo "  --sql_root_pw defaults to random password if not specified."
  echo "  --mysql_memory_percent defaults to 30 percent if not specified."
}

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars -f

#
# Sanity checks
#
assert -x /opt/zextras/libexec/zmmycnf
assert -x /opt/zextras/bin/mysqladmin
assert -x /opt/zextras/bin/mysql
assert -x /opt/zextras/bin/zmlocalconfig
assert -x /opt/zextras/bin/zmmypasswd
assert -x /opt/zextras/common/share/mysql/scripts/mysql_install_db
assert -r "${zimbra_db_directory}/db.sql"
assert -r "${zimbra_db_directory}/versions-init.sql"

for opt in "$@"; do
  case "$opt" in
    -help | --help | -h)
      usage
      exit 0
      ;;
    -verbose | --verbose | -v | --v)
      verbose=yes
      shift
      ;;
    --sql_root_pw)
      shift
      sql_root_pw=$1
      shift
      ;;
    --mysql_memory_percent)
      shift
      mysql_memory_percent=$1
      shift
      ;;
    --* | -*)
      echo "Unknown option $opt"
      usage
      exit 1
      ;;
  esac
done

mysql_memory_percent=${mysql_memory_percent:=30}
if [ "$verbose" = "yes" ]; then
  echo "mysql_memory_percent=$mysql_memory_percent"
fi

#
# Create necessary directories
#
echo "* Creating required directories"
su - zextras -c "mkdir -p ${mysql_data_directory}"
su - zextras -c "mkdir -p ${zimbra_index_directory}"
su - zextras -c "mkdir -p ${zimbra_store_directory}"
su - zextras -c "mkdir -p ${zimbra_log_directory}"

#
# Generate a mysql config file
#
echo "* Generating mysql config ${mysql_mycnf}"
su - zextras -c "rm -f ${mysql_mycnf}"
su - zextras -c "/opt/zextras/libexec/zmmycnf --innodb-buffer-pool-memory-percent \
  $mysql_memory_percent >${mysql_mycnf}"

#
# Create database
#
echo "* Creating database in ${mysql_data_directory}"
su - zextras -c "
  /opt/zextras/common/share/mysql/scripts/mysql_install_db \
    --basedir=/opt/zextras/common \
    --defaults-file=${mysql_mycnf} \
    >>${zimbra_log_directory}/zmmyinit.log 2>&1"

#
# Start mysql server
#

echo "* Starting mysql server"
if is_systemd; then
  systemctl start carbonio-appserver-db.service
else
  su - zextras -c "/opt/zextras/bin/mysql.server start \
  >>${zimbra_log_directory}/zmmyinit.log 2>&1"
fi

# make sure we can connect before continuing
until echo "show processlist" | /opt/zextras/bin/mysql -u root -p= >/dev/null 2>&1; do
  ((i++))
  sleep 5
  if [ $i -gt 25 ]; then
    echo "* Failed to connect to mysql...giving up!"
    exit 1
  else
    echo "* Failed to connect to mysql...retrying"
  fi
done

#
# Load zimbra sql files
#
echo "* Loading schema ${zimbra_db_directory}/db.sql"
/opt/zextras/bin/mysql -u root -p= < \
  "${zimbra_db_directory}/db.sql"

if [ -f "${zimbra_db_directory}/create_sharing_database.sql" ]; then
  echo "* Loading schema ${zimbra_db_directory}/create_sharing_database.sql"
  /opt/zextras/bin/mysql -u root -p= < \
    "${zimbra_db_directory}/create_sharing_database.sql"
fi

echo "* Loading version from ${zimbra_db_directory}/versions-init.sql"
/opt/zextras/bin/mysql -u root -p= < \
  "${zimbra_db_directory}/versions-init.sql"

if [ -f "${zimbra_db_directory}/backup-version-init.sql" ]; then
  echo "* Loading version from ${zimbra_db_directory}/backup-version-init.sql"
  /opt/zextras/bin/mysql -u root -p= < \
    "${zimbra_db_directory}/backup-version-init.sql"
fi

#
# Delete wildcard user login entries
#
/opt/zextras/bin/mysql -u root -p= \
  -e "DROP USER ''@'localhost'; DROP USER ''@'$(hostname)';"

#
# Generate passwords for mysql into local config
#
if [ "$sql_root_pw" = "" ]; then
  echo "* Setting random passwd for mysql root user in zimbra localconfig"
  su - zextras -c "/opt/zextras/bin/zmlocalconfig -r -f -e mysql_root_password"

  echo "* Setting random passwd for mysql zextras user in zimbra localconfig"
  su - zextras -c "/opt/zextras/bin/zmlocalconfig -r -f -e zimbra_mysql_password"
else
  echo "* Setting passwd for mysql root user in zimbra localconfig"
  su - zextras -c "/opt/zextras/bin/zmlocalconfig -f -e mysql_root_password=$sql_root_pw"
  echo "* Setting passwd for mysql zextras user in zimbra localconfig"
  su - zextras -c "/opt/zextras/bin/zmlocalconfig -f -e zimbra_mysql_password=$sql_root_pw"
fi

#
# Change mysql root user password, but first read back the passwords
# zimbra local config - they was generated above.  Note that we can not
# use 'zmmypasswd --root' here because of bootstrapping problems - at
# this stage we know that the root password is empty.
#
zmsetvars -f
echo "* Changing mysql root user password"
/opt/zextras/bin/mysql -u root -p= \
  -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${mysql_root_password}');"

echo "* Changing mysql zextras user password"
su - zextras -c "/opt/zextras/bin/zmmypasswd ${zimbra_mysql_password}"
