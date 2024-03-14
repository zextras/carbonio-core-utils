#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars

antispam_mysql_enabled=$(echo "${antispam_mysql_enabled}" | tr "[:upper:]" "[:lower:]")
if [ "${antispam_mysql_enabled}" != "true" ]; then
  echo "Spamassassin is not set up to use MySQL backend database!  Aborting..."
  exit 1
fi

#
# Usage.
#
usage() {
  cat <<EOF
Usage: $ zmantispamdbpasswd [ --root ] newpassword

By default, this script changes antispam_mysql_password.  If the --root
option is specified, then antispam_mysql_root_password is changed.  In both
cases, MySQL is updated with the new passwords.  This script can not bail
you out of a situation where you have lost your mysql root password -
consult MySQL documentation to see how you can start the server
temporarily to skip grant tables, so you can override the root
password.

EOF
}

#
# Parse command line
#
if [ "$1" = "--root" ]; then
  password_key="antispam_mysql_root_password"
  shift # lose --root option
else
  password_key="antispam_mysql_password"
fi

if [ $# -ne 1 ]; then
  usage
  exit 1
fi
newpassword="$1"

#
# For antispam_mysql_password
#
if [ ${password_key} = antispam_mysql_password ]; then
  # Change the password in mysql.
  cat <<EOF | /opt/zextras/bin/antispam-mysql -u root --password="${antispam_mysql_root_password}"
SET PASSWORD FOR '${antispam_mysql_user}' = PASSWORD('${newpassword}');
SET PASSWORD FOR '${antispam_mysql_user}'@'127.0.0.1' = PASSWORD('${newpassword}');
SET PASSWORD FOR '${antispam_mysql_user}'@'localhost' = PASSWORD('${newpassword}');
SET PASSWORD FOR '${antispam_mysql_user}'@'localhost.localdomain' = PASSWORD('${newpassword}');
EOF
  rc=$?
  if [ $rc -eq 0 ]; then
    echo '*' Changed antispam mysql user password
  else
    echo '****' PASSWORD CHANGE FAILED
    exit 1
  fi
fi

#
# For mysql_root_password
#
if [ ${password_key} = antispam_mysql_root_password ]; then
  echo /opt/zextras/bin/antispam-mysqladmin -u root --password="${antispam_mysql_root_password}" password "${newpassword}"
  /opt/zextras/bin/antispam-mysqladmin -u root --password="${antispam_mysql_root_password}" password "${newpassword}"
  rc=$?
  if [ $rc -eq 0 ]; then
    echo '*' Changed antispam mysql root user password
  else
    echo '****' PASSWORD CHANGE FAILED
    exit 1
  fi
  # Change for localhost socket clients also - useful for dev.
  cat <<EOF | /opt/zextras/bin/antispam-mysql -u root --password="${newpassword}"
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${newpassword}');
SET PASSWORD FOR 'root'@'localhost.localdomain' = PASSWORD('${newpassword}');
EOF
  rc=$?
  if [ $rc -eq 0 ]; then
    echo '*' Changed antispam mysql root user password root@localhost
  else
    echo '****' PASSWORD CHANGE FAILED FOR root@localhost
    exit 1
  fi
fi

#
# Change the password in local config.  TODO: notify app server that
# the password has changed, for now you will have to restart mailboxd
#
if ! /opt/zextras/bin/zmlocalconfig -f -e "${password_key}=${newpassword}"; then
  echo Error: command failed: /opt/zextras/bin/zmlocalconfig -f -e ${password_key}='#'
  exit 1
fi
