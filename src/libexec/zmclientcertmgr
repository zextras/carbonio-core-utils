#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ "$(whoami)" != "zextras" ]; then
  echo "$0 must be run as user zextras"
  exit 1
fi
umask 027

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars -f

ERROR_PREFIX="ERROR:"

saveConfigKey() {
  local key=$1
  local file=$2
  local location=$3
  local content
  content=$(cat "$file")
  if [ "$location" = "global" ]; then
    local zmprov_opts="mcf"
  elif [ "$location" = "server" ]; then
    local zmprov_opts="ms ${zimbra_server_hostname}"
  elif [ "$location" = "domain" ]; then
    local domain=$4
    local zmprov_opts="md $domain"
  else
    echo "Unknown config section $location"
    return
  fi

  echo -n "** Saving $location config key $key..."

  if /opt/zextras/bin/zmprov -m -l "${zmprov_opts}" "$key" "$content" 2>/dev/null; then
    echo "done."
  else
    echo "failed."
  fi
}

cleanConfigKey() {
  local key=$1
  local location=$2
  if [ "$location" = "global" ]; then
    local zmprov_opts="mcf"
  elif [ "$location" = "server" ]; then
    local zmprov_opts="ms ${zimbra_server_hostname}"
  elif [ "$location" = "domain" ]; then
    local domain=$3
    local zmprov_opts="md $domain"
  else
    echo "Unknown config section $location"
    return
  fi

  echo -n "** Clean $location config key $key..."
  /opt/zextras/bin/zmprov -m -l "${zmprov_opts}" "$key" "" 2>/dev/null
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "done."
  else
    echo "failed."
  fi
}

saveClientCertToLdap() {
  target=$1
  current_crt=$2
  if [ ! -e "$current_crt" ]; then
    echo "$ERROR_PREFIX Certificate file $current_crt does not exist."
    return
  fi

  if [ "$target" = "global" ]; then
    saveConfigKey "zimbraReverseProxyClientCertCA" "$current_crt" "global"
    return
  fi

  if [ "$target" = "server" ]; then
    saveConfigKey "zimbraReverseProxyClientCertCA" "$current_crt" "server"
    return
  fi

  domain=$target
  if [ "$domain" = "" ]; then
    echo "$ERROR_PREFIX Domain must be specified."
    return
  fi

  saveConfigKey "zimbraReverseProxyClientCertCA" "$current_crt" "domain" "$domain"
}

cleanClientCertFromLdap() {
  target=$1
  if [ "$target" = "global" ]; then
    cleanConfigKey "zimbraReverseProxyClientCertCA" "global"
    return
  fi

  if [ "$target" = "server" ]; then
    cleanConfigKey "zimbraReverseProxyClientCertCA" "server"
    return
  fi

  domain=$target
  if [ "$domain" = "" ]; then
    echo "$ERROR_PREFIX Domain must be specified."
    return
  fi

  cleanConfigKey "zimbraReverseProxyClientCertCA" "domain" "$domain"
}

usage() {
  rc=${1:-1}
  echo "Usage:
  $0 -h | --help
  $0 savecrt <domain> <cert file>
  $0 savecrt server <cert file>
  $0 savecrt global <cert file>
  $0 cleancrt <domain>
  $0 cleancrt server
  $0 cleancrt global
"
  exit "$rc"
}

###Main Execution###

if [[ $# = 0 ]]; then
  usage
fi

ACTION="$1"
shift

# check for valid usage
if [[ "$ACTION" = "savecrt" ]]; then
  saveClientCertToLdap "$@"
elif [[ "$ACTION" = "cleancrt" ]]; then
  cleanClientCertFromLdap "$@"
else
  for arg in "$ACTION" "$@"; do
    [[ "$arg" =~ ^-?-h ]] && usage 0
  done
  echo "$ERROR_PREFIX unknown argument(s): $ACTION" "$@"
  usage
fi

exit 0
