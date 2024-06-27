#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ "$(whoami)" != zextras ]; then
  echo "Error: must be run as zextras user"
  exit 1
fi

umask 027

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars -f

export JAVA_HOME=${zimbra_java_home}

zimbra_conf_directory=/opt/zextras/conf
zimbra_domain_cert_directory="${zimbra_conf_directory}/domaincerts"

# this avoid "unable to write 'random state' errors from openssl
export RANDFILE=/opt/zextras/ssl/.rnd

ERROR_PREFIX="ERROR:"

saveConfigKey() {
  local key=$1
  local file=$2
  local location=$3
  local content
  content=$(cat "${file}")
  zmprov_opts=()
  if [ "$location" = "global" ]; then
    zmprov_opts=("${zmprov_opts[@]}" mcf)
  elif [ "$location" = "server" ]; then
    zmprov_opts=("${zmprov_opts[@]}" ms "${zimbra_server_hostname}")
  elif [ "$location" = "domain" ]; then
    local domain=$4
    zmprov_opts=("${zmprov_opts[@]}" md "${domain}")
  else
    echo "Unknown config section $location"
    return
  fi

  echo -n "** Saving $location config key $key..."
  /opt/zextras/bin/zmprov -m -l "${zmprov_opts[@]}" "${key}" "$content" 2>/dev/null
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "done."
  else
    echo "failed."
  fi
}

loadConfigKey() {
  local key=$1
  local file=$2
  local location=$3
  zmprov_opts=()
  if [ "$location" = "global" ]; then
    zmprov_opts=("${zmprov_opts[@]}" gacf)
  elif [ "$location" = "server" ]; then
    local server=$4
    if [ "${server}" = "" ]; then
      server=${zimbra_server_hostname}
    fi
    zmprov_opts=("${zmprov_opts[@]}" gs "${server}")
  elif [ "$location" = "domain" ]; then
    local domain=$4
    zmprov_opts=("${zmprov_opts[@]}" gd "${domain}")
  else
    echo "Unknown config section $location"
    return
  fi
  TMPDIR="${zimbra_tmp_directory}"
  local tmpfile
  tmpfile=$(mktemp -t zmcertmgr.XXXXXX 2>/dev/null) || {
    echo "Failed to create tmpfile"
    exit 1
  }
  if [ -s "${file}" ]; then
    cp -a "${file}" "${file}.$(date +%Y%m%d)"
  fi
  echo -n "** Retrieving $location config key $key..."
  /opt/zextras/bin/zmprov -m -l "${zmprov_opts[@]}" "${key}" | sed -e "s/^${key}: //" >"${tmpfile}" 2>/dev/null
  rc=$?
  if [ $rc -eq 0 ] && [ -s "${tmpfile}" ]; then
    chmod 400 "${tmpfile}"
    mv -f "${tmpfile}" "${file}"
    echo "done."
  else
    echo "failed."
  fi
  rm -f "${tmpfile}" 2>/dev/null
}

deployCerts() {
  if [ "$1" = "-force" ] && [ -d "${zimbra_domain_cert_directory}" ]; then
    rm -rf "${zimbra_domain_cert_directory}" >/dev/null 2>&1
  fi

  DOMAINS=$(/opt/zextras/bin/zmprov -m -l garpd | awk '{print $1}')
  rc=$?
  if [ $rc != 0 ]; then
    echo "$ERROR_PREFIX zmprov -m -l getAllReverseProxyDomains failed (rc=$rc)."
    exit 1
  fi

  if [ "$DOMAINS" = "" ]; then
    echo "No domains returned by zmprov getAllReverseProxyDomains."
    echo "Consider setting zimbraVirtualHostname."
    exit 1
  fi

  for i in $DOMAINS; do
    echo -n "** Deploying cert for ${i}..."
    getDomainCertFromLdap "$i" >/dev/null 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
      echo "done."
    else
      echo "failed."
    fi
  done
}

saveDomainCertToLdap() {
  domain=$1
  current_crt=$2
  current_key=$3
  if [ "$domain" = "" ]; then
    echo "$ERROR_PREFIX Domain must be specified."
    return
  fi
  if [ ! -e "${current_crt}" ]; then
    echo "$ERROR_PREFIX Certificate file ${current_crt} does not exist."
    return
  fi
  if [ ! -e "${current_key}" ]; then
    echo "$ERROR_PREFIX Private key file ${current_key} does not exist."
    return
  fi

  saveConfigKey "zimbraSSLCertificate" "${current_crt}" "domain" "${domain}"
  saveConfigKey "zimbraSSLPrivateKey" "${current_key}" "domain" "${domain}"
}

getDomainCertFromLdap() {
  domain=$1
  if [ "$domain" = "" ]; then
    echo "$ERROR_PREFIX Domain must be specified"
  fi
  if [ ! -d "${zimbra_domain_cert_directory}" ]; then
    install -dm755 "${zimbra_domain_cert_directory}"
  fi
  current_crt="${zimbra_domain_cert_directory}/${domain}.crt"
  current_key="${zimbra_domain_cert_directory}/${domain}.key"

  loadConfigKey "zimbraSSLCertificate" "${current_crt}" "domain" "${domain}"
  loadConfigKey "zimbraSSLPrivateKey" "${current_key}" "domain" "${domain}"
}

###Main Execution###

usage() {
  echo "Usage: "
  echo "  $0 -help"
  echo "  $0 deploycrts"
  echo "  $0 savecrt <domain> <cert file> <private key file>"
  echo
  echo "Comments:  "
  echo "-  deploycrts"
  echo "-  savecrt"
  echo

  exit 1
}

if [ $# = 0 ]; then
  usage
fi

ACTION=$1
shift

# check for valid usage
if [ "$ACTION" = "deploycrts" ]; then
  deployCerts "$@"
elif [ "$ACTION" = "savecrt" ]; then
  saveDomainCertToLdap "$@"
elif [ "$ACTION" = "-help" ] || [ "$ACTION" = "help" ] || [ "$ACTION" = "-h" ] || [ "$ACTION" = "--help" ]; then
  usage
else
  usage
fi

exit 0
