#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

if [ "$(whoami)" != zextras ]; then
  echo "Error: must be run as zextras user"
  exit 1
fi

function chk_command() {
  for cmd in "$@"; do
    if [ ! -x "$cmd" ]; then
      echo "error: unable to find the command '${cmd##*/}'"
      exit 1
    fi
  done
}

ldapsearch="/opt/zextras/common/bin/ldapsearch"
zmhostname="/opt/zextras/bin/zmhostname"
zmlocalconfig="/opt/zextras/bin/zmlocalconfig"
zmprov="/opt/zextras/bin/zmprov"

chk_command $ldapsearch $zmhostname $zmlocalconfig $zmprov

hostname=$($zmhostname)

# NOTE: ldap_url may be multi-valued
if ! eval "$(${zmlocalconfig} -q -m export ldap_url zimbra_ldap_userdn zimbra_ldap_password)"; then
  echo "Error: executing: ${zmlocalconfig} -q -m export"
  exit 1
fi

zmgetallproxies_cache="unknown"
zmgetallproxies() {
  if [ $zmgetallproxies_cache = "unknown" ]; then
    ldap_urls=("$ldap_url")
    search=$(${ldapsearch} -LL -H "${ldap_urls[@]}" -D "$zimbra_ldap_userdn" -w "$zimbra_ldap_password" \
      -b 'cn=servers,cn=zimbra' '(&(objectClass=zimbraServer)(zimbraServiceEnabled=proxy))' cn 2>/dev/null)
    rc=$?
    if [ $rc -eq 0 ]; then
      zmgetallproxies_cache=$(echo "$search" | awk '/cn:/ {print $2}')
    else
      zmgetallproxies_cache=""
    fi
  fi
  echo "$zmgetallproxies_cache"
}

zmgetproxyforhost() {
  host=$1
  ldap_urls=("$ldap_url")
  # First, see if there is a proxy (or proxies) sepcifically designated for this host
  proxies=
  search=$($ldapsearch -LL -H "${ldap_urls[@]}" -D "$zimbra_ldap_userdn" -w "$zimbra_ldap_password" \
    -b 'cn=servers,cn=zimbra' "(&(objectClass=zimbraServer)(zimbraReverseProxyAvailableLookupTargets=*$host*))" \
    cn 2>/dev/null)

  rc=$?
  if [ $rc -eq 0 ]; then
    proxies=$(echo "$search" | awk '/cn:/ {print $2}')
    if [ "${proxies}" != "" ]; then
      echo "$proxies"
      return
    fi
  fi
  # If not, just return the list of all proxies and we will use the first one that works
  zmgetallproxies
}

validate_setting=1
zmvalidatehost() {
  foundhost=0
  hosts=$(${zmprov} garpb | awk '/server/ {split($2,parts,":"); print parts[1]}')
  for h in "${hosts[@]}"; do
    if [ "$hostname" = "$h" ]; then
      foundhost=1
      break
    fi
  done
  if [ $foundhost -eq 1 ]; then
    allproxies=$(zmgetallproxies)
    if [ "$allproxies" != "" ]; then
      return
    else
      echo "Warning: No proxy servers were detected. No validation will be performed."
    fi
  else
    echo "Warning: $hostname is not in the list of reverse proxy backends. No validation will be performed."
  fi
  validate_setting=0
}
zmvalidatehost

usage() {
  exitcode=$1
  if [ $validate_setting -eq 1 ]; then
    echo "Usage: $0 [both|http|https|help]"
  else
    echo "Usage: $0 [both|http|https|redirect|mixed|help]"
  fi
  exit "$exitcode"
}

if [ $# -gt 1 ]; then
  usage 1
fi

case "$1" in
  both | http | https | mixed | redirect)
    MODE=$1
    UPDATE_MAIL_MODE=1
    ;;
  help | --help | -help)
    usage 0
    ;;
  '') ;;

  *)
    usage 1
    ;;
esac

export JAVA_HOME=${zimbra_java_home}

if [ "${zimbra_tmp_directory}" = "" ]; then
  zimbra_tmp_directory=/opt/zextras/data/tmp
fi
if [ ! -d "${zimbra_tmp_directory}" ]; then
  mkdir -p "${zimbra_tmp_directory}"
fi

rewrite_configs() {
  echo -n "Rewriting config files for cyrus-sasl, webxml, mailboxd, service, zimbraUI, and zimbraAdmin..."
  /opt/zextras/libexec/configrewrite sasl webxml mailbox service zextras zextrasAdmin zimlet >/dev/null 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "done."
  else
    echo "failed."
    exit 1
  fi
}

updateLdap() {
  proxies=$(zmgetproxyforhost "$hostname")
  if [ $validate_setting -eq 1 ] && [ "$proxies" != "" ]; then
    # check the value of zimbraReverseProxySSLToUpstreamEnabled and zimbraReverseProxyMailMode
    # on a suitable proxy server
    sslup=
    rpmm=
    for proxy in "${proxies[@]}"; do
      echo "Attempting to query proxy ($proxy) settings for zimbraReverseProxyMailMode and zimbraReverseProxySSLToUpstreamEnabled."
      setting=$(/opt/zextras/bin/zmprov -l gs "${proxy}" zimbraReverseProxySSLToUpstreamEnabled zimbraReverseProxyMailMode)
      rc=$?
      if [ $rc -eq 0 ]; then
        sslup=$(echo "$setting" | awk '/zimbraReverseProxySSLToUpstreamEnabled:/ {print $2}')
        rpmm=$(echo "$setting" | awk '/zimbraReverseProxyMailMode:/ {print $2}')
        break
      fi
    done
    if [ "$sslup" = "" ]; then
      echo "Error: Unable to determine the proxy's value of zimbraReverseProxySSLToUpstreamEnabled"
      exit 1
    fi
    if [ "$rpmm" = "" ]; then
      echo "Error: Unable to determine the proxy's value of zimbraReverseProxyMailMode"
      exit 1
    fi
    # validate setting of zimbraReverseProxyMailMode based on the setting of zimbraReverseProxySSLToUpstreamEnabled
    echo "On proxy ($proxy): zimbraReverseProxyMailMode='$rpmm', zimbraReverseProxySSLToUpstreamEnabled='$sslup'"
    if [ "$sslup" = "TRUE" ] && [ "$rpmm" != "https" ] && [ "$rpmm" != "redirect" ]; then
      echo "Error: When zimbraReverseProxySSLToUpstreamEnabled (on the proxy server) is TRUE, zimbraReverseProxyMailMode must be one of the following: https or redirect. Please correct this on the proxy server then retry this command."
      exit 1
    fi
    if [ "$sslup" = "FALSE" ] && [ "$rpmm" != "both" ] && [ "$rpmm" != "http" ]; then
      echo "Error: When zimbraReverseProxySSLToUpstreamEnabled (on the proxy server) is FALSE, zimbraReverseProxyMailMode must be one of the following: both or http. Please correct this on the proxy server then retry this command."
      exit 1
    fi
    # Validate the new setting of zimbraMailMode based on the setting of zimbraReverseProxyMailMode
    if [ "$rpmm" = "https" ] && [ "$MODE" != "both" ] && [ "$MODE" != "https" ]; then
      echo "Error: When zimbraReverseProxyMailMode (on the proxy server) is https, the only valid settings for zimbraMailMode are both or https."
      exit 1
    fi

    if [ "$rpmm" = "redirect" ] && [ "$MODE" != "both" ] && [ "$MODE" != "https" ]; then
      echo "Error: When zimbraReverseProxyMailMode (on the proxy server) is redirect, the only valid settings for zimbraMailMode are both or https."
      exit 1
    fi
  fi

  tmpfile=$(mktemp "${zimbra_tmp_directory}/zmprov.XXX" 2>/dev/null) || {
    echo "Failed to create tmpfile"
    exit 1
  }
  echo -n "Attempting to set ldap config zimbraMailMode $MODE on host ${hostname}..."
  /opt/zextras/bin/zmprov -l ms "${hostname}" zimbraMailMode "$MODE" >/dev/null 2>"$tmpfile"
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "done."
    rm "$tmpfile"
    return
  fi
  echo "failed."
  cat "$tmpfile"
  rm "$tmpfile"
  exit 1
}

if [ "$UPDATE_MAIL_MODE" = "1" ]; then
  updateLdap
fi

rewrite_configs
