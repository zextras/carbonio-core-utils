#!/bin/bash
# shellcheck disable=SC2154

eval "$(/opt/zextras/common/bin/java \
  -client \
  -cp '/opt/zextras/mailbox/jars/*' \
  -Djava.library.path=/opt/zextras/lib \
  -Dzimbra.home=/opt/zextras \
  com.zimbra.cs.localconfig.LocalConfigCLI -q -m shell || true)"

# java

if [[ "${zimbra_zmjava_java_library_path}" = "" ]]; then
  zimbra_zmjava_java_library_path=/opt/zextras/lib
fi

# openldap
# Check for ldap_bind_url first (can contain multiple URLs), then fall back to ldap_url
if [[ -n "$ldap_bind_url" ]]; then
  bind_url="$ldap_bind_url"
  # Extract first URL for ldap_domain
  read -ra bind_url_array <<<"$ldap_bind_url"
  first_url=${bind_url_array[0]}
else
  # Read LDAP bind urls as bash array from ldap_url
  read -ra bind_url_array <<<"$ldap_url"
  first_url=${bind_url_array[0]}
  bind_url="$first_url"
fi

# Remove the protocol
url="${first_url#*//}"
# Retrieve the hostname
ldap_domain="${url%:*}"

# memcached
addr=$(/opt/zextras/bin/zmprov \
  -l gs "${zimbra_server_hostname}" zimbraMemcachedBindAddress \
  | awk '/^zimbraMemcachedBindAddress:/{ print $2 }' || true)
addr="${addr//$'\n'/,}"
port=$(/opt/zextras/bin/zmprov -l \
  gs "${zimbra_server_hostname}" zimbraMemcachedBindPort \
  | awk '/^zimbraMemcachedBindPort:/{ print $2 }' || true)
if [[ "${addr}" = "" ]]; then
  memcached_flags="-U 0 -l 127.0.1.1,127.0.0.1 -p ${port:-11211}"
else
  memcached_flags="-U 0 -l ${addr} -p ${port:-11211}"
fi

# mailboxdmgr
# Memory for use by JVM.
#
javaXmx=${mailboxd_java_heap_size:=512}
javaXms=${javaXmx}
mailboxd_java_heap_new_size_percent=${mailboxd_java_heap_new_size_percent:=25}

# mailboxd
if [[ -d ${mailboxd_directory} ]]; then
  if [[ ! -d ${mailboxd_directory}/work/service/jsp ]]; then
    mkdir -p "${mailboxd_directory}/work/service/jsp"
  fi
fi

mailboxd_thread_stack_size=${mailboxd_thread_stack_size:=256k}
if ! echo "${mailboxd_java_options}" | grep 'Xss'; then
  mailboxd_java_options="${mailboxd_java_options} -Xss${mailboxd_thread_stack_size}"
fi

networkaddress_cache_ttl=${networkaddress_cache_ttl:=60}
if ! echo "${mailboxd_java_options}" | grep -q 'sun.net.inetaddr.ttl'; then
  mailboxd_java_options="${mailboxd_java_options} -Dsun.net.inetaddr.ttl=${networkaddress_cache_ttl}"
fi

if ! echo "${mailboxd_java_options}" | grep -q 'log4j'; then
  mailboxd_java_options="${mailboxd_java_options} -Dlog4j.configurationFile=${zimbra_log4j_properties}"
fi

{
  echo "antispam_enable_restarts=${antispam_enable_restarts}"
  echo "antispam_enable_rule_compilation=${antispam_enable_rule_compilation}"
  echo "antispam_enable_rule_updates=${antispam_enable_rule_updates}"
  echo "bind_url=${bind_url}"
  echo "configd_listen_port=${zmconfigd_listen_port}"
  echo "configd_rewrite_timeout=${zimbra_configrewrite_timeout}"
  echo "java_library_path=${zimbra_zmjava_java_library_path}"
  echo "java_options=${zimbra_zmjava_options}"
  echo "java_xms=${javaXms}"
  echo "java_xmx=${javaXmx}"
  echo "ldap_domain=${ldap_domain}"
  echo "ldap_port=${ldap_port}"
  echo "log_directory=${zimbra_log_directory}"
  echo "mailboxd_directory=${mailboxd_directory}"
  echo "mailboxd_java_heap_new_size_percent=${mailboxd_java_heap_new_size_percent}"
  echo "mailboxd_java_options=${mailboxd_java_options}"
  echo "memcached_flags=${memcached_flags}"
  echo "mysql_errlogfile=${mysql_errlogfile}"
  echo "mysql_mycnf=${mysql_mycnf}"
} >/opt/zextras/data/systemd.env
