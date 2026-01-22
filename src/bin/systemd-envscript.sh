#!/bin/bash
# shellcheck disable=SC2154
# Generate /opt/zextras/data/systemd.env from localconfig.
#
# Uses configd's native localconfig reader (Go, ~6ms) instead of the JVM-based
# LocalConfigCLI (~400ms). The configd binary reads localconfig.xml, applies
# hardcoded defaults for missing keys, and resolves ${variable} references.

# Load all localconfig values as shell variables
eval "$(/opt/zextras/bin/configd localconfig -q -m shell || true)"

# --- Post-processing (derivation logic on top of raw localconfig values) ---

# java: default library path if not set
zimbra_zmjava_java_library_path=${zimbra_zmjava_java_library_path:-/opt/zextras/lib}

# mailboxd heap: default to 512 if not set, use for both xms and xmx
mailboxd_java_heap_size=${mailboxd_java_heap_size:-512}

# Append JVM flags to mailboxd_java_options if not already present
if ! echo "${mailboxd_java_options}" | grep -q 'Xss'; then
  mailboxd_java_options="${mailboxd_java_options} -Xss${mailboxd_thread_stack_size}"
fi
if ! echo "${mailboxd_java_options}" | grep -q 'log4j'; then
  mailboxd_java_options="${mailboxd_java_options} -Dlog4j.configurationFile=${zimbra_log4j_properties}"
fi

# openldap: derive bind_url and ldap_domain from ldap_bind_url or ldap_url
if [[ -n "$ldap_bind_url" ]]; then
  bind_url="$ldap_bind_url"
  read -ra bind_url_array <<<"$ldap_bind_url"
  first_url=${bind_url_array[0]}
else
  read -ra bind_url_array <<<"$ldap_url"
  first_url=${bind_url_array[0]}
  bind_url="$first_url"
fi

# Extract hostname from first LDAP URL
url="${first_url#*//}"
ldap_domain="${url%:*}"

# Write environment file consumed by systemd units
{
  echo "antispam_enable_restarts=${antispam_enable_restarts}"
  echo "antispam_enable_rule_compilation=${antispam_enable_rule_compilation}"
  echo "antispam_enable_rule_updates=${antispam_enable_rule_updates}"
  echo "bind_url=${bind_url}"
  echo "java_options=${zimbra_zmjava_options}"
  echo "java_xms=${javaXms}"
  echo "java_xmx=${javaXmx}"
  echo "ldap_domain=${ldap_domain}"
  echo "ldap_port=${ldap_port}"
  echo "mailboxd_java_options=${mailboxd_java_options}"
  echo "mail_service_port=${zimbra_mail_service_port}"
} >/opt/zextras/data/systemd.env
