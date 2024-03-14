#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

source /opt/zextras/bin/zmshutil || exit 1
zmsetvars

case "$#" in
  0) ;;

  1)
    ldap_host="$1"
    ldap_port=389
    ldap_url="ldap://${ldap_host}:${ldap_port}"
    ;;
  2)
    ldap_host="$1"
    ldap_port="$2"
    if [ "$ldap_port" == 636 ]; then
      ldap_url="ldaps://${ldap_host}:${ldap_port}"
    else
      ldap_url="ldap://${ldap_host}:${ldap_port}"
    fi
    ;;
  *)
    echo "Usage: $(basename "$0") ldap_host [ ldap_port ]"
    exit
    ;;
esac

if [ "$ldap_starttls_supported" == 1 ]; then
  STARTTLS="yes"
else
  STARTTLS="no"
fi

postfix_owner=postfix

confdir=/opt/zextras/conf
mkdir -p ${confdir}

cat <<EOF >${confdir}/ldap-vmm.cf
server_host = ${ldap_url}
server_port = ${ldap_port}
search_base =
query_filter = (&(zimbraMailDeliveryAddress=%s)(zimbraMailStatus=enabled))
result_attribute = zimbraMailDeliveryAddress
version = 3
start_tls = ${STARTTLS}
tls_ca_cert_dir = /opt/zextras/conf/ca
bind = yes
bind_dn = uid=zmpostfix,cn=appaccts,cn=zimbra
bind_pw = ${ldap_postfix_password}
timeout = 30
EOF

cat <<EOF >${confdir}/ldap-vmd.cf
server_host = ${ldap_url}
server_port = ${ldap_port}
search_base =
query_filter = (&(zimbraDomainName=%s)(zimbraDomainType=local)(zimbraMailStatus=enabled))
result_attribute = zimbraDomainName
version = 3
start_tls = ${STARTTLS}
tls_ca_cert_dir = /opt/zextras/conf/ca
bind = yes
bind_dn = uid=zmpostfix,cn=appaccts,cn=zimbra
bind_pw = ${ldap_postfix_password}
timeout = 30
EOF

cat <<EOF >${confdir}/ldap-vam.cf
server_host = ${ldap_url}
server_port = ${ldap_port}
search_base =
query_filter = (&(|(zimbraMailDeliveryAddress=%s)(zimbraMailAlias=%s)(zimbraOldMailAddress=%s)(zimbraMailCatchAllAddress=%s))(zimbraMailStatus=enabled))
result_attribute = zimbraMailDeliveryAddress,zimbraMailForwardingAddress,zimbraPrefMailForwardingAddress,zimbraMailCatchAllForwardingAddress
version = 3
start_tls = ${STARTTLS}
tls_ca_cert_dir = /opt/zextras/conf/ca
bind = yes
bind_dn = uid=zmpostfix,cn=appaccts,cn=zimbra
bind_pw = ${ldap_postfix_password}
timeout = 30
special_result_attribute = member
EOF

cat <<EOF >${confdir}/ldap-vad.cf
server_host = ${ldap_url}
server_port = ${ldap_port}
search_base =
query_filter = (&(zimbraDomainName=%s)(zimbraDomainType=alias)(zimbraMailStatus=enabled))
result_attribute = zimbraDomainName
version = 3
start_tls = ${STARTTLS}
tls_ca_cert_dir = /opt/zextras/conf/ca
bind = yes
bind_dn = uid=zmpostfix,cn=appaccts,cn=zimbra
bind_pw = ${ldap_postfix_password}
timeout = 30
EOF

cat <<EOF >${confdir}/ldap-canonical.cf
server_host = ${ldap_url}
server_port = ${ldap_port}
search_base = 
query_filter = (&(|(zimbraMailDeliveryAddress=%s)(zimbraMailAlias=%s)(zimbraMailCatchAllAddress=%s))(zimbraMailStatus=enabled))
result_attribute = zimbraMailCanonicalAddress,zimbraMailCatchAllCanonicalAddress
version = 3
start_tls = ${STARTTLS}
tls_ca_cert_dir = /opt/zextras/conf/ca
bind = yes
bind_dn = uid=zmpostfix,cn=appaccts,cn=zimbra
bind_pw = ${ldap_postfix_password}
timeout = 30
EOF

cat <<EOF >${confdir}/ldap-transport.cf
server_host = ${ldap_url}
server_port = ${ldap_port}
search_base =
query_filter = (&(|(zimbraMailDeliveryAddress=%s)(zimbraDomainName=%s))(zimbraMailStatus=enabled))
result_attribute = zimbraMailTransport
version = 3
start_tls = ${STARTTLS}
tls_ca_cert_dir = /opt/zextras/conf/ca
bind = yes
bind_dn = uid=zmpostfix,cn=appaccts,cn=zimbra
bind_pw = ${ldap_postfix_password}
timeout = 30
EOF

cat <<EOF >${confdir}/ldap-slm.cf
server_host = ${ldap_url}
server_port = ${ldap_port}
search_base =
query_filter = (&(|(uid=%s)(zimbraMailDeliveryAddress=%s)(zimbraMailAlias=%s)(zimbraMailCatchAllAddress=%s)(zimbraAllowFromAddress=%s))(zimbraMailStatus=enabled))
result_format = %u, %s
result_attribute = uid,zimbraMailDeliveryAddress,zimbraMailForwardingAddress,zimbraPrefMailForwardingAddress,zimbraMailCatchAllForwardingAddress,zimbraMailAlias,zimbraAllowFromAddress
version = 3
start_tls = ${STARTTLS}
tls_ca_cert_dir = /opt/zextras/conf/ca
bind = yes
bind_dn = uid=zmpostfix,cn=appaccts,cn=zimbra
bind_pw = ${ldap_postfix_password}
timeout = 30
EOF

cat <<EOF >${confdir}/ldap-splitdomain.cf
server_host = ${ldap_url}
server_port = ${ldap_port}
search_base =
query_filter = (&(|(zimbraMailDeliveryAddress=%s)(zimbraMailAlias=%s)(zimbraMailCatchAllAddress=%s))(zimbraMailStatus=enabled))
result_attribute = zimbraMailDeliveryAddress,zimbraMailForwardingAddress,zimbraPrefMailForwardingAddress
result_filter = OK
version = 3
start_tls = ${STARTTLS}
tls_ca_cert_dir = /opt/zextras/conf/ca
bind = yes
bind_dn = uid=zmpostfix,cn=appaccts,cn=zimbra
bind_pw = ${ldap_postfix_password}
timeout = 30
EOF

chgrp ${postfix_owner} ${confdir}/ldap-*.cf
