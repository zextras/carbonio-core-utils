#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

resolver_file=/opt/zextras/conf/nginx/resolvers.conf
cat /dev/null >${resolver_file}
[ -r /etc/resolv.conf ] && awk 'BEGIN{ns="";sep=""}/nameserver/{ns=ns sep $2;sep=" " }; END{ if (ns) {print "resolver " ns ";"} }' /etc/resolv.conf >>${resolver_file}
