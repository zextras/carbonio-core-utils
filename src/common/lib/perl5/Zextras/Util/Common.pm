#!/usr/bin/perl
# 
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

package Zextras::Util::Common; 
use strict;


# Library locations
use lib "/opt/zextras/common/lib/perl5";
use lib "/opt/zextras/common/lib/perl5/Zextras/SOAP";
use lib "/opt/zextras/common/lib/perl5/Zextras/Mon";
use lib "/opt/zextras/common/lib/perl5/Zextras/DB";
foreach my $type (qw(linux-thread-multi linux-gnu-thread-multi linux thread-multi thread-multi-2level)) {
  my $dir = "/opt/zextras/common/lib/perl5/x86_64-${type}";
  unshift(@INC, "$dir") 
    if (-d "$dir");
}

1
