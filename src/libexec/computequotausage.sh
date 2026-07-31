#!/bin/bash

# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# CO-3682: aggregate quota computation has been removed from the mailbox
# server. This command is kept as a no-op so that existing scripts and
# scheduled jobs invoking it do not break.

echo "zmcomputequotausage is deprecated and no longer functional."
echo "Aggregate quota computation has been removed in favor of the unified quota management system."
exit 0
