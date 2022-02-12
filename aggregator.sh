#!/usr/bin/env bash
#
# aggregator.sh
#
# Copyright (c) 2021 - 2022 Marius Zwicker
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

base_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd $base_dir

venv=$base_dir/.venv
if [ -f $venv/bin/activate ]; then
    echo "Using virtualenv at $venv"
    source $venv/bin/activate || exit 1
else
    echo "Creating virtualenv at $venv"
    python3 -m venv $venv
    source $venv/bin/activate || exit 1
fi

# macOS has md5, Linux is using md5sum
if command -v md5 > /dev/null; then
    md5=md5
else
    md5=md5sum
fi

md5_new=$($md5 requirements.txt aggregator.sh)
md5_inst=$(cat $venv/requirements.log 2> /dev/null)
if [ ! "$md5_new" = "$md5_inst" ]; then
    echo "Need to upgrade dependencies"
    python3 -m pip install --upgrade pip || exit 1

    if python3 -m pip --disable-pip-version-check install -r requirements.txt; then
        echo "$md5_new" > $venv/requirements.log
    else
        exit 1
    fi
fi

if [ $1 == "freeze" ]; then
    for line in $(python3 -m pip freeze -r requirements.txt); do
        if echo $line | grep -sq "##"; then
            # break when we hit the comment about pip adding recursive dependencies
            break
        else
            echo $line >> requirements.txt.filtered
        fi
    done
    mv -f requirements.txt.filtered requirements.txt
else
    python3 -m aggregator "$@"
fi
