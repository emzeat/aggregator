#!/bin/bash
#
# Helper to conveniently run aggregator within a python venv
#
# Note: This requires paths to configuration files to be absolute!

base_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd $base_dir

venv=$base_dir/.venv
if [ -d $venv ]; then
    echo "Using virtualenv at $venv"
    source $venv/bin/activate
else
    echo "Creating virtualenv at $venv"
    python3 -m venv $venv
    source $venv/bin/activate
fi

md5_new=$(md5 -q requirements.txt)
md5_inst=$(md5 -q $venv/requirements.txt 2> /dev/null)
if [ ! "$md5_new" = "$md5_inst" ]; then
    echo "Need to update dependencies"
    if python3 -m pip --disable-pip-version-check install -r requirements.txt; then
        cp requirements.txt $venv/requirements.txt
    else
        exit 1
    fi
fi

python3 -m aggregator "$@"
