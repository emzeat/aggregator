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
    python3 -m pip install -r requirements.txt
fi

python3 -m aggregator $@
