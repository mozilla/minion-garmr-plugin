#!/bin/bash

set -x

# This script expects an active virtualenv

if [ -z "$VIRTUAL_ENV" ]; then
    echo "abort: no virtual environment active"
    exit 1
fi

case $1 in
    develop)
        (cd dependencies/garmr && python setup.py develop) || exit 1
        python setup.py develop || exit 1
        ;;
esac
