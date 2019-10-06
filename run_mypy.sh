#!/usr/bin/env sh
#-*-mode: sh; encoding: utf-8-*-

_MY_DIR="$( cd "$( dirname "${0}" )" && pwd )"
set -ex
[ -d "${_MY_DIR}" ]
[ "${_MY_DIR}/run_mypy.sh" -ef "${0}" ]
cd "${_MY_DIR}"

mypy --strict `find ./elementstx -path ./elementstx/tests -prune -o -name "*.py" -print|sort`
mypy `find ./elementstx/tests ./examples -name "*.py" -print|sort`
