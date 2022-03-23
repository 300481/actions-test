#!/usr/bin/env bash

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

. ${SCRIPTPATH}/shared-functions.sh

[[ -z "${PAYLOAD}" ]] && die 2 "ERROR: empty payload"
[[ -z "${CONFIGFILE}" ]] && die 2 "ERROR: please set CONFIGFILE"

install_dependencies(){
    install_render
    install_trivy
}

${1}