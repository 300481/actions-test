#!/usr/bin/env bash

. ./shared-functions.sh

: ${CONFIGFILE:=helm-charts.yaml}
: ${MANIFESTS_ROOT:=.}
: ${DEPRECATIONS_ROOT:=.}

REPO_NAME=$(repo_name "${PAYLOAD}")
PUBLISHER=$(publisher "${PAYLOAD}")
CHART_NAME=$(chart_name "${PAYLOAD}")
VERSION=$(version "${PAYLOAD}")
REPO_URL=$(repo_url "${PAYLOAD}")

install_render

manifestdir="${MANIFESTS_ROOT}/chart-manifests/${REPO_NAME}/${CHART_NAME}"
deprecationsdir="${DEPRECATIONS_ROOT}/chart-deprecations/${REPO_NAME}/${CHART_NAME}"
[[ -d ${manifestdir} ]] || mkdir -p ${manifestdir}
[[ -d ${deprecationsdir} ]] || mkdir -p ${deprecationsdir}
for manifestfile in ${manifestdir}/* ; do
    echo ${REPO_NAME} : ${CHART_NAME} : ${manifestfile}
    pluto detect ${manifestfile} --output markdown --ignore-deprecations --ignore-removals > ${deprecationsdir}/${manifestfile##*/}.api-deprecations.md
done
