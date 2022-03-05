#!/usr/bin/env bash

. ./shared-functions.sh

: ${CONFIGFILE:=helm-charts.yaml}
: ${MANIFESTS_ROOT:=.}
: ${DEPRECATIONS_ROOT:=.}

install_render

for repo in $(repos) ; do
    repo_name=$(repo_name ${repo})
    for chart in $(charts ${repo}) ; do
        chart_name=$(chart_name ${repo} ${chart})
        manifestdir="${MANIFESTS_ROOT}/chart-manifests/${repo_name}/${chart_name}"
        deprecationsdir="${DEPRECATIONS_ROOT}/chart-deprecations/${repo_name}/${chart_name}"
        [[ -d ${manifestdir} ]] || mkdir -p ${manifestdir}
        [[ -d ${deprecationsdir} ]] || mkdir -p ${deprecationsdir}
        for manifestfile in ${manifestdir}/* ; do
            echo ${repo} : ${chart} : ${manifestfile}
            pluto detect ${manifestfile} --output markdown --ignore-deprecations --ignore-removals > ${deprecationsdir}/${manifestfile##*/}.api-deprecations.md
        done        
    done
done
