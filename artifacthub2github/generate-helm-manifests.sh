#!/usr/bin/env bash

. ./shared-functions.sh

: ${CONFIGFILE:=helm-charts.yaml}
: ${VALUES_ROOT:=.}
: ${MANIFESTS_ROOT:=.}

install_render

for repo in $(repos) ; do
    repo_url=$(repo_url ${repo})
    repo_name=$(repo_name ${repo})
    helm repo add ${repo_name} ${repo_url}
    helm repo update
    for chart in $(charts ${repo}) ; do
        chart_version=$(version ${repo} ${chart})
        chart_name=$(chart_name ${repo} ${chart})
        echo "${repo_name} | ${repo_url} | ${chart_name} | ${chart_version}"

        valuesdir="${VALUES_ROOT}/chart-values/${repo_name}/${chart_name}"
        manifestdir="${MANIFESTS_ROOT}/chart-manifests/${repo_name}/${chart_name}"
        [[ -d ${manifestdir} ]] || mkdir -p ${manifestdir}
        [[ -d ${valuesdir} ]] || $(mkdir -p ${valuesdir} ; touch ${valuesdir}/default.yaml)

        for valuesfile in ${valuesdir}/* ; do
            manifestfile=${manifestdir}/$(basename ${valuesfile})
            helm template ${chart_name} ${repo_name}/${chart_name} --version ${chart_version} --values ${valuesfile} > ${manifestfile}
        done        
    done
done
