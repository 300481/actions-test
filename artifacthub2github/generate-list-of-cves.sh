#!/usr/bin/env bash

. ./shared-functions.sh

: ${CONFIGFILE:=helm-charts.yaml}
: ${MANIFESTS_ROOT:=.}
: ${CVES_ROOT:=.}
: ${TRIVY_TEMPLATE:=markdown.tpl}

install_render
install_trivy

for repo in $(repos) ; do
    repo_name=$(repo_name ${repo})
    for chart in $(charts ${repo}) ; do
        chart_name=$(chart_name ${repo} ${chart})
        manifestdir="${MANIFESTS_ROOT}/chart-manifests/${repo_name}/${chart_name}"
        cvedir="${CVES_ROOT}/chart-cves/${repo_name}/${chart_name}"
        [[ -d ${manifestdir} ]] || mkdir -p ${manifestdir}
        [[ -d ${cvedir} ]] || mkdir -p ${cvedir}
        for manifestfile in ${manifestdir}/*.yaml ; do
            for image in $(grep -o 'image: .*$' ${manifestfile} | sed 's#image: ##g' | sed 's#"##g') ; do
                echo ${image}
                image_without_repo=${image##*/}
                image_without_tag=${image_without_repo/:*/}
                trivy image --format template --template "@${TRIVY_TEMPLATE}" --output ${cvedir}/${manifestfile##*/}.${image_without_tag}.cves.md --severity "MEDIUM,HIGH,CRITICAL" "${image}"
            done
        done        
    done
done
