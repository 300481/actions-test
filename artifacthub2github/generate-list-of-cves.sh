#!/usr/bin/env bash

. ./shared-functions.sh

: ${CONFIGFILE:=helm-charts.yaml}
: ${MANIFESTS_ROOT:=.}
: ${CVES_ROOT:=.}
: ${TRIVY_TEMPLATE:=markdown.tpl}

REPO_NAME=$(repo_name "${PAYLOAD}")
PUBLISHER=$(publisher "${PAYLOAD}")
CHART_NAME=$(chart_name "${PAYLOAD}")
VERSION=$(version "${PAYLOAD}")
REPO_URL=$(repo_url "${PAYLOAD}")

install_render
install_trivy

manifestdir="${MANIFESTS_ROOT}/chart-manifests/${REPO_NAME}/${CHART_NAME}"
cvedir="${CVES_ROOT}/chart-cves/${REPO_NAME}/${CHART_NAME}"
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
