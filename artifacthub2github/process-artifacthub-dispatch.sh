#!/usr/bin/env bash

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

. ${SCRIPTPATH}/shared-functions.sh

[[ -z "${PAYLOAD}" ]] && die 2 "ERROR: empty payload"
[[ -z "${PAYLOAD_DIR}" ]] && die 2 "ERROR: please set PAYLOAD_DIR"
[[ -z "${CONFIGFILE}" ]] && die 2 "ERROR: please set CONFIGFILE"
[[ -z "${VALUES_ROOT}" ]] && die 2 "ERROR: please set VALUES_ROOT"
[[ -z "${MANIFESTS_ROOT}" ]] && die 2 "ERROR: please set MANIFESTS_ROOT"
[[ -z "${DEPRECATIONS_ROOT}" ]] && die 2 "ERROR: please set DEPRECATIONS_ROOT"
[[ -z "${CVES_ROOT}" ]] && die 2 "ERROR: please set CVES_ROOT"
[[ -z "${TRIVY_TEMPLATE}" ]] && die 2 "ERROR: please set TRIVY_TEMPLATE"

install_dependencies(){
    install_render
    install_trivy
}

update_chart_version(){
    REPO_NAME=$(repo_name "${PAYLOAD}")
    REPO=$(yaml_compatible_name "${REPO_NAME}")
    PUBLISHER=$(publisher "${PAYLOAD}")
    CHART_NAME=$(chart_name "${PAYLOAD}")
    CHART=$(yaml_compatible_name "${CHART_NAME}")
    VERSION=$(version "${PAYLOAD}")
    REPO_URL=$(repo_url "${PAYLOAD}")

    echo "
    Repository Name: ${REPO_NAME}
    Repository URL:  ${REPO_URL}
    Chart Name:      ${CHART_NAME}
    Chart Version:   ${VERSION}
    Publisher:       ${PUBLISHER}
    "

    # update repo url
    yq eval '.repos.'${REPO}'.url = "'${REPO_URL}'"' -i ${CONFIGFILE}
    # update repo name
    yq eval '.repos.'${REPO}'.name = "'${REPO_NAME}'"' -i ${CONFIGFILE}
    # update chart version
    yq eval '.repos.'${REPO}'.charts.'${CHART}'.version = "'${VERSION}'"' -i ${CONFIGFILE}
    # update chart name
    yq eval '.repos.'${REPO}'.charts.'${CHART}'.name = "'${CHART_NAME}'"' -i ${CONFIGFILE}
}

generate_helm_manifests(){
    REPO_NAME=$(repo_name "${PAYLOAD}")
    CHART_NAME=$(chart_name "${PAYLOAD}")
    VERSION=$(version "${PAYLOAD}")
    REPO_URL=$(repo_url "${PAYLOAD}")

    echo "${REPO_NAME} | ${REPO_URL} | ${CHART_NAME} | ${VERSION}"

    helm repo add ${REPO_NAME} ${REPO_URL}
    helm repo update

    valuesdir="${VALUES_ROOT}/chart-values/${REPO_NAME}/${CHART_NAME}"
    manifestdir="${MANIFESTS_ROOT}/chart-manifests/${REPO_NAME}/${CHART_NAME}"
    [[ -d ${manifestdir} ]] || mkdir -p ${manifestdir}
    [[ -d ${valuesdir} ]] || $(mkdir -p ${valuesdir} ; touch ${valuesdir}/default.yaml)

    for valuesfile in ${valuesdir}/* ; do
        manifestfile=${manifestdir}/$(basename ${valuesfile})
        helm template ${CHART_NAME} ${REPO_NAME}/${CHART_NAME} --version ${VERSION} --values ${valuesfile} > ${manifestfile}
    done
}

generate_list_of_deprecated_api_versions(){
    REPO_NAME=$(repo_name "${PAYLOAD}")
    CHART_NAME=$(chart_name "${PAYLOAD}")

    manifestdir="${MANIFESTS_ROOT}/chart-manifests/${REPO_NAME}/${CHART_NAME}"
    deprecationsdir="${DEPRECATIONS_ROOT}/chart-deprecations/${REPO_NAME}/${CHART_NAME}"
    [[ -d ${manifestdir} ]] || mkdir -p ${manifestdir}
    [[ -d ${deprecationsdir} ]] || mkdir -p ${deprecationsdir}
    for manifestfile in ${manifestdir}/* ; do
        echo ${REPO_NAME} : ${CHART_NAME} : ${manifestfile}
        pluto detect ${manifestfile} --output markdown --ignore-deprecations --ignore-removals > ${deprecationsdir}/${manifestfile##*/}.api-deprecations.md
    done
}

generate_list_of_cves(){
    REPO_NAME=$(repo_name "${PAYLOAD}")
    CHART_NAME=$(chart_name "${PAYLOAD}")

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
}

save_payload(){
    REPO_NAME=$(repo_name "${PAYLOAD}")
    CHART_NAME=$(chart_name "${PAYLOAD}")
    jq . <<< "${PAYLOAD}" > ${PAYLOAD_DIR}/${REPO_NAME}-${CHART_NAME}.json
}

${1}