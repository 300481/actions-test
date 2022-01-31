#!/usr/bin/env bash

: ${CONFIGFILE:=helm-charts.yaml}
: ${VALUES_ROOT:=.}
: ${MANIFESTS_ROOT:=.}

install_render() {
    [[ -f /usr/local/bin/render ]] && return
    local version=$(curl -s https://github.com/VirtusLab/render/releases/latest | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]')
    cd /tmp
    wget -O render https://github.com/VirtusLab/render/releases/download/${version}/render-linux-amd64
    sudo install render /usr/local/bin/render
    cd -
}

repos() {
    local repo_template='{{ range $repo, $values := .repos }}{{ $repo }} {{ end }}'
    echo ${repo_template} | render -s --config ${CONFIGFILE}
}


charts() {
    local repo=$1
    local chart_template='{{ range $chart, $values := .repos.'${repo}'.charts }}{{ $chart }} {{ end }}'
    echo ${chart_template} | render -s --config ${CONFIGFILE}
}

version() {
    local repo=$1 ; shift ; local chart=$1
    local version_template="{{ .repos.${repo}.charts.${chart}.version }}"
    echo ${version_template} | render -s --config ${CONFIGFILE}
}

chart_name() {
    local repo=$1 ; shift ; local chart=$1
    local chart_name_template="{{ .repos.${repo}.charts.${chart}.name }}"
    echo ${chart_name_template} | render -s --config ${CONFIGFILE}
}

repo_name() {
    local repo=$1
    local repo_name_template="{{ .repos.${repo}.name }}"
    echo ${repo_name_template} | render -s --config ${CONFIGFILE}
}

repo_url() {
    local repo=$1
    local url_template="{{ .repos.${repo}.url }}"
    echo ${url_template} | render -s --config ${CONFIGFILE}
}

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
