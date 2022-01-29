#!/usr/bin/env bash

: ${CONFIGFILE:=helm-charts.yaml}
: ${CHART_ROOT:=.}

install_render() {
    [[ -f /usr/local/bin/render ]] && return
    local version=$(curl -s https://github.com/VirtusLab/render/releases/latest | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]')
    wget -O render https://github.com/VirtusLab/render/releases/download/${version}/render-linux-amd64
    sudo install render /usr/local/bin/render
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
    repo_name=$(repo_name ${repo})
    for chart in $(charts ${repo}) ; do
        chart_name=$(chart_name ${repo} ${chart})
        manifestdir="${CHART_ROOT}/chart-manifests/${repo_name}/${chart_name}"
        [[ -d ${manifestdir} ]] || mkdir -p ${manifestdir}
        for manifestfile in ${manifestdir}/* ; do
            echo ${repo} : ${chart} : ${manifestfile}
            pluto detect ${manifestfile} --output markdown --ignore-deprecations --ignore-removals > ${manifestfile}-deprecations.md
        done        
    done
done
