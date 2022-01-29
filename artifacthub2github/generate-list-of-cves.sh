#!/usr/bin/env bash

: ${CONFIGFILE:=helm-charts.yaml}
: ${CHART_ROOT:=.}

install_render() {
    [[ -f /usr/local/bin/render ]] && return
    local version=$(curl -s https://github.com/VirtusLab/render/releases/latest | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]')
    cd /tmp
    wget -O render https://github.com/VirtusLab/render/releases/download/${version}/render-linux-amd64
    sudo install render /usr/local/bin/render
}

install_trivy() {
    [[ -f /usr/local/bin/trivy ]] && return
    local version=$(curl -s https://github.com/aquasecurity/trivy/releases/latest | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]')
    cd /tmp
    wget -O trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/${version}/trivy_${version#v}_Linux-64bit.tar.gz
    tar xvzf trivy.tar.gz
    sudo install trivy /usr/local/bin/trivy
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
install_trivy

for repo in $(repos) ; do
    repo_name=$(repo_name ${repo})
    for chart in $(charts ${repo}) ; do
        chart_name=$(chart_name ${repo} ${chart})
        manifestdir="${CHART_ROOT}/chart-manifests/${repo_name}/${chart_name}"
        cvedir="${CHART_ROOT}/chart-cves/${repo_name}/${chart_name}"
        [[ -d ${manifestdir} ]] || mkdir -p ${manifestdir}
        [[ -d ${cvedir} ]] || mkdir -p ${cvedir}
        for manifestfile in ${manifestdir}/*.yaml ; do
            for image in $(grep -o 'image: .*$' ${manifestfile} | sed 's#image: ##g' | sed 's#"##g') ; do
                echo ${image}
                image_without_repo=${image##*/}
                image_without_tag=${image_without_repo/:*/}
                trivy image --format template --template "@/tmp/contrib/html.tpl" --output ${cvedir}/${manifestfile##*/}.${image_without_tag}.cves.md --severity "MEDIUM,HIGH,CRITICAL" "${image}"
            done
        done        
    done
done
