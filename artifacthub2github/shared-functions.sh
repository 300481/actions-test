# compatible_name makes a name usable as YAML key
yaml_compatible_name(){
    sed 's/-/_/g' <<< ${1}
}

# repo_name returns the repositories name of the payload
repo_name(){
    jq -r .data.package.repository.name <<< ${1}
}

# publisher returns the publishers name of the payload
publisher(){
    jq -r .data.package.repository.publisher <<< ${1}
}

# chart_name returns the charts name of the payload
chart_name(){
    jq -r .data.package.name <<< ${1}
}

# version returns the charts version of the payload
version(){
    jq -r .data.package.version <<< ${1}
}

# repo_url returns the URL of the repository of the payload
repo_url(){
    local REPOSITORY_PUBLISHER=$(publisher "${1}")
    local REPOSITORY_NAME=$(repo_name "${1}")
    curl -s "https://artifacthub.io/api/v1/repositories/search?offset=0&limit=20&kind=0&user=${REPOSITORY_PUBLISHER}&org=${REPOSITORY_PUBLISHER}&name=${REPOSITORY_NAME}" | jq -r .[0].url
}

# install_render installs the render program
install_render() {
    [[ -f /usr/local/bin/render ]] && return
    local version=$(curl -s https://github.com/VirtusLab/render/releases/latest | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]')
    cd /tmp
    wget -O render https://github.com/VirtusLab/render/releases/download/${version}/render-linux-amd64
    sudo install render /usr/local/bin/render
    cd -
}

# install_trivy installs the trivy program
install_trivy() {
    [[ -f /usr/local/bin/trivy ]] && return
    local version=$(curl -s https://github.com/aquasecurity/trivy/releases/latest | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]')
    cd /tmp
    wget -O trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/${version}/trivy_${version#v}_Linux-64bit.tar.gz
    tar xvzf trivy.tar.gz
    sudo install trivy /usr/local/bin/trivy
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
