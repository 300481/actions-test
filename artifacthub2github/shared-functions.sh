# die exits the script with the given return code and echos the given message
die(){
    RC=$1 ; shift
    echo $@
    exit $RC
}

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

# install_trivy installs the trivy program
install_trivy() {
    podman run -d --rm --name trivy --entrypoint /bin/sleep docker.io/aquasec/trivy:latest 10
    podman cp trivy:/usr/local/bin/trivy .
    sudo install trivy /usr/local/bin/trivy
}
