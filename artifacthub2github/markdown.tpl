# Trivy Vulnerability Report

{{- range . -}}
## Target: {{ .Target }} --- Class: {{ .Class }}
|Severity|VulnerabilityID|PkgName|InstalledVersion|FixedVersion|
|--------|---------------|-------|----------------|------------|
{{ range .Vulnerabilities -}}
|{{ .Severity }}|{{ .VulnerabilityID }}|{{ .PkgName }}|{{ .InstalledVersion }}|{{ .FixedVersion }}|
{{ end }}

{{ end }}