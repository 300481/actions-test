# Trivy Vulnerability Report

{{ define "color" }}
{{- if eq . "UNKNOWN" }}lightgrey{{ end -}}
{{- if eq . "LOW" }}yellowgreen{{ end -}}
{{- if eq . "MEDIUM" }}yellow{{ end -}}
{{- if eq . "HIGH" }}orange{{ end -}}
{{- if eq . "CRITICAL" }}red{{ end -}}
{{ end }}

{{- define "badge" -}}
![](https://img.shields.io/badge/-{{ . }}-{{ template "color" . }})
{{- end }}

{{ range . }}
## Target: {{ .Target }} --- Class: {{ .Class }}
|Severity|VulnerabilityID|PkgName|InstalledVersion|FixedVersion|
|--------|---------------|-------|----------------|------------|
{{ range .Vulnerabilities -}}
|{{ template "badge" .Severity }}|{{ .VulnerabilityID }}|{{ .PkgName }}|{{ .InstalledVersion }}|{{ .FixedVersion }}|
{{ end -}}
{{ end -}}