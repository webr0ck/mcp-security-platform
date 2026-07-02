{{/*
Expand the name of the chart.
*/}}
{{- define "mcp-security-platform.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "mcp-security-platform.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label.
*/}}
{{- define "mcp-security-platform.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "mcp-security-platform.labels" -}}
helm.sh/chart: {{ include "mcp-security-platform.chart" . }}
{{ include "mcp-security-platform.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels (used in matchLabels + Service selectors).
*/}}
{{- define "mcp-security-platform.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-security-platform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Proxy-specific selector labels.
*/}}
{{- define "mcp-security-platform.proxySelectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-security-platform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: proxy
{{- end }}

{{/*
OPA-specific selector labels.
*/}}
{{- define "mcp-security-platform.opaSelectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-security-platform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: opa
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "mcp-security-platform.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "mcp-security-platform.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Proxy image tag — defaults to .Chart.AppVersion.
*/}}
{{- define "mcp-security-platform.proxyImageTag" -}}
{{- .Values.proxy.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
OPA service name (used by proxy to resolve OPA_HOST).
*/}}
{{- define "mcp-security-platform.opaServiceName" -}}
{{- printf "%s-opa" (include "mcp-security-platform.fullname" .) }}
{{- end }}
