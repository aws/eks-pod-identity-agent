{{/*
Expand the name of the chart.
*/}}
{{- define "eks-pod-identity-agent.name" -}}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- include "addSuffixAndTrim" (dict "name" $name "suffix" .nameSuffix) -}}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "eks-pod-identity-agent.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if .Values.fullnameOverride }}
{{- $name = .Values.fullnameOverride }}
{{- else }}
{{- if contains $name .Release.Name }}
{{- $name = .Release.Name}}
{{- else }}
{{- $name = printf "%s-%s" .Release.Name $name }}
{{- end }}
{{- end }}
{{- include "addSuffixAndTrim" (dict "name" $name "suffix" .nameSuffix) -}}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "addSuffixAndTrim" -}}
{{- if .suffix -}}
{{- $truncSize := int (sub 62 (len .suffix)) -}}
{{- $trimmmedName := .name | trunc $truncSize | trimSuffix "-" -}}
{{- printf "%s-%s" $trimmmedName .suffix -}}
{{- else -}}
{{- .name | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "eks-pod-identity-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "eks-pod-identity-agent.labels" -}}
helm.sh/chart: {{ include "eks-pod-identity-agent.chart" . }}
{{ include "eks-pod-identity-agent.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app: eks-pod-identity-agent
{{- end }}

{{/*
Selector labels
*/}}
{{- define "eks-pod-identity-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "eks-pod-identity-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The eks-pod-identity-agent image to use
*/}}
{{- define "eks-pod-identity-agent.image" -}}
{{- if .Values.image.override }}
{{- .Values.image.override }}
{{- else }}
{{- printf "%s/eks/eks-pod-identity-agent:%s" .Values.image.containerRegistry .Values.image.tag }}
{{- end }}
{{- end }}
