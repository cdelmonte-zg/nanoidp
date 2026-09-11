{{/*
Expand the name of the chart.
*/}}
{{- define "nanoidp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name, truncated to fit Kubernetes'
63-character label limit, trimming any trailing "-" left by truncation.
*/}}
{{- define "nanoidp.fullname" -}}
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
Chart name and version as used by the chart label.
*/}}
{{- define "nanoidp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "nanoidp.labels" -}}
helm.sh/chart: {{ include "nanoidp.chart" . }}
{{ include "nanoidp.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "nanoidp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nanoidp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Full label set for one resource: chart-managed labels, then
.Values.commonLabels, then that resource's own extra labels, later ones
win on key collision. Call with (dict "context" $ "extra" .Values.service.labels).
*/}}
{{- define "nanoidp.mergedLabels" -}}
{{- $managed := include "nanoidp.labels" .context | fromYaml }}
{{- $merged := mustMergeOverwrite (dict) $managed (.context.Values.commonLabels | default dict) (.extra | default dict) }}
{{- toYaml $merged }}
{{- end }}

{{/*
Full annotation set for one resource: .Values.commonAnnotations, then
that resource's own extra annotations, later ones win on key collision.
Renders nothing if the merged map is empty. Call with
(dict "context" $ "extra" .Values.service.annotations).
*/}}
{{- define "nanoidp.mergedAnnotations" -}}
{{- $merged := mustMergeOverwrite (dict) (.context.Values.commonAnnotations | default dict) (.extra | default dict) }}
{{- if $merged }}
{{- toYaml $merged }}
{{- end }}
{{- end }}

{{/*
Name of the Secret mounted as the config directory: the user-supplied
configFiles.existingSecret if set, otherwise the chart's own generated
Secret name.
*/}}
{{- define "nanoidp.configSecretName" -}}
{{- .Values.configFiles.existingSecret | default (printf "%s-config" (include "nanoidp.fullname" .)) }}
{{- end }}
