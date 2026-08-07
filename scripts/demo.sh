#!/usr/bin/env bash
# Drives the terminal recording in docs/demo.gif.
#
# Kept in the repository so the recording can be regenerated rather than being
# a binary nobody can reproduce. Every command here is real and its output is
# whatever the tool actually prints — nothing is staged or edited afterwards.
#
#   scripts/record-demo.sh          # re-record and rebuild the gif
set -euo pipefail

TYPE_DELAY=${TYPE_DELAY:-0.045}
PROMPT="\033[1;32m$\033[0m "

say() { printf "\033[2m# %s\033[0m\n" "$1"; sleep 1.1; }

type_out() {
  printf "%b" "$PROMPT"
  local text="$1"
  for ((i = 0; i < ${#text}; i++)); do
    printf "%s" "${text:i:1}"
    sleep "$TYPE_DELAY"
  done
  printf "\n"
  sleep 0.35
}

run() {
  type_out "$1"
  eval "$1" || true
  sleep "${2:-2.4}"
}

clear
say "A deterministic triage report. No model, no API key, no network."
run "loglens report app.log" 3.6

clear
say "The last section is the point: a request followed across services."
say "The SMTP failure sits 2.5s downstream of the Kafka timeout, same trace."
sleep 1.4

clear
say "Kubernetes control-plane logs, straight off a node."
say "Every component writes klog, and klog sends INFO to stderr."
run "head -3 tests/fixtures/cri_kube_apiserver_klog.log | cut -c1-100" 2.6
say "Read the stream as the severity and a healthy apiserver is 100% errors."
say "Read the klog letter instead:"
run "loglens report tests/fixtures/cri_kube_apiserver_klog.log | head -12" 3.6

clear
say "A node file mixes formats: plain text, logfmt and JSON under one prefix."
run "cat tests/fixtures/cri_node_container.log | cut -c1-86" 2.8
say "Each line keeps its own fields rather than becoming opaque text."
run "loglens report tests/fixtures/cri_node_container.log | head -11" 3.4

clear
say "loglens report <file>   — half a second, nothing to install but Python."
sleep 2.5
