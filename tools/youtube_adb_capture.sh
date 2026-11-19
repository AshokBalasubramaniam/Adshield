#!/usr/bin/env bash
# Helper for the YouTube test matrix (docs/TEST_PLAN.md §C). Records facts about the device and mirrors
# the debug-build-only AdShieldDiag log to a file. Nothing is uploaded anywhere.
#   tools/youtube_adb_capture.sh start Y02   # writes build/youtube-capture/Y02/{facts.txt,logcat.txt}
#   tools/youtube_adb_capture.sh stop  Y02   # stops the logcat mirror
set -euo pipefail
ADB="${ADB:-$HOME/Android/Sdk/platform-tools/adb}"
SERIAL_ARG=()
[[ -n "${ANDROID_SERIAL:-}" ]] && SERIAL_ARG=(-s "$ANDROID_SERIAL")
adb() { "$ADB" "${SERIAL_ARG[@]}" "$@"; }

cmd="${1:-}"; id="${2:-}"
[[ -z "$cmd" || -z "$id" ]] && { echo "usage: $0 start|stop <scenario-id>"; exit 2; }
dir="build/youtube-capture/$id"; mkdir -p "$dir"

case "$cmd" in
  start)
    adb get-state >/dev/null 2>&1 || { echo "no device connected (adb devices)"; exit 1; }
    {
      echo "scenario: $id"
      echo "captured: $(date -Is)"
      echo "android: $(adb shell getprop ro.build.version.release) (API $(adb shell getprop ro.build.version.sdk))"
      echo "youtube: $(adb shell dumpsys package com.google.android.youtube | grep -E 'versionName|versionCode' | head -2 | tr -s ' ' | tr '\n' ' ')"
      echo "private_dns_mode: $(adb shell settings get global private_dns_mode) / $(adb shell settings get global private_dns_specifier)"
      echo "default network: $(adb shell dumpsys connectivity | grep -m1 -E 'Active default network|mDefaultNetwork' || true)"
      echo "adshield installed: $(adb shell pm list packages | grep -c adshield)"
    } | tee "$dir/facts.txt"
    adb logcat -c
    nohup "$ADB" "${SERIAL_ARG[@]}" logcat -v time -s AdShieldDiag:D > "$dir/logcat.txt" 2>&1 &
    echo $! > "$dir/logcat.pid"
    echo "capturing to $dir (play the video now; run '$0 stop $id' afterwards)"
    ;;
  stop)
    [[ -f "$dir/logcat.pid" ]] && kill "$(cat "$dir/logcat.pid")" 2>/dev/null || true
    rm -f "$dir/logcat.pid"
    echo "stopped. $(grep -c AdShieldDiag "$dir/logcat.txt" 2>/dev/null || echo 0) diagnostic lines in $dir/logcat.txt"
    ;;
  *) echo "usage: $0 start|stop <scenario-id>"; exit 2 ;;
esac
