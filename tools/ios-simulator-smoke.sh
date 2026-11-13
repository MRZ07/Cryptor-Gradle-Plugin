#!/usr/bin/env bash
set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MRZ_ROOT="$(cd "$PLUGIN_ROOT/.." && pwd)"
IOS_VERSION="${IOS_SIMULATOR_VERSION:-27.2}"
LOG_DIR="${IOS_CRYPTOR_SMOKE_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/cryptor-ios-smoke.XXXXXX")}"
mkdir -p "$LOG_DIR"

fail() {
    echo "FAIL: $*" >&2
    echo "Logs and screenshots: $LOG_DIR" >&2
    exit 1
}

for command in xcodebuild xcrun python3 perl cmp; do
    command -v "$command" >/dev/null 2>&1 || fail "Required command not found: $command"
done

if [[ -z "${JAVA_HOME:-}" ]]; then
    JAVA_HOME="$(/usr/libexec/java_home -v 21 2>/dev/null)" || fail "JDK 21 is required. Set JAVA_HOME to JDK 21."
fi
[[ -x "$JAVA_HOME/bin/java" ]] || fail "JAVA_HOME does not contain a Java executable: $JAVA_HOME"
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

xcode_version="$(xcodebuild -version | awk 'NR == 1 { print $2 }')"
xcodebuild -showsdks | grep -Fq "iOS $IOS_VERSION" || fail "Xcode $xcode_version does not expose the iOS $IOS_VERSION SDK"

runtime_id="com.apple.CoreSimulator.SimRuntime.iOS-${IOS_VERSION//./-}"
runtime_json="$(xcrun simctl list runtimes -j)"
printf '%s' "$runtime_json" | python3 -c '
import json, sys
identifier = sys.argv[1]
runtimes = json.load(sys.stdin).get("runtimes", [])
if not any(r.get("identifier") == identifier and r.get("isAvailable") for r in runtimes):
    raise SystemExit(1)
' "$runtime_id" || fail "iOS $IOS_VERSION simulator runtime is not installed"

device_json="$(xcrun simctl list devices available -j)"
device_info="$(printf '%s' "$device_json" | python3 -c '
import json, sys
runtime_id, requested_udid = sys.argv[1:3]
devices = json.load(sys.stdin).get("devices", {}).get(runtime_id, [])
devices = [d for d in devices if d.get("isAvailable")]
if requested_udid:
    device = next((d for d in devices if d.get("udid") == requested_udid), None)
else:
    device = next((d for d in devices if d.get("name", "").startswith("iPhone")), None)
if device is None:
    raise SystemExit(1)
print("\t".join((device["udid"], device["name"], device["state"])))
' "$runtime_id" "${SIMULATOR_UDID:-}")" || fail "No available iPhone simulator with iOS $IOS_VERSION"
IFS=$'\t' read -r simulator_udid simulator_name simulator_state <<< "$device_info"

if [[ "$simulator_state" != "Booted" ]]; then
    xcrun simctl boot "$simulator_udid" >/dev/null
fi
xcrun simctl bootstatus "$simulator_udid" -b

echo "Using Xcode $xcode_version, iOS $IOS_VERSION, $simulator_name ($simulator_udid)"
echo "Logs and screenshots: $LOG_DIR"

verify_bundle_assets() {
    local app="$1"
    local mode="$2"
    local assets="$3"
    local encrypted="$4"
    local bundle="$5"
    python3 - "$app" "$mode" "$assets" "$encrypted" "$bundle" <<'PY'
from pathlib import Path
import sys

app, mode = sys.argv[1], sys.argv[2]
assets, encrypted, bundle = map(Path, sys.argv[3:])
encrypted_extensions = {
    ".tmx", ".png", ".jpg", ".jpeg", ".atlas", ".pack", ".fnt", ".ttf",
    ".mp3", ".ogg", ".wav", ".map",
}
fixtures = sorted(
    p for p in assets.rglob("*")
    if p.is_file() and p.suffix.lower() in encrypted_extensions
)
if not fixtures:
    raise SystemExit(f"No configured Cryptor asset fixture under {assets}")
samples = [fixtures[0]]
if app == "SamsWorld2":
    samples.append(assets / "map/level/1/start.tmx")
    if mode == "encrypted":
        samples.extend([assets / "ts/main.tsx", assets / "i18n/bundle.properties"])

for source in samples:
    relative = source.relative_to(assets)
    encrypted_file = encrypted / relative
    bundled_file = bundle / relative
    if not source.is_file() or not bundled_file.is_file():
        raise SystemExit(f"Missing source/bundled fixture: {relative}")
    raw = source.read_bytes()
    packaged = bundled_file.read_bytes()
    if mode == "encrypted":
        if not encrypted_file.is_file():
            raise SystemExit(f"Missing encrypted output: {relative}")
        ciphertext = encrypted_file.read_bytes()
        if raw == ciphertext:
            raise SystemExit(f"Asset was not encrypted: {relative}")
        if ciphertext != packaged:
            raise SystemExit(f"Simulator app did not package encrypted bytes: {relative}")
        print(f"encrypted bundle bytes verified: {relative}")
    else:
        if raw != packaged:
            raise SystemExit(f"Startup-only app did not bundle the expected source bytes: {relative}")
        print(f"startup-only bundle bytes verified: {relative}")
PY
}

snapshot_audio_cache() {
    local data_container="$1"
    local sound_relative="$2"
    local music_relative="$3"
    python3 - "$data_container" "$sound_relative" "$music_relative" <<'PY'
from pathlib import Path
import hashlib
import json
import sys

container = Path(sys.argv[1])
relatives = [sys.argv[2]]
if sys.argv[3] != "-":
    relatives.append(sys.argv[3])
cache_roots = list((container / "Library/local/cryptor").glob("*/audio"))
before = {}
for relative in relatives:
    normalized = relative.replace("\\", "/")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    extension = Path(relative).suffix.lower()
    filename = f"cryptor_{digest}{extension}"
    before[relative] = {
        str(path): path.stat().st_mtime_ns
        for directory in cache_roots
        for path in [directory / filename]
        if path.is_file()
    }
print(json.dumps(before))
PY
}

verify_audio_cache() {
    local assets="$1"
    local data_container="$2"
    local sound_relative="$3"
    local music_relative="$4"
    local baseline_file="$5"
    python3 - "$assets" "$data_container" "$sound_relative" "$music_relative" "$baseline_file" <<'PY'
from pathlib import Path
import hashlib
import json
import sys

assets, container = Path(sys.argv[1]), Path(sys.argv[2])
checks = [("sound", sys.argv[3])]
if sys.argv[4] != "-":
    checks.append(("music", sys.argv[4]))
before = json.loads(Path(sys.argv[5]).read_text())
cache_roots = list((container / "Library/local/cryptor").glob("*/audio"))
if not cache_roots:
    raise SystemExit("No decrypted audio files were materialized in the app's local cache")

for label, relative in checks:
    source = assets / relative
    if not source.is_file():
        raise SystemExit(f"Missing {label} fixture: {relative}")
    normalized = relative.replace("\\", "/")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    filename = f"cryptor_{digest}{source.suffix.lower()}"
    matches = [directory / filename for directory in cache_roots if (directory / filename).is_file()]
    previous_mtimes = before.get(relative, {})
    fresh_matches = [
        candidate for candidate in matches
        if candidate.stat().st_mtime_ns > previous_mtimes.get(str(candidate), -1)
    ]
    if not any(candidate.read_bytes() == source.read_bytes() for candidate in fresh_matches):
        raise SystemExit(f"No decrypted {label} cache matches source asset: {relative}")
    print(f"{label} cache verified: {relative}")
PY
}

read_robovm_identity() {
    local properties="$1"
    python3 - "$properties" <<'PY'
from pathlib import Path
import sys

values = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    stripped = line.strip()
    if stripped and not stripped.startswith("#") and "=" in stripped:
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
if not values.get("app.id") or not values.get("app.executable"):
    raise SystemExit("robovm.properties must define app.id and app.executable")
print(values["app.id"] + "\t" + values["app.executable"])
PY
}

run_app() {
    local app="$1"
    local mode="$2"
    local sound_relative="$3"
    local music_relative="$4"
    local repo="$MRZ_ROOT/$app"
    local assets="$repo/assets"
    local properties="$repo/ios/robovm.properties"
    local gradle_log="$LOG_DIR/$app-gradle.log"
    local app_log="$LOG_DIR/$app.log"

    [[ -x "$repo/gradlew" ]] || fail "$app has no executable Gradle wrapper"
    [[ -f "$properties" ]] || fail "$app is missing ios/robovm.properties"
    if [[ "$mode" == "encrypted" ]]; then
        [[ -f "$assets/$sound_relative" ]] || fail "$app is missing audio fixture $sound_relative"
        if [[ "$music_relative" != "-" ]]; then
            [[ -f "$assets/$music_relative" ]] || fail "$app is missing music fixture $music_relative"
        fi
    fi

    local identity bundle_id executable
    identity="$(read_robovm_identity "$properties")"
    IFS=$'\t' read -r bundle_id executable <<< "$identity"
    local simulator_app="$repo/ios/build/robovm.tmp/$executable.app"

    echo "[$app] building simulator app..."
    if ! (cd "$repo" && ./gradlew \
        --include-build "$PLUGIN_ROOT" \
        -Probovm.device.name="$simulator_name" \
        -Probovm.sdk.version="$IOS_VERSION" \
        :ios:launchIPhoneSimulator --console=plain) >"$gradle_log" 2>&1; then
        tail -n 80 "$gradle_log" >&2
        fail "$app simulator build failed (see $gradle_log)"
    fi
    if grep -Fq "Unable to find application named 'Simulator'" "$gradle_log"; then
        echo "[$app] RoboVM GUI handoff unavailable; continuing with simctl."
    fi

    [[ -d "$simulator_app" ]] || fail "$app simulator app bundle was not generated: $simulator_app"
    local build_info
    build_info="$(xcrun vtool -show-build "$simulator_app/$executable")"
    printf '%s\n' "$build_info" | grep -Fq "platform IOSSIMULATOR" || fail "$app binary is not an iOS Simulator build"
    printf '%s\n' "$build_info" | grep -Fq "sdk $IOS_VERSION" || fail "$app binary was not built with iOS $IOS_VERSION SDK"

    verify_bundle_assets "$app" "$mode" "$assets" "$repo/ios/build/encryptedAssets" "$simulator_app"

    local tmx_relative=""
    if [[ "$app" == "SamsWorld2" ]]; then
        tmx_relative="map/level/1/start.tmx"
    fi

    xcrun simctl terminate "$simulator_udid" "$bundle_id" >/dev/null 2>&1 || true
    xcrun simctl install "$simulator_udid" "$simulator_app"

    local container
    container="$(xcrun simctl get_app_container "$simulator_udid" "$bundle_id" data)"
    local audio_baseline="$LOG_DIR/$app-audio-before.json"
    if [[ "$mode" == "encrypted" ]]; then
        snapshot_audio_cache "$container" "$sound_relative" "$music_relative" > "$audio_baseline"
    fi

    local launch_log_start
    launch_log_start="$(date '+%Y-%m-%d %H:%M:%S')"
    local launch_output
    if [[ "$app" == "SamsWorld2" ]]; then
        launch_output="$(SIMCTL_CHILD_SW2_START_LEVEL=1 xcrun simctl launch "$simulator_udid" "$bundle_id")"
    else
        launch_output="$(xcrun simctl launch "$simulator_udid" "$bundle_id")"
    fi
    echo "$launch_output" > "$LOG_DIR/$app-launch.txt"
    local pid
    pid="$(printf '%s\n' "$launch_output" | awk -F': ' 'END { print $NF }')"
    [[ "$pid" =~ ^[0-9]+$ ]] || fail "$app simctl launch returned no process id: $launch_output"

    local running=false
    local attempt
    for attempt in $(seq 1 30); do
        if xcrun simctl spawn "$simulator_udid" launchctl procinfo "$pid" >/dev/null 2>&1; then
            running=true
            break
        fi
        sleep 1
    done
    [[ "$running" == true ]] || fail "$app process exited before smoke assertions (pid $pid)"

    if [[ "$mode" == "encrypted" ]]; then
        local audio_ok=false
        local attempt
        for attempt in $(seq 1 30); do
            if verify_audio_cache "$assets" "$container" "$sound_relative" "$music_relative" "$audio_baseline" >"$LOG_DIR/$app-audio.txt" 2>&1; then
                audio_ok=true
                break
            fi
            sleep 2
        done
        if [[ "$audio_ok" != true ]]; then
            cat "$LOG_DIR/$app-audio.txt" >&2
            fail "$app did not materialize fresh decrypted sound/music assets"
        fi
        cat "$LOG_DIR/$app-audio.txt"
    else
        echo "$app startup-only mode: no Cryptor audio-cache assertion"
    fi

    xcrun simctl spawn "$simulator_udid" log show --start "$launch_log_start" --style compact \
        --predicate "process == \"$executable\" AND processIdentifier == $pid" \
        >"$app_log" 2>/dev/null || true
    if [[ "$app" == "SamsWorld2" ]]; then
        local tmx_loaded=false
        for attempt in $(seq 1 30); do
            xcrun simctl spawn "$simulator_udid" log show --start "$launch_log_start" --style compact \
                --predicate "process == \"$executable\" AND processIdentifier == $pid" \
                >"$app_log" 2>/dev/null || true
            if grep -Fq "TMXMapLoader.loadGameMap: $tmx_relative" "$app_log"; then
                tmx_loaded=true
                break
            fi
            sleep 1
        done
        [[ "$tmx_loaded" == true ]] || fail "SamsWorld2 did not load the level-1 TMX fixture"
        grep -Fq "LocalizationManager: locale=" "$app_log" || fail "SamsWorld2 startup localization marker is missing"
        if grep -Fq "LocalizationManager.loadLocaleLanguageBundle() must be called before getBundle()" "$app_log"; then
            fail "SamsWorld2 hit the startup localization ordering regression"
        fi
    fi

    xcrun simctl spawn "$simulator_udid" launchctl procinfo "$pid" >/dev/null 2>&1 ||
        fail "$app exited before the smoke assertions completed"

    local screenshot="$LOG_DIR/$app.png"
    xcrun simctl io "$simulator_udid" screenshot "$screenshot" >/dev/null
    [[ -s "$screenshot" ]] || fail "$app screenshot was not written"
    if [[ "$mode" == "encrypted" ]]; then
        echo "PASS $app (iOS $IOS_VERSION, encrypted bundle, startup, audio cache, screenshot)"
    else
        echo "PASS $app (iOS $IOS_VERSION, startup/TMX and screenshot; Cryptor assets/audio are not asserted)"
    fi
    xcrun simctl terminate "$simulator_udid" "$bundle_id" >/dev/null 2>&1 || true
}

run_app SamsWorld2 startup-only "-" "-"
run_app SamsWorld encrypted "sounds/kick.mp3" "music/menu.mp3"
run_app ZacksWorld encrypted "sounds/kick.mp3" "music/menu.mp3"
run_app SamsLevelMaker encrypted "sounds/bump.mp3" "-"
run_app ZacksLevelMaker encrypted "sounds/bump.mp3" "-"
run_app MakeWords encrypted "sounds/click.mp3" "music/menu.mp3"

echo "All Cryptor iOS simulator smoke tests passed on iOS $IOS_VERSION. Logs: $LOG_DIR"
