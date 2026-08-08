#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"

if ! command -v gitleaks >/dev/null 2>&1; then
	echo "error: gitleaks is required (brew install gitleaks)" >&2
	exit 127
fi

forbidden=$(
	git ls-files -- \
		'*.pcap' '*.pcapng' '*.keylog' '*.key' '*.p12' '*.mobileconfig' \
		'captures/raw/**' 'fixtures/private/**' 'secrets/**'
)
if [ -n "$forbidden" ]; then
	echo "error: forbidden private artifact paths are tracked:" >&2
	printf '%s\n' "$forbidden" >&2
	exit 1
fi

gitleaks dir . \
	--no-banner \
	--redact \
	--max-target-megabytes "${GITLEAKS_MAX_TARGET_MB:-5}" \
	--timeout "${GITLEAKS_TIMEOUT_SECONDS:-30}"
