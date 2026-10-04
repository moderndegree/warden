#!/usr/bin/env bash
# Start the warden test bed on http://127.0.0.1:8740 (needs lev: systemctl --user start decision.service)
cd "$(dirname "$0")" && exec python3 -m warden testbed "$@"
