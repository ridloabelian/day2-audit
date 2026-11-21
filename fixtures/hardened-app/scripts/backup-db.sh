#!/usr/bin/env bash
set -euo pipefail
pg_dump "$DATABASE_URL" --format=custom --file="backup-$(date -u +%Y%m%dT%H%M%SZ).dump"
