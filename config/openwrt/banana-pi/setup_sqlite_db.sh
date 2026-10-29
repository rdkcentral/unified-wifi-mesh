#!/bin/sh

DB_DIR="${EASYMESH_DB_DIR:-/var/lib/unified-wifi-mesh}"
DB_FILE="${EASYMESH_DB_FILE:-$DB_DIR/unified_wifi_mesh.db}"

mkdir -p "$DB_DIR"
touch "$DB_FILE"