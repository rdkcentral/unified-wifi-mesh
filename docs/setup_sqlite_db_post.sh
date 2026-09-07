#!/bin/sh

set -eu

# Allow platform-specific locations while keeping the current defaults.
DB_DIR="${EASYMESH_DB_DIR:-/var/lib/unified-wifi-mesh}"
DB_FILE="${EASYMESH_DB_FILE:-$DB_DIR/unified_wifi_mesh.db}"
DB_MARKER="${EASYMESH_DB_MARKER:-/nvram/sqlite_db_data_exists}"
EASYMESH_CONFIG_FILE="${EASYMESH_CONFIG_FILE:-/nvram/EasymeshCfg.json}"
EASYMESH_DB_LOG="${EASYMESH_DB_LOG:-/tmp/setup_sqlite_db_post.log}"

# Capture output because this script may be launched by the controller process.
exec >>"$EASYMESH_DB_LOG" 2>&1
echo "$(date '+%Y-%m-%d %H:%M:%S') setup_sqlite_db_post: starting"

ctrl_al_mac="$(cat /sys/class/net/eth0_virt_peer/address)"
agent_al_mac="$(cat /sys/class/net/eth1_virt_peer/address)"

# Keep the configuration MAC synchronized on every invocation, including when
# the database is already initialized and the script exits below.
if [ -f "$EASYMESH_CONFIG_FILE" ]; then
  old_ctrl_al_mac_addr="$(grep AL_MAC_ADDR "$EASYMESH_CONFIG_FILE" | cut -d '"' -f4)"
  if [ -n "$old_ctrl_al_mac_addr" ] && [ "$old_ctrl_al_mac_addr" != "$ctrl_al_mac" ]; then
    sed -i "s/$old_ctrl_al_mac_addr/$ctrl_al_mac/g" "$EASYMESH_CONFIG_FILE"
    echo "Updated AL_MAC_ADDR from $old_ctrl_al_mac_addr to $ctrl_al_mac in $EASYMESH_CONFIG_FILE"
  fi
fi

# Skip schema and seed creation when the database already contains NetworkList.
if [ -e "$DB_MARKER" ] && [ -s "$DB_FILE" ] &&
   sqlite3 -noheader -batch "$DB_FILE" \
     "SELECT 1 FROM NetworkList LIMIT 1;" 2>/dev/null | grep -q '^1$'; then
  exit 0
fi

# Create the database directory before opening the SQLite database.
mkdir -p "$DB_DIR"

# Create the schema required by the EasyMesh data model.
sqlite3 "$DB_FILE" <<EOF
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS NetworkSSIDList (
  ID TEXT PRIMARY KEY,
  SSID TEXT,
  PassPhrase TEXT,
  Band TEXT,
  Enable INTEGER,
  AKMsAllowed TEXT,
  SuiteSelector TEXT,
  AdvertisementEnabled INTEGER,
  MFPConfig TEXT,
  MobilityDomain TEXT,
  HaulType TEXT,
  AuthType TEXT,
  VLANID INTEGER
);
CREATE TABLE IF NOT EXISTS NetworkList (
  ID TEXT PRIMARY KEY,
  ControllerID TEXT,
  ColocatedAgentID TEXT,
  Media INTEGER
);
EOF

# Seed default network data only when each row does not already exist.
sqlite3 "$DB_FILE" <<EOF
INSERT OR IGNORE INTO NetworkSSIDList (
  ID,
  SSID,
  PassPhrase,
  Band,
  Enable,
  AKMsAllowed,
  SuiteSelector,
  AdvertisementEnabled,
  MFPConfig,
  MobilityDomain,
  HaulType,
  AuthType,
  VLANID
) VALUES
  -- ID                         SSID          PassPhrase       Band       Enable
  -- AKMsAllowed                SuiteSelector AdvertisementEnabled MFPConfig
  -- MobilityDomain             HaulType      AuthType          VLANID
  ('Fronthaul@OneWifiMesh',     'private_ssid', 'test-fronthaul', '2.4,5,6', 1,
   'dpp',                       '00010203',    1,                  'Optional',
   '00:01:02:03:04:05',        'Fronthaul',   'WPA3 Personal',   12),
  ('IoT@OneWifiMesh',           'iot_ssid',     'test-backhaul',   '2.4,5,6', 1,
   'dpp,sae,SuiteSelector',     '00010203',    1,                  'Required',
   '00:01:02:03:04:05',        'IoT',         'WPA3 Personal',   14),
  ('Configurator@OneWifiMesh', 'lnf_radius',   'test-backhaul',   '2.4,5,6', 1,
   'dpp,sae,SuiteSelector',     '00010203',    1,                  'Required',
   '00:01:02:03:04:05',        'Configurator', 'WPA3 Personal', 15),
  ('Backhaul@OneWifiMesh',      'mesh_backhaul', 'test-backhaul',  '2.4,5,6', 1,
   'dpp,sae,SuiteSelector',     '00010203',    1,                  'Required',
   '00:01:02:03:04:05',        'Backhaul',    'WPA3 Personal',   13),
  ('Hotspot@OneWifiMesh',       'hotspot',      'test-hotspot',    '2.4,5,6', 1,
   'dpp,sae,SuiteSelector',     '00010203',    1,                  'Required',
   '00:01:02:03:04:05',        'Hotspot',     'WPA3 Personal',   16);

INSERT OR REPLACE INTO NetworkList (
  ID,
  ControllerID,
  ColocatedAgentID,
  Media
) VALUES (
  'OneWifiMesh',
  '$ctrl_al_mac',
  '$agent_al_mac',
  0
);
EOF

# Mark initialization complete after schema creation and data seeding succeed.
touch "$DB_MARKER"
