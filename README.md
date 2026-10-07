# Unified WiFi Mesh

The database backend is SQLite3. The default database file is
`/var/lib/unified-wifi-mesh/unified_wifi_mesh.db`; it is created and initialized
on first startup. Pass a different SQLite file path as the controller database
argument when required.

Build systems require the SQLite3 development package (`libsqlite3-dev` on
Debian/Ubuntu) and `pkg-config`. MariaDB is not required. See
`docs/sqlite3_migration.md` for migrating an existing MariaDB database.

The documentation is available in Unified-Wifi-Mesh file under docs directory
