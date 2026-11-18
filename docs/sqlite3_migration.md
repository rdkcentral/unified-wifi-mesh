# MariaDB to SQLite3 migration

This document records the MariaDB removal and SQLite3 implementation in
`unified-wifi-mesh`.

## Result

The controller no longer requires a MariaDB server, MariaDB client headers, or
MariaDB client libraries. The database is a local SQLite3 file:

```text
/var/lib/unified-wifi-mesh/unified_wifi_mesh.db
```

The database file and its parent directory are created automatically when the
database client opens the path. The existing table loaders create each missing
table during startup, so a new empty file is initialized without a separate SQL
server or setup database.

Migration is data-preserving: the MariaDB source is only read by the export
utility, and the SQLite importer refuses to write into a non-empty target file.
Use a new target path for each migration attempt and keep the original MariaDB
database and its backup until the imported data has been verified.

## Source changes

### `inc/db_client.h`

- Replaced conditional MariaDB/MySQL includes with `<sqlite3.h>`.
- Replaced the `MYSQL *` connection member with `sqlite3 *`.
- Added the configured file path and a per-client mutex.
- Preserved `init`, `execute`, `next_result`, `get_string`, `get_number`, and
    `recreate_db` wrapper methods.
- Added `free_result(void *)` for partially consumed results.
- Added `begin_transaction()`, `commit()`, and `rollback()` methods.

### `src/db/db_client.cpp`

- `sqlite3_open()` replaces `mysql_init()` and `mysql_real_connect()`.
- Empty or null paths use the default database file. Non-empty paths are treated
    directly as SQLite file paths; `username@password` is no longer parsed.
- Parent directories are created with `std::filesystem` before opening the file.
- `sqlite3_prepare_v2()` and `sqlite3_step()` replace `mysql_query()` and
    `mysql_store_result()`.
- Result contexts retain a `sqlite3_stmt *`. `next_result()` advances rows and
    getters use SQLite column APIs.
- `sqlite3_finalize()` replaces `mysql_free_result()` and `sqlite3_close()`
    replaces `mysql_close()`.
- Errors use `sqlite3_errmsg()`.
- A 5-second `sqlite3_busy_timeout()` and mutex protection serialize shared
    client access.
- `recreate_db()` enumerates user tables through `sqlite_master`, finalizes the
    enumeration, and drops those tables. SQLite has no `DROP DATABASE` command.
- Transactions use `BEGIN IMMEDIATE TRANSACTION`, `COMMIT`, and `ROLLBACK`.

### `src/db/db_easy_mesh.cpp`

- Replaced MariaDB `SHOW TABLES` with a query against SQLite's `sqlite_master`.
- Generated `tinyint` columns now use `integer` declarations.
- Added `datetime` handling as `text`.
- Corrected `compare_row()` so variadic arguments are formatted before execution.
- Existing table model callers and wrapper APIs remain unchanged.

### `src/ctrl/dm_easy_mesh_ctrl.cpp`

Replaced the MariaDB fallback with an RDKB SQLite fallback invoking
`/usr/ccsp/EasyMesh/setup_sqlite_db_post.sh` when `NetworkList` is empty.
The controller reloads the tables after the script seeds the initial network
configuration. OpenWrt uses its init script and `setup_sqlite_db.sh` instead.

## Build and dependency changes

The following makefiles no longer link MariaDB or call `mariadb_config`:

- `build/agent/makefile`
- `build/cli/makefile`
- `build/ctrl/makefile`
- `build/openwrt/agent/makefile`
- `build/openwrt/cli/makefile`
- `build/openwrt/ctrl/makefile`
- `src/ctrl/Makefile.am`

They remove `-lmariadb`, `mariadb_config --include`,
`mariadb_config --libs`, and the OpenWrt MySQL include directory. Native and
OpenWrt targets now link `-lsqlite3`; the native controller also uses
`pkg-config --cflags sqlite3` and `pkg-config --libs sqlite3`.

### `configure.ac`

Adds `sqlite3.h` to header checks and verifies `sqlite3_open` with
`AC_CHECK_LIB`. Configuration fails early if the SQLite3 development library is
missing.

### CI workflows

`.github/workflows/build.yml` and `.github/workflows/unit-tests.yml` remove
`libmysqlcppconn-dev`, `mariadb-server`, `libmariadb3`, and `libmariadb-dev`.
Both install `libsqlite3-dev` instead.

## Deployment and configuration

### `config/openwrt/banana-pi/etc/init.d/em_ctrl`

The controller argument changed from `bpi@root` to
`/var/lib/unified-wifi-mesh/unified_wifi_mesh.db`. The MariaDB setup log and
script invocation were replaced with SQLite initialization.

### `config/openwrt/banana-pi/setup_sqlite_db.sh`

creates `/var/lib/unified-wifi-mesh` and an empty database file. The application
performs schema initialization when it opens the file. The RDKB
`scripts/setup_sqlite_db_post.sh` additionally seeds the initial
`NetworkList` and `NetworkSSIDList` rows. The old `setup_mysql_db.sh` was
removed.

No `db_host`, `db_port`, `db_user`, or `db_password` settings are used by the
migrated client. The only database connection setting is the file path passed to
`init()`.

## Tests

### `tests/test_l1_db_client.cpp`

- Replaced MariaDB result structures and row-fetch calls with `next_result()`.
- Replaced `mysql_free_result()` cleanup with `db_client_t::free_result()`.
- Converted the test schema to `INTEGER PRIMARY KEY AUTOINCREMENT`.
- Tests now use temporary SQLite files instead of credentials.
- Empty paths verify default-path behavior, and paths containing `@` are valid
    SQLite file names.

## Data migration utility

`docs/mariadb_to_sqlite.sh` runs `mysqldump`, removes common MariaDB-only
settings such as `AUTO_INCREMENT`, `UNSIGNED`, engine clauses, session `SET`
statements, and table locks, converts `INSERT IGNORE` to `INSERT OR IGNORE`,
converts common `TINYINT` declarations to `INTEGER` and `DATETIME` declarations
to `TEXT`, then imports the dump with the SQLite command-line tool.

```sh
sh docs/mariadb_to_sqlite.sh localhost mesh_user 'password' OneWifiMesh \
        /var/lib/unified-wifi-mesh/unified_wifi_mesh.db
```

This utility is intended for table and row migration. Dumps containing stored
procedures, triggers, views, vendor-specific SQL, or complex MariaDB syntax must
be reviewed before import. The utility does not delete or modify the MariaDB
source, and it refuses to overwrite an existing non-empty SQLite file. Back up
the source database before exporting and retain the dump and original database
until validation is complete.

After import, verify row counts and representative records against the source,
then point the controller at the imported file. The original MariaDB data is
kept as the rollback copy during this verification period.

## SQLite verification commands

After the database file is created or populated, these commands are the usual
SQLite checks for confirming the schema and table contents:

```sh
sqlite3 /var/lib/unified-wifi-mesh/unified_wifi_mesh.db ".tables"

sqlite3 -header -column /var/lib/unified-wifi-mesh/unified_wifi_mesh.db \
    "SELECT * FROM NetworkList;"

sqlite3 -header -column /var/lib/unified-wifi-mesh/unified_wifi_mesh.db \
    "SELECT COUNT(*) AS network_count FROM NetworkSSIDList;"

sqlite3 -header -column /var/lib/unified-wifi-mesh/unified_wifi_mesh.db \
    "SELECT * FROM NetworkSSIDList;"

sqlite3 -header -column /var/lib/unified-wifi-mesh/unified_wifi_mesh.db \
    "SELECT * FROM OperatingClassList;"

sqlite3 -header -column /var/lib/unified-wifi-mesh/unified_wifi_mesh.db \
    "SELECT * FROM RadioInfo;"

sqlite3 -header -column /var/lib/unified-wifi-mesh/unified_wifi_mesh.db \
    "SELECT * FROM DeviceList;"
```

### Interactive sqlite3 session example

```sh
sqlite3 /var/lib/unified-wifi-mesh/unified_wifi_mesh.db
SQLite version 3.x.x
Enter ".help" for usage hints.

sqlite> .tables
sqlite> .schema NetworkList
sqlite> SELECT COUNT(*) FROM NetworkList;
sqlite> SELECT * FROM NetworkSSIDList LIMIT 10;
sqlite> .mode column
sqlite> .headers on
sqlite> SELECT * FROM OperatingClassList;
sqlite> .quit
```

This is the simplest way to inspect the live SQLite database from a shell, check
which tables exist, and query representative rows before or after migration.

## Compatibility differences

- SQLite has no host, port, username, password, or server database selection.
- SQLite uses type affinity; generated integer-family fields use `integer` and
    datetime fields use `text`.
- SQLite does not support MariaDB `SHOW TABLES`, `ENGINE=InnoDB`, character-set
    clauses, or server-level database creation.
- `execute(const char *)` remains raw SQL. Existing variadic table wrappers
    preserve their APIs, but callers constructing SQL strings remain responsible
    for escaping values. A parameter-binding API would be needed for complete SQL
    injection hardening.
- No pre-existing application transaction calls were found. Transaction methods
    are now available on `db_client_t` for atomic flows.
- The client mutex serializes shared-handle access. Separate connections should
    be used for independent per-thread transaction lifetimes.
