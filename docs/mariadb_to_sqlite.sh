#!/bin/sh

set -eu

if [ "$#" -ne 5 ]; then
    echo "Usage: $0 <mariadb-host> <mariadb-user> <mariadb-password> <database> <sqlite-file>" >&2
    exit 2
fi

host=$1
user=$2
password=$3
database=$4
sqlite_file=$5

if [ -e "$sqlite_file" ] && [ -s "$sqlite_file" ]; then
    echo "Refusing to import into non-empty SQLite file: $sqlite_file" >&2
    echo "Choose a new target file or move the existing file to a backup first." >&2
    exit 1
fi

dump_file=$(mktemp)
trap 'rm -f "$dump_file"' EXIT

MYSQL_PWD="$password" mysqldump --host="$host" --user="$user" \
    --skip-extended-insert --skip-comments "$database" > "$dump_file"

sed -i \
    -e 's/ AUTO_INCREMENT//g' \
    -e 's/ TINYINT([^)]*)/ INTEGER/Ig' \
    -e 's/ TINYINT/ INTEGER/Ig' \
    -e 's/ DATETIME([^)]*)/ TEXT/Ig' \
    -e 's/ DATETIME/ TEXT/Ig' \
    -e 's/ unsigned//Ig' \
    -e 's/ ENGINE=[^;]*//Ig' \
    -e 's/ DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP/ DEFAULT CURRENT_TIMESTAMP/Ig' \
    -e 's/`/"/g' \
    -e 's/INSERT IGNORE/INSERT OR IGNORE/Ig' \
    -e '/^SET /d' \
    -e '/^LOCK TABLES /d' \
    -e '/^UNLOCK TABLES;/d' \
    "$dump_file"

mkdir -p "$(dirname "$sqlite_file")"
sqlite3 "$sqlite_file" < "$dump_file"
echo "Imported $database into $sqlite_file"