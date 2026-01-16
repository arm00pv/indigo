#!/bin/bash
set -e

# Wait for primary
until pg_isready -h db_primary -p 5432 -U indigo; do
  echo "Waiting for primary..."
  sleep 2
done

# Clean data dir
rm -rf /var/lib/postgresql/data/*

# Backup from primary
pg_basebackup -h db_primary -D /var/lib/postgresql/data -U replicator -P -v -R -X stream -C -S replication_slot

# Start Postgres
postgres
