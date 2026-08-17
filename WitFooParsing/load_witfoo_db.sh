#!/bin/bash
set -euo pipefail
DB=$(echo "$1" | tr '[:upper:]' '[:lower:]')
DIR=${2%/}
PSQL="apptainer exec instance://postgres_instance psql -h localhost -U postgres"
for f in subject_node_table file_node_table netflow_node_table event_table ground_truth_nodes; do
  [ -f "$DIR/$f.csv" ] || { echo "missing $DIR/$f.csv"; exit 1; }
done
$PSQL <<EOF
DROP DATABASE IF EXISTS $DB;
CREATE DATABASE $DB;
EOF
$PSQL -d "$DB" <<'EOF'
CREATE TABLE event_table (
    src_node VARCHAR, src_index_id VARCHAR, operation VARCHAR,
    dst_node VARCHAR, dst_index_id VARCHAR, event_uuid VARCHAR NOT NULL,
    timestamp_rec BIGINT, _id SERIAL PRIMARY KEY
);
CREATE UNIQUE INDEX event_table__id_uindex ON event_table (_id);
CREATE TABLE file_node_table (
    node_uuid VARCHAR NOT NULL, hash_id VARCHAR NOT NULL, path VARCHAR,
    index_id BIGINT, PRIMARY KEY (node_uuid, hash_id)
);
CREATE TABLE netflow_node_table (
    node_uuid VARCHAR NOT NULL, hash_id VARCHAR NOT NULL,
    src_addr VARCHAR, src_port VARCHAR, dst_addr VARCHAR, dst_port VARCHAR,
    index_id BIGINT, PRIMARY KEY (node_uuid, hash_id)
);
CREATE TABLE subject_node_table (
    node_uuid VARCHAR, hash_id VARCHAR, path VARCHAR, cmd VARCHAR,
    index_id BIGINT, PRIMARY KEY (node_uuid, hash_id)
);
EOF
$PSQL -d "$DB" <<EOF
\copy subject_node_table(node_uuid,hash_id,path,cmd,index_id) FROM '$DIR/subject_node_table.csv' CSV HEADER;
\copy file_node_table(node_uuid,hash_id,path,index_id) FROM '$DIR/file_node_table.csv' CSV HEADER;
\copy netflow_node_table(node_uuid,hash_id,src_addr,src_port,dst_addr,dst_port,index_id) FROM '$DIR/netflow_node_table.csv' CSV HEADER;
\copy event_table(src_node,src_index_id,operation,dst_node,dst_index_id,event_uuid,timestamp_rec) FROM '$DIR/event_table.csv' CSV HEADER;
EOF
echo "=== loaded $DB ==="
$PSQL -d "$DB" -c "select 'subjects', count(*) from subject_node_table
  union all select 'files', count(*) from file_node_table
  union all select 'netflows', count(*) from netflow_node_table
  union all select 'events', count(*) from event_table;"
