#!/bin/bash
# usage: create.sh <testbed>
set -uo pipefail
AR=$(cd "$(dirname "$0")/.." && pwd)
tb=$1; D=$AR/testbeds/$tb
TAG=$(grep '^tag:' $D/deploy/config.yaml | cut -d' ' -f2)
R=$AR/RESOURCES.md
[ -f $R ] || cat > $R <<EOF
# AWS resources for the Multimmit paper re-measurement

Load creds: eval \$(aws configure export-credentials --profile "${AWS_PROFILE:-default}" --format env)
Deployer: $AR/build/deployer

## Teardown (each testbed)
cd $AR/testbeds/global/deploy && $AR/build/deployer aws destroy --config config.yaml
cd $AR/testbeds/na/deploy && $AR/build/deployer aws destroy --config config.yaml
# The deployer's shared S3 cache bucket is reused across deployments; destroy removes this deployment's prefix only.

## Log
EOF
echo "- $(date -u +%FT%TZ) [$tb] starting 'deployer aws create' for tag $TAG (50 x c8g.12xlarge, io2 1000 GiB/16k IOPS; 1 x c8g.8xlarge monitoring gp3 500 GiB in us-east-1)" >> $R
cd $D/deploy && eval $(aws configure export-credentials --profile "${AWS_PROFILE:-default}" --format env) && $AR/build/deployer aws create --config config.yaml > $D/create.log 2>&1
rc=$?
if [ $rc -ne 0 ]; then echo "- $(date -u +%FT%TZ) [$tb] create FAILED rc=$rc (see testbeds/$tb/create.log); run teardown" >> $R; exit 1; fi
echo "- $(date -u +%FT%TZ) [$tb] create complete" >> $R
echo CREATE_DONE
