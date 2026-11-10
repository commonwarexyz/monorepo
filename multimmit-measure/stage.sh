#!/bin/bash
# usage: stage.sh <testbed>: uploads the three binaries under the deployment's S3 prefix and presigns them
set -euo pipefail
AR=$(cd "$(dirname "$0")/.." && pwd)
tb=$1
TAG=$(grep '^tag:' $AR/testbeds/$tb/deploy/config.yaml | cut -d' ' -f2)
BUCKET=$(cat ~/.commonware_deployer/bucket)
eval $(aws configure export-credentials --profile "${AWS_PROFILE:-default}" --format env)
echo "{" > $AR/testbeds/$tb/presigned.json
first=1
for m in base payments base-fsync; do
  aws s3 cp --only-show-errors $AR/build/r4/$m/commonware-log-multimmit s3://$BUCKET/deployments/$TAG/extra/$m
  url=$(aws s3 presign s3://$BUCKET/deployments/$TAG/extra/$m --expires-in 21600 --region us-east-1)
  [ $first = 1 ] || echo "," >> $AR/testbeds/$tb/presigned.json; first=0
  printf '"%s": "%s"' $m "$url" >> $AR/testbeds/$tb/presigned.json
done
echo "}" >> $AR/testbeds/$tb/presigned.json
echo "- $(date -u +%FT%TZ) [$tb] uploaded 3 binaries to s3://$BUCKET/deployments/$TAG/extra/ (removed by destroy with the deployment prefix)" >> $AR/RESOURCES.md
echo STAGED_S3
