#!/bin/bash
# usage: bundle.sh <campaign-dir> <host log-multimmit binary>
# Generates the deployer bundle of each testbed (50 validators round-robin over its regions, one monitor)
# and gives every node config an idle far-future benchmark schedule; the driver rewrites it per run.
set -euo pipefail
AR=$(cd "$1" && pwd); LM=$2
for tb in global na; do
  if [ $tb = global ]; then
    R=us-east-1,us-west-2,ca-central-1,eu-central-1,eu-west-1,eu-west-2,eu-west-3,eu-north-1,ap-south-1,ap-southeast-1,ap-southeast-2,ap-northeast-1,ap-northeast-2
  else
    R=us-east-1,us-east-2,ca-central-1
  fi
  rm -rf "$AR/testbeds/$tb/deploy"
  "$LM" deploy --output-dir "$AR/testbeds/$tb/deploy" --nodes 50 --regions $R \
    --instance-type c8g.12xlarge --monitoring-instance-type c8g.8xlarge \
    --storage-size 1000 --storage-class io2 --storage-iops 16000 --monitoring-storage-size 500 \
    --worker-threads 16 --compute-threads 24 --body-size 262144 \
    --pipeline-depth 32 --extension-bound 8 --marshal-memory-bytes 12884901888 --trace-sampling 0 \
    > "$AR/testbeds/$tb/bundle.log" 2>&1
  cp "$AR/build/base/commonware-log-multimmit" "$AR/testbeds/$tb/deploy/commonware-log-multimmit"
done
python3 - "$AR" <<'EOF'
import glob, sys, time, yaml
b = {"committee_seed": 1, "schedule": {"start_unix_ms": int((time.time() + 48 * 3600) * 1000),
                                       "phases": [{"duration_ms": 1000, "bytes_per_second": 0}]}}
for f in glob.glob(sys.argv[1] + "/testbeds/*/deploy/node-*.yaml"):
    cfg = yaml.safe_load(open(f)); out = {"benchmark": b}; out.update(cfg)
    yaml.safe_dump(out, open(f, "w"), sort_keys=False)
EOF
echo "bundles in $AR/testbeds/{global,na}/deploy"
