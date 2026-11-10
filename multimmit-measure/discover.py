#!/usr/bin/env python3
"""Writes testbeds/<tb>/hosts.json ({name: [public ip, region]}) from EC2, by deployer tag."""
import concurrent.futures as cf, json, os, subprocess, sys
from pathlib import Path
import yaml
AR = Path(__file__).resolve().parent.parent
tb = sys.argv[1]
cfg = yaml.safe_load(open(AR / "testbeds" / tb / "deploy" / "config.yaml"))
tag = cfg["tag"]
regions = sorted({i["region"] for i in cfg["instances"]} | {"us-east-1"})
out = subprocess.run("aws configure export-credentials --profile ${AWS_PROFILE:-default} --format env", shell=True, check=True,
                     capture_output=True, text=True).stdout
env = dict(os.environ)
for line in out.splitlines():
    if line.startswith("export "):
        k, v = line[len("export "):].split("=", 1)
        env[k] = v.strip('"')
def one(region):
    r = subprocess.run(["aws", "ec2", "describe-instances", "--region", region, "--filters", f"Name=tag:deployer,Values={tag}",
                        "Name=instance-state-name,Values=running", "--query",
                        "Reservations[].Instances[].[Tags[?Key=='name']|[0].Value,PublicIpAddress,InstanceType]", "--output", "json"],
                       check=True, capture_output=True, text=True, env=env).stdout
    return [(n, ip, region, t) for n, ip, t in json.loads(r)]
hosts = {}
with cf.ThreadPoolExecutor(len(regions)) as ex:
    for rows in ex.map(one, regions):
        for n, ip, region, t in rows:
            hosts[n] = [ip, region, t]
expected = {i["name"]: i["region"] for i in cfg["instances"]}
missing = [n for n in expected if n not in hosts]
wrong = [n for n in expected if n in hosts and hosts[n][1] != expected[n]]
assert "monitoring" in hosts, "monitoring missing"
assert not missing and not wrong, (missing, wrong)
json.dump(hosts, open(AR / "testbeds" / tb / "hosts.json", "w"), indent=1)
print(json.dumps({"testbed": tb, "tag": tag, "instances": len(hosts), "monitoring": hosts["monitoring"]}))
