# Shared setup of the optimizer gates (sourced). A gate that runs cargo sends
# every cargo command through $HEAVY when it is set (the machine-wide
# admission wrapper); never run a gate script itself under it. Ported from
# the toolchain's previous repository (tools/gates/common.sh); `repo` is the
# monorepo root.
set -euo pipefail
gates=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$gates/../../.." && pwd)
H=${HEAVY:-}
JOBS=${CARGO_BUILD_JOBS:-4}
say() { echo "[$(basename "$0" .sh)] $*"; }
