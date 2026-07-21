#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
usage:
  block-fault-stack.sh create <new-work-directory> [size-gib]
  block-fault-stack.sh restore <work-directory>
  block-fault-stack.sh mode <work-directory> <healthy|io-error|error-writes|drop-writes|corrupt-byte|random-corrupt|progress-error>
  block-fault-stack.sh mark <work-directory> <label>
  block-fault-stack.sh status <work-directory>
  block-fault-stack.sh destroy <work-directory>

Creates only sparse files, loop devices, and uniquely named device-mapper
targets. It never accepts a physical block device. Run it as root in a
disposable Linux VM used for fault qualification.
EOF
}

fail() {
    echo "block-fault-stack: $*" >&2
    exit 1
}

require_root() {
    [[ ${EUID} -eq 0 ]] || fail "must run as root"
}

require_tools() {
    local tool
    for tool in blockdev dmsetup findmnt losetup realpath truncate; do
        command -v "${tool}" >/dev/null || fail "missing required tool: ${tool}"
    done
}

require_targets() {
    local targets
    targets=$(dmsetup targets)
    grep -q '^flakey ' <<<"${targets}" || fail "kernel does not provide the dm-flakey target"
    grep -q '^log-writes ' <<<"${targets}" || fail "kernel does not provide the dm-log-writes target"
}

load_metadata() {
    local requested=$1
    work_dir=$(realpath "${requested}")
    [[ ${work_dir} =~ ^/[A-Za-z0-9_./-]+$ ]] || fail "work directory contains unsupported characters"
    [[ -f ${work_dir}/stack.state ]] || fail "missing ${work_dir}/stack.state"
    # The state file is created by this root-only script in a new directory.
    # shellcheck disable=SC1090
    source "${work_dir}/stack.state"
    [[ ${state_version:-} == 1 ]] || fail "unsupported state version"
    [[ ${data_image:-} == "${work_dir}/data.img" ]] || fail "unexpected data image"
    [[ ${log_image:-} == "${work_dir}/log.img" ]] || fail "unexpected log image"
    [[ ${fault_name:-} == cw_fault_* && ${log_name:-} == cw_log_* ]] || fail "unexpected mapper names"
    [[ -f ${data_image} && -f ${log_image} ]] || fail "backing images are missing"
}

load_state() {
    load_metadata "$1"
    [[ ${data_loop:-} == /dev/loop* && ${log_loop:-} == /dev/loop* ]] || fail "state does not reference loop devices"
    [[ $(losetup -n -O BACK-FILE "${data_loop}") == "${data_image}" ]] || fail "data loop backing changed"
    [[ $(losetup -n -O BACK-FILE "${log_loop}") == "${log_image}" ]] || fail "log loop backing changed"
}

load_table() {
    local table=$1
    dmsetup suspend "${fault_name}"
    if ! dmsetup load "${fault_name}" --table "${table}"; then
        dmsetup resume "${fault_name}"
        return 1
    fi
    dmsetup resume "${fault_name}"
}

command_name=${1:-}
case ${command_name} in
    create)
        require_root
        require_tools
        require_targets
        [[ $# -ge 2 && $# -le 3 ]] || { usage; exit 2; }
        requested=$2
        size_gib=${3:-8}
        [[ ${size_gib} =~ ^[1-9][0-9]*$ ]] || fail "size-gib must be a positive integer"
        (( size_gib <= 1024 )) || fail "size-gib must not exceed 1024"
        work_dir=$(realpath -m "${requested}")
        [[ ${work_dir} =~ ^/[A-Za-z0-9_./-]+$ ]] || fail "work directory contains unsupported characters"
        [[ ! -e ${work_dir} ]] || fail "create target already exists: ${work_dir}"
        mkdir -m 0700 "${work_dir}"
        data_image=${work_dir}/data.img
        log_image=${work_dir}/log.img
        log_size_gib=$((size_gib * 4))
        truncate -s "${size_gib}G" "${data_image}"
        truncate -s "${log_size_gib}G" "${log_image}"
        data_loop=$(losetup --find --show "${data_image}")
        log_loop=$(losetup --find --show "${log_image}")
        suffix=$$
        fault_name=cw_fault_${suffix}
        log_name=cw_log_${suffix}
        sectors=$(blockdev --getsz "${data_loop}")
        cleanup_create() {
            dmsetup remove "${log_name}" 2>/dev/null || true
            dmsetup remove "${fault_name}" 2>/dev/null || true
            losetup --detach "${log_loop}" 2>/dev/null || true
            losetup --detach "${data_loop}" 2>/dev/null || true
        }
        trap cleanup_create ERR
        dmsetup create "${fault_name}" --table "0 ${sectors} flakey ${data_loop} 0 3600 1"
        dmsetup create "${log_name}" --table "0 ${sectors} log-writes /dev/mapper/${fault_name} ${log_loop}"
        cat >"${work_dir}/stack.state" <<EOF
state_version=1
data_image=${data_image}
log_image=${log_image}
data_loop=${data_loop}
log_loop=${log_loop}
fault_name=${fault_name}
log_name=${log_name}
sectors=${sectors}
EOF
        chmod 0600 "${work_dir}/stack.state"
        trap - ERR
        echo "data_device=/dev/mapper/${log_name}"
        echo "state=${work_dir}/stack.state"
        ;;
    restore)
        require_root
        require_tools
        require_targets
        [[ $# -eq 2 ]] || { usage; exit 2; }
        load_metadata "$2"
        ! dmsetup info "${fault_name}" >/dev/null 2>&1 || fail "old fault mapper still exists"
        ! dmsetup info "${log_name}" >/dev/null 2>&1 || fail "old log mapper still exists"
        [[ -z $(losetup -j "${data_image}") ]] || fail "data image is already attached"
        [[ -z $(losetup -j "${log_image}") ]] || fail "log image is already attached"
        data_loop=$(losetup --find --show "${data_image}")
        log_loop=$(losetup --find --show "${log_image}")
        suffix=$$
        fault_name=cw_fault_${suffix}
        log_name=cw_log_${suffix}
        sectors=$(blockdev --getsz "${data_loop}")
        cleanup_restore() {
            dmsetup remove "${log_name}" 2>/dev/null || true
            dmsetup remove "${fault_name}" 2>/dev/null || true
            losetup --detach "${log_loop}" 2>/dev/null || true
            losetup --detach "${data_loop}" 2>/dev/null || true
        }
        trap cleanup_restore ERR
        dmsetup create "${fault_name}" --table "0 ${sectors} flakey ${data_loop} 0 3600 1"
        dmsetup create "${log_name}" --table "0 ${sectors} log-writes /dev/mapper/${fault_name} ${log_loop}"
        cat >"${work_dir}/stack.state" <<EOF
state_version=1
data_image=${data_image}
log_image=${log_image}
data_loop=${data_loop}
log_loop=${log_loop}
fault_name=${fault_name}
log_name=${log_name}
sectors=${sectors}
EOF
        chmod 0600 "${work_dir}/stack.state"
        trap - ERR
        echo "data_device=/dev/mapper/${log_name}"
        ;;
    mode)
        require_root
        require_tools
        [[ $# -eq 3 ]] || { usage; exit 2; }
        load_state "$2"
        case $3 in
            healthy)
                table="0 ${sectors} flakey ${data_loop} 0 3600 1"
                ;;
            io-error)
                table="0 ${sectors} flakey ${data_loop} 0 1 3600"
                ;;
            error-writes)
                table="0 ${sectors} flakey ${data_loop} 0 1 3600 1 error_writes"
                ;;
            drop-writes)
                table="0 ${sectors} flakey ${data_loop} 0 1 3600 1 drop_writes"
                ;;
            corrupt-byte)
                table="0 ${sectors} flakey ${data_loop} 0 1 3600 1 corrupt_bio_byte 1 w 0 0"
                ;;
            random-corrupt)
                table="0 ${sectors} flakey ${data_loop} 0 1 3600 1 random_write_corrupt 1000000000"
                ;;
            progress-error)
                table="0 ${sectors} flakey ${data_loop} 0 1 1 1 error_writes"
                ;;
            *) fail "unknown fault mode: $3" ;;
        esac
        load_table "${table}"
        echo "loaded mode=$3; flakey begins in its up interval"
        ;;
    mark)
        require_root
        require_tools
        [[ $# -eq 3 ]] || { usage; exit 2; }
        [[ $3 =~ ^[A-Za-z0-9_.:-]+$ ]] || fail "mark contains unsupported characters"
        load_state "$2"
        dmsetup message "${log_name}" 0 mark "$3"
        ;;
    status)
        require_root
        require_tools
        [[ $# -eq 2 ]] || { usage; exit 2; }
        load_state "$2"
        dmsetup table "${fault_name}"
        dmsetup status "${fault_name}"
        dmsetup status "${log_name}"
        ;;
    destroy)
        require_root
        require_tools
        [[ $# -eq 2 ]] || { usage; exit 2; }
        load_state "$2"
        [[ -z $(findmnt -rn -S "/dev/mapper/${log_name}" -o TARGET) ]] || fail "data device is still mounted"
        dmsetup remove "${log_name}"
        dmsetup remove "${fault_name}"
        losetup --detach "${log_loop}"
        losetup --detach "${data_loop}"
        echo "detached mapper and loop devices; images and log remain in ${work_dir}"
        ;;
    *)
        usage
        exit 2
        ;;
esac
