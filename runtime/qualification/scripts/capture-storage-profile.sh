#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: capture-storage-profile.sh <storage-path> <new-output-directory>" >&2
    exit 2
}

[[ $# -eq 2 ]] || usage
[[ $(uname -s) == Linux ]] || { echo "capture-storage-profile: Linux is required" >&2; exit 1; }

for tool in findmnt lsblk realpath sha256sum xargs; do
    command -v "${tool}" >/dev/null || {
        echo "capture-storage-profile: missing required tool: ${tool}" >&2
        exit 1
    }
done

read_sysfs_value() {
    local path=$1
    local value

    if [[ -r ${path} ]]; then
        value=$(<"${path}")
        value=$(xargs <<<"${value}")
    fi
    if [[ -n ${value:-} ]]; then
        echo "${value}"
    else
        echo unknown
    fi
}

storage_path=$(realpath -e "$1")
output=$(realpath -m "$2")
[[ ! -e ${output} ]] || {
    echo "capture-storage-profile: output already exists: ${output}" >&2
    exit 1
}

source_device=$(findmnt -T "${storage_path}" -n -o SOURCE)
[[ -b ${source_device} ]] || {
    echo "capture-storage-profile: storage path is not backed by a block device: ${source_device}" >&2
    exit 1
}

mkdir -m 0700 "${output}"

{
    echo "captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "storage_path=${storage_path}"
    echo "source_device=${source_device}"
    echo "kernel=$(uname -r)"
    echo "architecture=$(uname -m)"
    echo "machine=$(cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null || echo unknown)"
    echo "system_vendor=$(cat /sys/devices/virtual/dmi/id/sys_vendor 2>/dev/null || echo unknown)"
    echo "virtualization=$(systemd-detect-virt 2>/dev/null || echo unknown)"
    findmnt -T "${storage_path}" -n \
        -o TARGET,SOURCE,FSTYPE,OPTIONS,VFS-OPTIONS,FS-OPTIONS
} >"${output}/summary.txt"

cp /proc/version "${output}/proc-version.txt"
cp /proc/mounts "${output}/proc-mounts.txt"
[[ ! -f /etc/os-release ]] || cp /etc/os-release "${output}/os-release.txt"

findmnt --json --target "${storage_path}" \
    --output TARGET,SOURCE,FSTYPE,OPTIONS,VFS-OPTIONS,FS-OPTIONS \
    >"${output}/findmnt.json"
lsblk --json --bytes \
    --output NAME,KNAME,PATH,TYPE,SIZE,FSTYPE,FSVER,MOUNTPOINTS,ROTA,RO,RM,MODEL,VENDOR,REV,SERIAL,TRAN,WWN,LOG-SEC,PHY-SEC,MIN-IO,OPT-IO,DISC-GRAN,DISC-MAX \
    "${source_device}" >"${output}/lsblk.json"
lsblk --inverse --paths --output NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,REV \
    "${source_device}" >"${output}/device-stack.txt"

mapfile -t devices < <(lsblk --inverse --noheadings --output KNAME "${source_device}" | awk 'NF {print $1}')
for device in "${devices[@]}"; do
    sysfs=/sys/class/block/${device}
    [[ -e ${sysfs} ]] || continue
    report=${output}/device-${device}.txt
    {
        echo "device=/dev/${device}"
        echo "sysfs=$(realpath "${sysfs}")"
        echo "type=$(lsblk -dn -o TYPE "/dev/${device}")"
        echo "size_bytes=$(lsblk -bdn -o SIZE "/dev/${device}")"
        echo "model=$(read_sysfs_value "${sysfs}/device/model")"
        echo "vendor=$(read_sysfs_value "${sysfs}/device/vendor")"
        echo "firmware=$(read_sysfs_value "${sysfs}/device/firmware_rev")"
        for field in write_cache fua stable_writes logical_block_size physical_block_size \
            minimum_io_size optimal_io_size rotational scheduler discard_granularity discard_max_bytes; do
            value=$(cat "${sysfs}/queue/${field}" 2>/dev/null || echo unknown)
            echo "${field}=${value}"
        done
        if command -v blockdev >/dev/null; then
            echo "blockdev_sector_size=$(blockdev --getss "/dev/${device}" 2>/dev/null || echo unknown)"
            echo "blockdev_physical_sector_size=$(blockdev --getpbsz "/dev/${device}" 2>/dev/null || echo unknown)"
            echo "blockdev_minimum_io=$(blockdev --getiomin "/dev/${device}" 2>/dev/null || echo unknown)"
            echo "blockdev_optimal_io=$(blockdev --getioopt "/dev/${device}" 2>/dev/null || echo unknown)"
        fi
    } >"${report}"

    if command -v nvme >/dev/null && [[ ${device} == nvme* ]]; then
        nvme id-ctrl "/dev/${device}" >"${output}/nvme-${device}-id-ctrl.txt" 2>&1 || true
        nvme get-feature "/dev/${device}" --feature-id=6 \
            >"${output}/nvme-${device}-volatile-write-cache.txt" 2>&1 || true
    fi
    if command -v mdadm >/dev/null && [[ ${device} == md* ]]; then
        mdadm --detail "/dev/${device}" >"${output}/md-${device}.txt" 2>&1 || true
    fi
done

filesystem=$(findmnt -T "${storage_path}" -n -o FSTYPE)
mountpoint=$(findmnt -T "${storage_path}" -n -o TARGET)
if [[ ${filesystem} == ext4 ]] && command -v tune2fs >/dev/null; then
    tune2fs -l "${source_device}" >"${output}/ext4-superblock.txt" 2>&1 || true
elif [[ ${filesystem} == xfs ]] && command -v xfs_info >/dev/null; then
    xfs_info "${mountpoint}" >"${output}/xfs-info.txt" 2>&1 || true
fi

(
    cd "${output}"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum
) >"${output}/SHA256SUMS"

echo "captured storage profile in ${output}"
