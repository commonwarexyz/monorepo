//! CPU identification of a campaign machine: the key hardware evidence is
//! recorded under (design §19.1: "keyed by model hash × CPUID
//! vendor/family/model/stepping (+ microcode)").
//!
//! * **x86_64**: CPUID leaf 0 (vendor string) and leaf 1 EAX (the signature),
//!   decoded into the *display* family and model of the Intel SDM /
//!   AMD APM (family = base + extended family when the base family is 0xF;
//!   model = extended model · 16 + base model when the base family is 6 or
//!   0xF). `__cpuid` is a safe function on x86_64, so this module needs no
//!   `unsafe`.
//! * **aarch64**: Linux `/proc/cpuinfo` (`CPU implementer`, `CPU architecture`,
//!   `CPU part`, `CPU variant`, `CPU revision`, i.e. MIDR_EL1), or on macOS
//!   `sysctl hw.cpufamily` / `hw.cpusubfamily` (Apple does not expose MIDR).
//! * **microcode**: Linux `/sys/devices/system/cpu/cpu0/microcode/version`
//!   or the `microcode` line of `/proc/cpuinfo`; macOS on Intel
//!   `sysctl machdep.cpu.microcode_version`; otherwise unknown (Rosetta 2
//!   exposes none and reports a synthetic `GenuineIntel` family 6 model 0x2c).
//!
//! The key is `vendor/FF-MM-SS/microcode` in lower-case hex
//! (`AuthenticAMD/1a-44-00/0xb404023`), with `+executor` appended when the
//! campaign did not run natively (`GenuineIntel/06-2c-00/unknown+rosetta2`),
//! so emulated and native results never share a key.
//!
//! **Emulators** ([`detect_emulator`]). An instruction emulator can report a
//! real CPU's CPUID (Intel SDE `-spr` claims a Sapphire Rapids), so the key
//! alone does not say the instructions ran on that CPU. The probe looks for
//! the emulators it can see from inside the process: QEMU system emulation
//! without KVM (CPUID hypervisor leaf `TCGTCGTCGTCG` → `qemu-tcg`), and on
//! Linux Intel SDE / Pin (`sde`), Valgrind (`valgrind`) and DynamoRIO
//! (`dynamorio`) through the files mapped into the process. Hardware
//! virtualization (KVM, Hyper-V, Xen, VMware, Nitro) executes the
//! instructions on the CPU and stays `native`. What the probe cannot see
//! (QEMU user mode hides itself from `/proc/self`) is named with the
//! evidence binary's `--executor`. Only `native` and `rosetta2` results ever
//! validate (`evidence::executor_may_validate`, an allowlist).
#![forbid(unsafe_code)]

use crate::json::Json;

/// CPU identification (see the module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuId {
    /// x86: the CPUID vendor string (`GenuineIntel`, `AuthenticAMD`);
    /// aarch64: the implementer (`Apple`, or MIDR's implementer code `0x41`).
    pub vendor: String,
    /// Display family (x86), architecture (aarch64 Linux) or `hw.cpufamily`
    /// (macOS).
    pub family: u32,
    /// Display model (x86), part number (aarch64 Linux) or `hw.cpusubfamily`.
    pub model: u32,
    /// Stepping (x86) or `variant << 4 | revision` (aarch64 Linux).
    pub stepping: u32,
    /// Microcode revision as the OS prints it (`0x2b000603`), if exposed.
    pub microcode: Option<String>,
    /// The raw signature: x86 CPUID.1:EAX, aarch64 MIDR_EL1 (Linux), if known.
    pub signature: Option<u64>,
}

impl CpuId {
    /// Decode an x86 CPUID.1:EAX signature (SDM Vol. 2A, CPUID "Version
    /// Information"; AMD APM Vol. 3, CPUID Fn0000_0001_EAX).
    pub fn from_x86(vendor: &str, eax: u32, microcode: Option<String>) -> CpuId {
        let stepping = eax & 0xf;
        let base_model = (eax >> 4) & 0xf;
        let base_family = (eax >> 8) & 0xf;
        let ext_model = (eax >> 16) & 0xf;
        let ext_family = (eax >> 20) & 0xff;
        let family = if base_family == 0xf { base_family + ext_family } else { base_family };
        let model = if base_family == 0x6 || base_family == 0xf { (ext_model << 4) + base_model } else { base_model };
        CpuId { vendor: vendor.to_string(), family, model, stepping, microcode, signature: Some(u64::from(eax)) }
    }

    /// The key (without the executor suffix): `vendor/FF-MM-SS/microcode`.
    pub fn key(&self) -> String {
        format!(
            "{}/{:02x}-{:02x}-{:02x}/{}",
            self.vendor.replace(['/', '+', ' '], "_"),
            self.family,
            self.model,
            self.stepping,
            self.microcode.as_deref().unwrap_or("unknown")
        )
    }

    /// The key of a campaign that ran on `executor` (`native`, `rosetta2`,
    /// `sde`, ...): [`CpuId::key`] plus `+executor` unless native.
    pub fn key_on(&self, executor: &str) -> String {
        if executor == "native" { self.key() } else { format!("{}+{executor}", self.key()) }
    }

    /// The JSON record (`vendor`, `family`, `model`, `stepping` as numbers,
    /// `microcode` and `signature` as strings or `null`).
    pub fn to_json(&self) -> Json {
        Json::obj([
            ("vendor", Json::str(self.vendor.clone())),
            ("family", Json::uint(u64::from(self.family))),
            ("model", Json::uint(u64::from(self.model))),
            ("stepping", Json::uint(u64::from(self.stepping))),
            ("microcode", self.microcode.as_ref().map_or(Json::Null, |m| Json::str(m.clone()))),
            ("signature", self.signature.map_or(Json::Null, |s| Json::str(format!("{s:#x}")))),
        ])
    }

    /// Parse [`CpuId::to_json`] output.
    pub fn from_json(j: &Json) -> Option<CpuId> {
        let n = |k: &str| j.get(k).and_then(Json::as_u64).and_then(|v| u32::try_from(v).ok());
        Some(CpuId {
            vendor: j.get("vendor")?.as_str()?.to_string(),
            family: n("family")?,
            model: n("model")?,
            stepping: n("stepping")?,
            microcode: j.get("microcode").and_then(Json::as_str).map(str::to_string),
            signature: j
                .get("signature")
                .and_then(Json::as_str)
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()),
        })
    }

    /// Probe the running machine (`None` on an architecture without models
    /// or when nothing can be read).
    pub fn probe() -> Option<CpuId> {
        probe_impl()
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn sysctl(name: &str) -> Option<String> {
    let out = std::process::Command::new("sysctl").args(["-n", name]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The first `key : value` line of `/proc/cpuinfo` whose key is `key`.
fn cpuinfo_field(info: &str, key: &str) -> Option<String> {
    info.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim() == key).then(|| v.trim().to_string())
    })
}

fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// The microcode revision exposed by the OS, normalized to `0x…` lower case.
pub fn microcode() -> Option<String> {
    let raw = read_trimmed("/sys/devices/system/cpu/cpu0/microcode/version")
        .or_else(|| {
            let info = std::fs::read_to_string("/proc/cpuinfo").ok()?;
            cpuinfo_field(&info, "microcode")
        })
        .or_else(|| sysctl("machdep.cpu.microcode_version"))?;
    Some(match parse_num(&raw) {
        Some(v) => format!("{v:#x}"),
        None => raw,
    })
}

#[cfg(target_arch = "x86_64")]
fn probe_impl() -> Option<CpuId> {
    use core::arch::x86_64::__cpuid;
    let l0 = __cpuid(0);
    let vendor: Vec<u8> = [l0.ebx, l0.edx, l0.ecx].iter().flat_map(|r| r.to_le_bytes()).collect();
    let vendor = String::from_utf8_lossy(&vendor).trim_matches(char::from(0)).to_string();
    let eax = if l0.eax >= 1 { __cpuid(1).eax } else { 0 };
    Some(CpuId::from_x86(&vendor, eax, microcode()))
}

#[cfg(target_arch = "aarch64")]
fn probe_impl() -> Option<CpuId> {
    if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
        let f = |k: &str| cpuinfo_field(&info, k).and_then(|v| parse_num(&v));
        if let (Some(imp), Some(part)) = (f("CPU implementer"), f("CPU part")) {
            let arch = f("CPU architecture").unwrap_or(8);
            let variant = f("CPU variant").unwrap_or(0);
            let rev = f("CPU revision").unwrap_or(0);
            let midr = (imp << 24) | (variant << 20) | (0xf << 16) | (part << 4) | rev;
            return Some(CpuId {
                vendor: format!("{imp:#04x}"),
                family: arch as u32,
                model: part as u32,
                stepping: ((variant << 4) | rev) as u32,
                microcode: microcode(),
                signature: Some(midr),
            });
        }
    }
    let family = sysctl("hw.cpufamily").and_then(|v| parse_num(&v))?;
    let sub = sysctl("hw.cpusubfamily").and_then(|v| parse_num(&v)).unwrap_or(0);
    Some(CpuId { vendor: "Apple".into(), family: family as u32, model: sub as u32, stepping: 0, microcode: None, signature: None })
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn probe_impl() -> Option<CpuId> {
    None
}

/// The instruction emulator this process runs under, if the probe can see
/// one (see the module documentation): `qemu-tcg`, `sde`, `valgrind` or
/// `dynamorio`; `None` for native execution (including hardware
/// virtualization). Rosetta 2 is detected separately
/// (`sysctl.proc_translated`).
pub fn detect_emulator() -> Option<String> {
    if let Some(e) = hypervisor_vendor().as_deref().and_then(emulator_from_hypervisor) {
        return Some(e.to_string());
    }
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    emulator_in_maps(&maps).map(str::to_string)
}

/// The emulator named by a CPUID hypervisor vendor signature (leaf
/// 0x4000_0000, EBX:ECX:EDX): QEMU's TCG (`TCGTCGTCGTCG`) translates every
/// instruction; the hardware hypervisors (`KVMKVMKVM`, `Microsoft Hv`,
/// `VMwareVMware`, `XenVMMXenVMM`, ...) do not.
pub fn emulator_from_hypervisor(vendor: &str) -> Option<&'static str> {
    (vendor.trim_matches(char::from(0)) == "TCGTCGTCGTCG").then_some("qemu-tcg")
}

/// The emulator whose files a `/proc/self/maps` text shows mapped into the
/// process: Intel SDE / Pin (`pinbin`, `libpindwarf*`, `libpinvm*`,
/// `*pin3dwarf*`, `libsde*`,
/// `sde-*.so`, an `sde-external-*` installation), Valgrind (`vgpreload_*`,
/// a `valgrind/` directory) or DynamoRIO (`libdynamorio*`, `libdrpreload*`).
pub fn emulator_in_maps(maps: &str) -> Option<&'static str> {
    for line in maps.lines() {
        // address perms offset dev inode [path, which may contain spaces]
        let path = line.split_whitespace().skip(5).collect::<Vec<_>>().join(" ");
        if path.is_empty() {
            continue;
        }
        let base = path.rsplit('/').next().unwrap_or(&path);
        if base == "pinbin"
            || base.starts_with("libpindwarf")
            || base.starts_with("libpinvm")
            || base.contains("pin3dwarf")
            || base.starts_with("libsde")
            || (base.starts_with("sde-") && base.contains(".so"))
            || path.contains("/sde-external-")
        {
            return Some("sde");
        }
        if base.starts_with("vgpreload_") || path.contains("/valgrind/") {
            return Some("valgrind");
        }
        if base.starts_with("libdynamorio") || base.starts_with("libdrpreload") {
            return Some("dynamorio");
        }
    }
    None
}

/// The CPUID hypervisor vendor signature, when CPUID.1:ECX[31] (hypervisor
/// present) is set.
#[cfg(target_arch = "x86_64")]
fn hypervisor_vendor() -> Option<String> {
    use core::arch::x86_64::__cpuid;
    if __cpuid(0).eax < 1 || __cpuid(1).ecx & (1 << 31) == 0 {
        return None;
    }
    let l = __cpuid(0x4000_0000);
    let v: Vec<u8> = [l.ebx, l.ecx, l.edx].iter().flat_map(|r| r.to_le_bytes()).collect();
    Some(String::from_utf8_lossy(&v).to_string())
}

#[cfg(not(target_arch = "x86_64"))]
fn hypervisor_vendor() -> Option<String> {
    None
}

/// A best-effort microarchitecture name for tuning files
/// (`tuning-<arch>-<uarch>.json`): known x86 family/model pairs, else
/// `<vendor>-<family>-<model>`.
pub fn uarch_name(cpu: &CpuId) -> String {
    let known = match (cpu.vendor.as_str(), cpu.family, cpu.model) {
        ("GenuineIntel", 6, 0x6a | 0x6c) => Some("icelake-server"),
        ("GenuineIntel", 6, 0x7d | 0x7e) => Some("icelake-client"),
        ("GenuineIntel", 6, 0x8c | 0x8d) => Some("tigerlake"),
        ("GenuineIntel", 6, 0x8f) => Some("sapphirerapids"),
        ("GenuineIntel", 6, 0xcf) => Some("emeraldrapids"),
        ("GenuineIntel", 6, 0xad | 0xae) => Some("graniterapids"),
        ("GenuineIntel", 6, 0x55) => Some("skylake-avx512"),
        ("GenuineIntel", 6, 0x2c) => Some("westmere-rosetta2"),
        ("AuthenticAMD", 0x19, 0x10..=0x1f | 0x60..=0x7f | 0xa0..=0xaf) => Some("zen4"),
        ("AuthenticAMD", 0x19, _) => Some("zen3"),
        ("AuthenticAMD", 0x1a, _) => Some("zen5"),
        ("Apple", _, _) => Some("apple"),
        _ => None,
    };
    match known {
        Some(n) => n.to_string(),
        None => format!("{}-{:x}-{:x}", cpu.vendor.to_ascii_lowercase().replace(['/', ' '], "_"), cpu.family, cpu.model),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_signatures_decode_to_display_family_and_model() {
        // Sapphire Rapids: family 6, model 0x8f, stepping 8 (eax 0x806f8).
        let spr = CpuId::from_x86("GenuineIntel", 0x0008_06f8, Some("0x2b000603".into()));
        assert_eq!((spr.family, spr.model, spr.stepping), (6, 0x8f, 8));
        assert_eq!(spr.key(), "GenuineIntel/06-8f-08/0x2b000603");
        assert_eq!(uarch_name(&spr), "sapphirerapids");
        // Zen 5 (Turin): family 0x1a (0xf + 0xb), model 0x02 (eax 0xb00f21).
        let zen5 = CpuId::from_x86("AuthenticAMD", 0x00b0_0f21, None);
        assert_eq!((zen5.family, zen5.model, zen5.stepping), (0x1a, 0x02, 1));
        assert_eq!(uarch_name(&zen5), "zen5");
        // Zen 4 (Genoa): family 0x19, model 0x11.
        let zen4 = CpuId::from_x86("AuthenticAMD", 0x00a1_0f11, None);
        assert_eq!((zen4.family, zen4.model), (0x19, 0x11));
        assert_eq!(uarch_name(&zen4), "zen4");
        // Rosetta 2's synthetic CPU: GenuineIntel family 6 model 0x2c stepping 0.
        let ros = CpuId::from_x86("GenuineIntel", 0x0002_06c0, None);
        assert_eq!(ros.key_on("rosetta2"), "GenuineIntel/06-2c-00/unknown+rosetta2");
        assert_eq!(ros.key_on("native"), "GenuineIntel/06-2c-00/unknown");
        // Base family 5 ignores the extended model.
        let p5 = CpuId::from_x86("GenuineIntel", 0x000f_0543, None);
        assert_eq!((p5.family, p5.model, p5.stepping), (5, 4, 3));
    }

    #[test]
    fn json_round_trip() {
        let c = CpuId::from_x86("AuthenticAMD", 0x00b0_0f21, Some("0xb404023".into()));
        assert_eq!(CpuId::from_json(&c.to_json()), Some(c));
        let a = CpuId { vendor: "Apple".into(), family: 0x1234, model: 5, stepping: 0, microcode: None, signature: None };
        assert_eq!(CpuId::from_json(&a.to_json()), Some(a));
    }

    #[test]
    fn emulators_are_detected_from_hypervisor_and_maps() {
        assert_eq!(emulator_from_hypervisor("TCGTCGTCGTCG"), Some("qemu-tcg"));
        assert_eq!(emulator_from_hypervisor("KVMKVMKVM\0\0\0"), None);
        assert_eq!(emulator_from_hypervisor("Microsoft Hv"), None);
        let native = "55d0c0000000-55d0c0001000 r--p 00000000 fd:01 123 /usr/bin/sandblaster-targets-evidence\n\
                      7f0000000000-7f0000100000 r-xp 00000000 fd:01 456 /usr/lib/x86_64-linux-gnu/libc.so.6\n\
                      7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]\n";
        assert_eq!(emulator_in_maps(native), None);
        let with = |path: &str| format!("{native}7f1000000000-7f1000100000 r-xp 00000000 fd:01 789 {path}\n");
        assert_eq!(emulator_in_maps(&with("/opt/sde-external-9.44.0-2024-08-22-lin/intel64/pinbin")), Some("sde"));
        assert_eq!(emulator_in_maps(&with("/opt/sde/intel64/libpindwarf.so")), Some("sde"));
        assert_eq!(emulator_in_maps(&with("/opt/sde/intel64/libpin3dwarf.so")), Some("sde"));
        assert_eq!(emulator_in_maps(&with("/opt/tools/intel64/sde-mix-mt.so")), Some("sde"));
        assert_eq!(emulator_in_maps(&with("/usr/libexec/valgrind/vgpreload_core-amd64-linux.so")), Some("valgrind"));
        assert_eq!(emulator_in_maps(&with("/opt/dr/lib64/release/libdynamorio.so")), Some("dynamorio"));
        // A path with spaces, and names that only look similar, are not emulators.
        assert_eq!(emulator_in_maps(&with("/home/a user/lib/libpinyin.so")), None);
        assert_eq!(emulator_in_maps(&with("/home/a user/lib/libspin.so")), None);
        assert_eq!(emulator_in_maps(&with("/home/u/opinbin")), None);
    }

    #[test]
    fn cpuinfo_parsing() {
        let info = "processor\t: 0\nvendor_id\t: GenuineIntel\nmicrocode\t: 0x2b000603\nCPU part\t: 0xd0c\n";
        assert_eq!(cpuinfo_field(info, "microcode").as_deref(), Some("0x2b000603"));
        assert_eq!(cpuinfo_field(info, "CPU part").and_then(|v| parse_num(&v)), Some(0xd0c));
        assert_eq!(parse_num("12"), Some(12));
    }
}
