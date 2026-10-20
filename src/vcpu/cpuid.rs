//! The virtual x86 CPU's public identity, shared by hardware and software execution.
//!
//! Build-time TOML parsing keeps guest CPUID independent of host files and avoids
//! adding a parser to the guest execution path or the WebAssembly binary.

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Entry {
    pub leaf: u32,
    pub subleaf: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

include!(concat!(env!("OUT_DIR"), "/cpuid.rs"));

/// Whether ECX selects a subleaf. Other leaves ignore the input ECX register.
pub(crate) const fn indexed(leaf: u32) -> bool {
    matches!(leaf, 4 | 7 | 0xb | 0xd | 0x12 | 0x14 | 0x17 | 0x18 | 0x1f)
}

pub(crate) const fn query(leaf: u32, subleaf: u32) -> Entry {
    let subleaf = if indexed(leaf) { subleaf } else { 0 };
    let mut index = 0;
    while index < ENTRIES.len() {
        let entry = ENTRIES[index];
        if entry.leaf == leaf && entry.subleaf == subleaf {
            return entry;
        }
        index += 1;
    }
    Entry {
        leaf,
        subleaf,
        eax: 0,
        ebx: 0,
        // Intel topology termination echoes the queried level number in ECX.
        // KVM applies this architectural rule to unlisted leaf-0xB subleaves.
        ecx: if leaf == 0xb { subleaf & 0xff } else { 0 },
        edx: 0,
    }
}

/// Linux names for the advertised feature bits used by `/proc/cpuinfo`.
pub(crate) fn flag_string() -> String {
    let basic = query(1, 0);
    let structured = query(7, 0);
    let extended = query(0x8000_0001, 0);
    let words: &[(u32, &[(u32, &str)])] = &[
        (
            basic.edx,
            &[
                (0, "fpu"),
                (2, "de"),
                (3, "pse"),
                (4, "tsc"),
                (5, "msr"),
                (6, "pae"),
                (7, "mce"),
                (8, "cx8"),
                (9, "apic"),
                (11, "sep"),
                (12, "mtrr"),
                (13, "pge"),
                (14, "mca"),
                (15, "cmov"),
                (16, "pat"),
                (17, "pse36"),
                (19, "clflush"),
                (23, "mmx"),
                (24, "fxsr"),
                (25, "sse"),
                (26, "sse2"),
            ],
        ),
        (
            basic.ecx,
            &[
                (0, "pni"),
                (1, "pclmulqdq"),
                (9, "ssse3"),
                (12, "fma"),
                (13, "cx16"),
                (19, "sse4_1"),
                (20, "sse4_2"),
                (22, "movbe"),
                (23, "popcnt"),
                (25, "aes"),
                (26, "xsave"),
                (27, "osxsave"),
                (28, "avx"),
                (29, "f16c"),
                (30, "rdrand"),
                (31, "hypervisor"),
            ],
        ),
        (
            structured.ebx,
            &[
                (3, "bmi1"),
                (5, "avx2"),
                (7, "smep"),
                (8, "bmi2"),
                (9, "erms"),
                (18, "rdseed"),
                (19, "adx"),
                (20, "smap"),
                (23, "clflushopt"),
                (24, "clwb"),
                (29, "sha_ni"),
            ],
        ),
        (
            structured.ecx,
            &[(8, "gfni"), (9, "vaes"), (10, "vpclmulqdq"), (22, "rdpid")],
        ),
        (structured.edx, &[(29, "arch_capabilities")]),
        (
            extended.edx,
            &[
                (11, "syscall"),
                (20, "nx"),
                (26, "pdpe1gb"),
                (27, "rdtscp"),
                (29, "lm"),
            ],
        ),
        (
            extended.ecx,
            &[(0, "lahf_lm"), (5, "abm"), (8, "3dnowprefetch")],
        ),
    ];
    words
        .iter()
        .flat_map(|(word, names)| {
            names
                .iter()
                .filter_map(move |(bit, name)| (word & (1 << bit) != 0).then_some(*name))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn vendor_id() -> String {
    let entry = query(0, 0);
    let bytes: Vec<_> = [entry.ebx, entry.edx, entry.ecx]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub(crate) fn brand_string() -> String {
    let bytes: Vec<_> = (0x8000_0002..=0x8000_0004)
        .flat_map(|leaf| {
            let entry = query(leaf, 0);
            [entry.eax, entry.ebx, entry.ecx, entry.edx]
        })
        .flat_map(u32::to_le_bytes)
        .take_while(|byte| *byte != 0)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::query;

    #[test]
    fn identity_and_unknown_queries_are_host_independent() {
        let identity = query(0, 0);
        let mut vendor = Vec::new();
        for value in [identity.ebx, identity.edx, identity.ecx] {
            vendor.extend_from_slice(&value.to_le_bytes());
        }
        assert_eq!(vendor, b"GenuineIntel");
        assert_eq!(query(1, 0).eax, 0x0005_06e3);
        let mut brand = Vec::new();
        for leaf in 0x8000_0002..=0x8000_0004 {
            let entry = query(leaf, 0);
            for value in [entry.eax, entry.ebx, entry.ecx, entry.edx] {
                brand.extend_from_slice(&value.to_le_bytes());
            }
        }
        assert_eq!(&brand[..28], b"Deterministic Virtual CPU v1");
        for (leaf, subleaf) in [(3, 0), (7, 1), (0xd, 63), (0x1234_5678, 0)] {
            let entry = query(leaf, subleaf);
            assert_eq!((entry.eax, entry.ebx, entry.ecx, entry.edx), (0, 0, 0, 0));
        }
        assert_eq!(query(1, u32::MAX), query(1, 0));
    }

    #[test]
    fn avx_profile_describes_only_x87_sse_and_ymm_state() {
        let ecx = query(1, 0).ecx;
        assert_eq!(ecx & (7 << 26), 7 << 26); // XSAVE, OSXSAVE, AVX.
        assert_eq!(ecx & (1 << 30), 0); // RDRAND.
        let features = query(7, 0);
        assert_ne!(features.ebx & (1 << 5), 0); // AVX2.
        assert_eq!(features.ebx & ((1 << 16) | (1 << 18)), 0); // AVX512F, RDSEED.
        let xsave = query(0xd, 0);
        assert_eq!(
            (xsave.eax, xsave.ebx, xsave.ecx, xsave.edx),
            (7, 832, 832, 0)
        );
        let ymm = query(0xd, 2);
        assert_eq!((ymm.eax, ymm.ebx, ymm.ecx, ymm.edx), (256, 576, 0, 0));
    }

    /// The Ice Lake-SP floor's extensions, as (leaf, register index EAX..EDX, bit).
    const ICE_LAKE_FEATURES: [(&str, u32, usize, u32); 14] = [
        ("pclmulqdq", 1, 2, 1),
        ("fma", 1, 2, 12),
        ("aes", 1, 2, 25),
        ("f16c", 1, 2, 29),
        ("adx", 7, 1, 19),
        ("clflushopt", 7, 1, 23),
        ("clwb", 7, 1, 24),
        ("sha_ni", 7, 1, 29),
        ("gfni", 7, 2, 8),
        ("vaes", 7, 2, 9),
        ("vpclmulqdq", 7, 2, 10),
        ("rdpid", 7, 2, 22),
        ("abm", 0x8000_0001, 2, 5),
        ("3dnowprefetch", 0x8000_0001, 2, 8),
    ];

    #[test]
    fn profile_advertises_the_ice_lake_floor_and_keeps_excluded_features_off() {
        for (name, leaf, register, bit) in ICE_LAKE_FEATURES {
            let entry = query(leaf, 0);
            let word = [entry.eax, entry.ebx, entry.ecx, entry.edx][register];
            assert_ne!(word & (1 << bit), 0, "{name}");
        }
        // RDRAND, x2APIC and TSC-Deadline.
        assert_eq!(query(1, 0).ecx & ((1 << 30) | (1 << 21) | (1 << 24)), 0);
        let structured = query(7, 0);
        // FSGSBASE, HLE, RTM, RDSEED and every AVX-512 bit.
        let excluded = (1 << 0) | (1 << 4) | (1 << 11) | (1 << 18);
        let avx512 = (1 << 16) | (1 << 17) | (1 << 21) | (7 << 26) | (3 << 30);
        assert_eq!(structured.ebx & (excluded | avx512), 0);
        // PKU, OSPKE and the AVX-512 VBMI/VBMI2/VNNI/BITALG/VPOPCNTDQ extensions.
        let excluded = (1 << 1) | (1 << 3) | (1 << 4) | (1 << 6) | (3 << 11) | (1 << 14);
        assert_eq!(structured.ecx & excluded, 0);
        let xsave = query(0xd, 1); // XSAVEOPT, XSAVEC, XGETBV1, XSAVES.
        assert_eq!((xsave.eax, xsave.ebx, xsave.ecx, xsave.edx), (0, 0, 0, 0));
    }

    #[test]
    fn cpuinfo_flags_include_vectors_and_exclude_hidden_host_features() {
        let flags = super::flag_string();
        let flags: Vec<_> = flags.split_whitespace().collect();
        for name in ["xsave", "osxsave", "avx", "avx2", "bmi1", "bmi2", "rdtscp"] {
            assert!(flags.contains(&name), "missing {name}");
        }
        for (name, ..) in ICE_LAKE_FEATURES {
            assert!(flags.contains(&name), "missing {name}");
        }
        for name in ["rdrand", "rdseed", "x2apic"] {
            assert!(!flags.contains(&name), "unexpected {name}");
        }
    }
}
