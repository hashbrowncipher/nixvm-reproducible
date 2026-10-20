use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt::Write;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    cpuid: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    leaf: u32,
    subleaf: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

fn main() {
    println!("cargo:rerun-if-changed=cpuid.toml");
    let source = std::fs::read_to_string("cpuid.toml").expect("read cpuid.toml");
    let mut profile: Profile = toml::from_str(&source).expect("parse cpuid.toml");
    let mut seen = BTreeSet::new();
    for entry in &profile.cpuid {
        assert!(
            seen.insert((entry.leaf, entry.subleaf)),
            "duplicate CPUID entry {:#x}/{:#x}",
            entry.leaf,
            entry.subleaf
        );
    }
    profile
        .cpuid
        .sort_by_key(|entry| (entry.leaf, entry.subleaf));
    let mut output = String::from("pub(crate) const ENTRIES: &[Entry] = &[\n");
    for entry in profile.cpuid {
        writeln!(
            output,
            "    Entry {{ leaf: {:#x}, subleaf: {:#x}, eax: {:#x}, ebx: {:#x}, ecx: {:#x}, edx: {:#x} }},",
            entry.leaf, entry.subleaf, entry.eax, entry.ebx, entry.ecx, entry.edx
        )
        .expect("write generated CPUID entry");
    }
    output.push_str("];");
    let destination = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(destination.join("cpuid.rs"), output).expect("write generated CPUID table");
}
