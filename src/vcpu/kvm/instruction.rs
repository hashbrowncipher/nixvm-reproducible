//! Fetch a faulting CPL3 instruction through its address space, a byte at a time.

use crate::vcpu::pagetable::{AddrSpace, is_canonical};
use crate::vcpu::phys::PhysMem;
use crate::vcpu::{Exit, Prot};
use iced_x86::{Decoder, DecoderError, DecoderOptions, Instruction};

pub(super) fn decode(cr3: u64, phys: &PhysMem, pc: u64) -> Result<Instruction, Exit> {
    let mut bytes = [0; 15];
    for len in 1..=bytes.len() {
        let addr = pc.wrapping_add(len as u64 - 1);
        if !is_canonical(addr) {
            return Err(Exit::ProtectionFault { pc });
        }
        let translation = AddrSpace::translate_cr3(cr3, addr, phys)
            .filter(|t| !t.supervisor && t.prot.contains(Prot::EXEC))
            .ok_or(Exit::MemFault { addr, write: false })?;
        phys.read(translation.paddr, &mut bytes[len - 1..len]);
        let mut decoder = Decoder::with_ip(64, &bytes[..len], pc, DecoderOptions::NONE);
        let instruction = decoder.decode();
        // Stop as soon as decoding finishes, including an invalid encoding.
        // A short instruction at the end of a page must not fetch the next page.
        if decoder.last_error() != DecoderError::NoMoreBytes || len == bytes.len() {
            return Ok(instruction);
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vcpu::GuestMemory;
    use crate::vcpu::mem::PAGE_SIZE;

    #[test]
    fn instruction_fetch_requires_an_executable_user_page() {
        let base = 0x1_0000;
        let mut mem = GuestMemory::new(base, 64 * 1024);
        mem.map(base, PAGE_SIZE, Prot::rw()).unwrap();
        mem.write_init(base, &[0x0f, 0x31]).unwrap();
        let phys = mem.phys_arc();
        for pc in [base, crate::vcpu::ctrl::LSTAR_VA, base + PAGE_SIZE] {
            assert!(
                matches!(decode(mem.cr3(), &phys, pc), Err(Exit::MemFault { addr, write: false }) if addr == pc)
            );
        }
        assert!(
            matches!(decode(mem.cr3(), &phys, 1 << 48), Err(Exit::ProtectionFault { pc }) if pc == 1 << 48)
        );
    }

    #[test]
    fn missing_instruction_tail_faults_at_the_missing_byte() {
        let base = 0x1_0000;
        let mut mem = GuestMemory::new(base, 64 * 1024);
        mem.map(base, PAGE_SIZE, Prot::rx()).unwrap();
        let pc = base + PAGE_SIZE - 1;
        mem.write_init(pc, &[0x0f]).unwrap();
        assert!(
            matches!(decode(mem.cr3(), &mem.phys_arc(), pc), Err(Exit::MemFault { addr, write: false }) if addr == base + PAGE_SIZE)
        );
    }
}
