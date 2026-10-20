//! Buffered seeded byte streams for host and sandbox randomness.

use std::sync::{Arc, Mutex};

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{Rng, SeedableRng};

/// A leaf lock: filling or reseeding never acquires a kernel or filesystem lock.
#[derive(Clone)]
pub(crate) struct RandomSource(Arc<Mutex<RandomState>>);

pub(crate) struct RandomState {
    generator: ChaCha20Rng,
    // rand_chacha consumes whole words. Keep unused bytes so read boundaries
    // cannot skip bytes in the sandbox's stream.
    pending: [u8; 64],
    used: usize,
}

impl std::fmt::Debug for RandomSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RandomSource").finish_non_exhaustive()
    }
}

impl RandomState {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self {
            generator: ChaCha20Rng::from_seed(seed),
            pending: [0; 64],
            used: 64,
        }
    }

    pub(crate) fn fill(&mut self, mut output: &mut [u8]) {
        while !output.is_empty() {
            if self.used == self.pending.len() {
                self.generator.fill_bytes(&mut self.pending);
                self.used = 0;
            }
            let count = output.len().min(self.pending.len() - self.used);
            output[..count].copy_from_slice(&self.pending[self.used..self.used + count]);
            self.used += count;
            output = &mut output[count..];
        }
    }
}

impl RandomSource {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self(Arc::new(Mutex::new(RandomState::new(seed))))
    }

    pub(crate) fn fill(&self, output: &mut [u8]) {
        self.0.lock().unwrap().fill(output);
    }

    /// Consume 32 bytes, XOR the child's little-endian PID into the first four,
    /// and restart ChaCha20 from that seed. Buffered bytes belong to the old
    /// stream and are discarded. The initial seed and clone history alone
    /// determine the result; the PID supplies no host entropy.
    pub(crate) fn reseed_for_clone(&self, pid: i32) {
        let mut state = self.0.lock().unwrap();
        let mut seed = [0; 32];
        state.fill(&mut seed);
        for (byte, pid_byte) in seed.iter_mut().zip(pid.to_le_bytes()) {
            *byte ^= pid_byte;
        }
        *state = RandomState::new(seed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ChaCha20's published all-zero key/nonce, counter-zero block.
    const ZERO_BLOCK: [u8; 64] = [
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd,
        0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77,
        0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8,
        0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69,
        0xb2, 0xee, 0x65, 0x86,
    ];

    #[test]
    fn known_chacha20_bytes() {
        let source = RandomSource::new([0; 32]);
        let mut output = [0; 64];
        source.fill(&mut output);
        assert_eq!(output, ZERO_BLOCK);
    }

    #[test]
    fn arbitrary_read_boundaries_preserve_bytes() {
        let mut expected = [0; 1027];
        ChaCha20Rng::from_seed([42; 32]).fill_bytes(&mut expected);
        for width in [1, 3, 4, 7, 63, 64, 65, 255, 256, 257] {
            let source = RandomSource::new([42; 32]);
            let mut actual = [0; 1027];
            for chunk in actual.chunks_mut(width) {
                source.fill(&mut []);
                source.clone().fill(chunk);
            }
            assert_eq!(actual, expected, "read width {width}");
        }
    }

    #[test]
    fn clone_reseed_uses_stream_bytes_and_pid() {
        for pid in [2i32, 3, 0x1234_5678] {
            let source = RandomSource::new([0; 32]);
            source.reseed_for_clone(pid);
            let mut expected_seed = [0; 32];
            expected_seed.copy_from_slice(&ZERO_BLOCK[..32]);
            for (byte, pid_byte) in expected_seed.iter_mut().zip(pid.to_le_bytes()) {
                *byte ^= pid_byte;
            }
            let mut expected = [0; 128];
            ChaCha20Rng::from_seed(expected_seed).fill_bytes(&mut expected);
            let mut actual = [0; 128];
            source.fill(&mut actual);
            assert_eq!(actual, expected);
        }
    }
}
