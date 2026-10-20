.intel_syntax noprefix
.text
# Feature probes for tests/cpuid.rs. Each case reads inputs at [rbx+0x00..0x40] and
# writes outputs at [rbx+0x40..0x60]. An "f_" label marks the feature's first instruction.
# The test replaces each RET with SYSCALL.
.macro CASE name
.globl \name
\name:
.endm

CASE aes
  movdqu xmm0, [rbx]
f_aes: aesenc xmm0, [rbx+16]
  movdqu [rbx+0x40], xmm0
  ret

CASE pclmul
  movdqu xmm0, [rbx]
f_pclmul: pclmulqdq xmm0, [rbx+16], 0x01
  movdqu [rbx+0x40], xmm0
  ret

CASE fma
  vmovsd xmm0, [rbx]
  vmovsd xmm1, [rbx+8]
f_fma: vfmadd213sd xmm0, xmm1, [rbx+16]
  vmovsd [rbx+0x40], xmm0
  ret

CASE f16c
f_f16c: vcvtph2ps xmm0, [rbx]
  vmovdqu [rbx+0x40], xmm0
  ret

CASE lzcnt
f_lzcnt: lzcnt rax, [rbx]
  mov [rbx+0x40], rax
  setc byte ptr [rbx+0x48]
  lzcnt rax, [rbx+8]
  mov [rbx+0x50], rax
  setc byte ptr [rbx+0x58]
  ret

CASE adx
  xor eax, eax
  mov rax, [rbx]
  mov rdx, rax
f_adx: adcx rax, [rbx+8]
  setc byte ptr [rbx+0x50]
  seto byte ptr [rbx+0x51]
  adox rdx, [rbx+8]
  setc byte ptr [rbx+0x52]
  seto byte ptr [rbx+0x53]
  adcx rax, [rbx+16]
  setc byte ptr [rbx+0x54]
  seto byte ptr [rbx+0x55]
  adox rdx, [rbx+16]
  setc byte ptr [rbx+0x56]
  seto byte ptr [rbx+0x57]
  mov [rbx+0x40], rax
  mov [rbx+0x48], rdx
  ret

CASE prefetchw
f_prefetchw: prefetchw [rbx]
  mov dword ptr [rbx+0x40], 0x600d
  ret

CASE clflushopt
f_clflushopt: clflushopt [rbx]
  mov dword ptr [rbx+0x40], 0x600d
  ret

CASE clwb
f_clwb: clwb [rbx]
  mov dword ptr [rbx+0x40], 0x600d
  ret

CASE sha
  movdqu xmm1, [rbx]
  movdqu xmm2, [rbx+16]
  movdqu xmm0, [rbx+32]
f_sha: sha256rnds2 xmm1, xmm2
  movdqu [rbx+0x40], xmm1
  ret

CASE gfni
  movdqu xmm0, [rbx]
f_gfni: gf2p8mulb xmm0, [rbx+16]
  movdqu [rbx+0x40], xmm0
  ret

CASE vaes
  vmovdqu ymm0, [rbx]
f_vaes: vaesenc ymm0, ymm0, [rbx+32]
  vmovdqu [rbx+0x40], ymm0
  ret

CASE vpclmul
  vmovdqu ymm0, [rbx]
f_vpclmul: vpclmulqdq ymm0, ymm0, [rbx+32], 0x10
  vmovdqu [rbx+0x40], ymm0
  ret

CASE rdpid
  mov rax, -1
f_rdpid: rdpid rax
  mov [rbx+0x40], rax
  ret
