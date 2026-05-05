// Copyright (c) 2026 Maruf Zaber
// SPDX-License-Identifier: MIT
//
// =============================================================================
//  hyp.cpp — Minimal educational hypervisor for Apple Silicon
// =============================================================================
//
//  WHAT THIS PROGRAM DOES
//  ----------------------
//  The smallest hypervisor that does something observable. It:
//
//    1. asks macOS to set up a virtual machine,
//    2. allocates one 16 KiB page of "guest RAM",
//    3. writes three ARM64 instructions into that page,
//    4. starts a virtual CPU with its program counter at instruction 0,
//    5. waits for the guest to trap back to us,
//    6. reads a guest CPU register to prove the guest actually ran.
//
//  The guest program is:
//
//      mov  x0, #42       ; load 42 into general-purpose register X0
//      add  x0, x0, #1    ; X0 = 43
//      hvc  #0            ; "hypercall" — synchronous trap to the host
//
//  When the host catches the trap, it reads X0 and prints "43". That is the
//  minimum loop a real hypervisor runs millions of times per second, just
//  with far more sophisticated guests, memory layouts, and exit handlers.
//
//  BACKGROUND: WHAT IS A HYPERVISOR?
//  ---------------------------------
//  A hypervisor is software that creates and runs virtual machines. On modern
//  hardware it relies on CPU "virtualization extensions" — special privilege
//  levels designed expressly so guest software can run at near-native speed
//  without being able to interfere with the host.
//
//  Apple Silicon (ARMv8.5+) implements these as four "Exception Levels":
//
//    EL0  — userspace processes
//    EL1  — kernel
//    EL2  — hypervisor
//    EL3  — secure monitor (firmware; we don't touch it)
//
//  macOS itself runs at EL2 and exposes a thin C API called
//  Hypervisor.framework (HVF). When we call hv_vcpu_run() below, macOS
//  programs the EL2 control registers, drops the CPU into EL1, and lets it
//  execute the guest code natively until something causes a "VM exit" — a
//  trap back into EL2, where macOS in turn returns control to us.
//
//  This style of design — a host OS running normal apps alongside a thin
//  virtualization layer it exposes to userspace — is called a "Type-2"
//  hypervisor (KVM on Linux, HVF on macOS, WHPX on Windows). Type-1
//  hypervisors (Xen, ESXi) instead boot directly on the hardware with no
//  host OS underneath.
//
//  PREREQUISITES
//  -------------
//    * Apple Silicon Mac (M1 or later). Intel Macs use a different HVF API.
//    * Xcode Command Line Tools: `xcode-select --install`.
//    * Codesigning with the entitlement com.apple.security.hypervisor.
//      Without it hv_vm_create returns HV_DENIED. The Makefile handles this.
// =============================================================================

#include <Hypervisor/Hypervisor.h>   // hv_vm_*, hv_vcpu_*, HV_REG_*
#include <sys/mman.h>                // mmap, munmap
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// CHECK aborts the program if a Hypervisor.framework call fails. Real
// hypervisors handle errors more gracefully, but for an educational example
// "die loudly with the failed call shown" is the right call.
#define CHECK(call) do {                                              \
    hv_return_t _r = (call);                                          \
    if (_r != HV_SUCCESS) {                                           \
        std::fprintf(stderr, #call " failed: 0x%x\n", _r);            \
        std::exit(1);                                                 \
    }                                                                 \
} while (0)

int main() {
    // -------------------------------------------------------------------------
    //  STEP 1 / Create the VM.
    //
    //  Hypervisor.framework allows ONE VM per process. hv_vm_create asks
    //  macOS to allocate the per-VM control structures (stage-2 page tables,
    //  vCPU slots, etc.) and to enable EL2 virtualization for this process.
    //  From here on, the process is a hypervisor.
    // -------------------------------------------------------------------------
    CHECK(hv_vm_create(nullptr));

    // -------------------------------------------------------------------------
    //  STEP 2 / Allocate one host page that will back the guest's RAM.
    //
    //  A guest VM has its own "guest physical address space" — it thinks it
    //  has bare hardware. Each guest physical page must be backed by a real
    //  page of host memory; the hypervisor's stage-2 page tables translate
    //  between them on every guest memory access.
    //
    //  We use mmap (rather than malloc) for two reasons:
    //    * mmap returns page-aligned memory, which hv_vm_map requires.
    //    * mmap lets us allocate exactly one page with no allocator overhead.
    //
    //  16 KiB is the page size on Apple Silicon (Intel Macs use 4 KiB).
    // -------------------------------------------------------------------------
    constexpr size_t   kPageSize = 0x4000;          // 16 KiB
    constexpr uint64_t kGuestPA  = 0x0;             // guest physical base
    void* host_mem = mmap(nullptr, kPageSize,
                          PROT_READ | PROT_WRITE,
                          MAP_ANON | MAP_PRIVATE, -1, 0);
    if (host_mem == MAP_FAILED) { std::perror("mmap"); return 1; }

    // -------------------------------------------------------------------------
    //  STEP 3 / Write the guest program into guest RAM.
    //
    //  ARM64 instructions are fixed-width 32-bit values stored little-endian.
    //  We hand-encode three instructions here. In a real hypervisor you would
    //  load a kernel image (Linux Image, FreeBSD kernel, etc.) instead.
    //
    //  Instruction 1: movz x0, #42
    //    "movz" loads an immediate into a register, zero-extending. The
    //    encoding for "movz <Xd>, #imm16" packs sf=1 (64-bit), hw=00 (low
    //    16 bits), imm16=0x2a (=42), Rd=0 to give 0xd2800540. You don't
    //    need to memorize this — `clang -c` will generate it for you. We
    //    hardcode it so this file has zero build-time dependencies.
    //
    //  Instruction 2: add x0, x0, #1
    //    "add immediate" with sf=1, sh=0, imm12=1, Rn=0, Rd=0  =  0x91000400.
    //
    //  Instruction 3: hvc #0
    //    "hypervisor call" with imm16=0  =  0xd4000002. This is the magic
    //    instruction that takes us back to the host.
    // -------------------------------------------------------------------------
    const uint32_t guest_code[] = {
        0xd2800540,   // movz x0, #42
        0x91000400,   // add  x0, x0, #1
        0xd4000002,   // hvc  #0
    };
    std::memcpy(host_mem, guest_code, sizeof(guest_code));

    // -------------------------------------------------------------------------
    //  STEP 4 / Map the host page into the guest's physical address space.
    //
    //  hv_vm_map installs a stage-2 page table entry: from now on, when the
    //  guest accesses guest physical address kGuestPA (=0), the CPU walks
    //  the stage-2 tables and lands in our `host_mem` page.
    //
    //  We mark the mapping RWX. A real hypervisor would map kernel code as
    //  RX, device-tree blobs as R, RAM as RW, etc., so that bugs in the
    //  guest can't, for example, modify its own kernel text.
    // -------------------------------------------------------------------------
    CHECK(hv_vm_map(host_mem, kGuestPA, kPageSize,
                    HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC));

    // -------------------------------------------------------------------------
    //  STEP 5 / Create a virtual CPU.
    //
    //  A vCPU is the runtime object that represents "one CPU executing
    //  inside the guest". hv_vcpu_create gives us back a handle and a
    //  pointer to a hv_vcpu_exit_t — the struct macOS fills in every time
    //  the guest exits.
    // -------------------------------------------------------------------------
    hv_vcpu_t        vcpu;
    hv_vcpu_exit_t*  exit_info = nullptr;
    CHECK(hv_vcpu_create(&vcpu, &exit_info, nullptr));

    // -------------------------------------------------------------------------
    //  STEP 6 / Initialize vCPU registers.
    //
    //  At minimum we must set:
    //    * PC — where the CPU should start executing (= our entry point).
    //    * PSTATE/CPSR — the processor state word: privilege mode,
    //      interrupt masks, condition flags, etc.
    //
    //  The PSTATE value 0x3c4 decodes as:
    //
    //    bit  field   value  meaning
    //    ---  -----   -----  ------------------------------------------------
    //    9    D       1      Debug exceptions masked
    //    8    A       1      SError (asynchronous abort) masked
    //    7    I       1      IRQ masked
    //    6    F       1      FIQ masked
    //    3-0  M[3:0]  0100   EL1t — run at EL1 using stack pointer SP_EL0
    //
    //  In other words: "start the CPU in kernel mode (EL1) with all
    //  asynchronous interrupts disabled". This is the canonical boot-time
    //  PSTATE for ARM64 kernels — Linux's head.S sets the same bits before
    //  jumping to start_kernel.
    //
    //  We don't bother setting SP because our three-instruction guest never
    //  uses the stack.
    // -------------------------------------------------------------------------
    CHECK(hv_vcpu_set_reg(vcpu, HV_REG_PC,   kGuestPA));
    CHECK(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c4));

    // -------------------------------------------------------------------------
    //  STEP 7 / The run loop.
    //
    //  hv_vcpu_run() is the heart of any hypervisor. It hands the physical
    //  CPU to the guest, which executes natively until something — an
    //  instruction it can't run unprivileged, an MMIO access, an interrupt,
    //  a hypercall — forces a "VM exit" back to the host.
    //
    //  On exit, exit_info->reason tells us why. A real hypervisor's main
    //  loop is essentially a big switch on this value: emulate I/O on MMIO
    //  exits, inject interrupts on timer exits, deliver hypercalls on HVC
    //  exits, and re-enter the guest. We handle only one exit type — HVC —
    //  and stop.
    // -------------------------------------------------------------------------
    for (;;) {
        CHECK(hv_vcpu_run(vcpu));

        if (exit_info->reason == HV_EXIT_REASON_EXCEPTION) {
            // The "syndrome" is the value of ESR_EL2, the ARM register that
            // tells the hypervisor what kind of exception happened. Its
            // top 6 bits (the "Exception Class", EC) are the primary
            // classifier.
            uint64_t esr = exit_info->exception.syndrome;
            uint32_t ec  = (esr >> 26) & 0x3f;

            // EC = 0x16 means "HVC instruction executed in AArch64 state".
            // (See ARM ARM, table "ESR_ELx Encoding".) That's our exit
            // signal.
            if (ec == 0x16) {
                uint64_t x0 = 0;
                CHECK(hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0));
                std::printf("guest exited via HVC, x0 = %llu\n",
                            (unsigned long long)x0);
                break;
            }
            std::fprintf(stderr,
                         "unexpected exception, EC=0x%x ESR=0x%llx\n",
                         ec, (unsigned long long)esr);
            return 1;
        }

        std::fprintf(stderr, "unexpected exit reason: %u\n",
                     (unsigned)exit_info->reason);
        return 1;
    }

    // -------------------------------------------------------------------------
    //  STEP 8 / Tear down. Order matters: vCPU before VM, then unmap guest
    //  memory, then destroy the VM, then release the host page.
    // -------------------------------------------------------------------------
    CHECK(hv_vcpu_destroy(vcpu));
    CHECK(hv_vm_unmap(kGuestPA, kPageSize));
    CHECK(hv_vm_destroy());
    munmap(host_mem, kPageSize);
    return 0;
}
