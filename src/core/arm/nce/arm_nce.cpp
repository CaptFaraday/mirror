// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

// SPDX-FileCopyrightText: Copyright 2023 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cinttypes>
#include <memory>

#include "common/signal_chain.h"
#include "core/arm/nce/arm_nce.h"
#include "core/arm/nce/interpreter_visitor.h"
#include "core/arm/nce/patcher.h"
#include "core/core.h"
#include "core/memory.h"

#include "core/hle/kernel/k_process.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <android/log.h>
#endif

namespace Core {

namespace {

struct sigaction g_orig_bus_action;
struct sigaction g_orig_segv_action;

// -----------------------------------------------------------------------------
// Temporary diagnostic instrumentation. Not intended for upstream merge.
//
// Tracks down a reproducible SIGILL / ILL_ILLOPC raised on a CPUCore thread from
// inside the guest memory arena, reached via an indirect branch (x16 == pc).
// NCE installs handlers for SIGBUS and SIGSEGV but none for SIGILL, so the
// process dies with no emulator-side context at all.
//
// This handler records the faulting registers, the /proc/self/maps entries
// around pc, and the bytes at pc, then restores the default action so the usual
// tombstone is still produced. Reading our own maps needs no root.
//
// All-zero bytes at pc mean the page is mapped but unpopulated (torn down or
// never filled). Real instructions mean the page was simply never patched.
// -----------------------------------------------------------------------------
struct sigaction g_orig_ill_action;

// Static so the handler needs no allocator and very little stack.
char g_diag_maps[512 * 1024];

void DiagLog(const char* msg) {
#ifdef __ANDROID__
    __android_log_write(ANDROID_LOG_ERROR, "EDENDIAG", msg);
#else
    size_t len = 0;
    while (msg[len] != '\0') {
        ++len;
    }
    (void)::write(2, msg, len);
    (void)::write(2, "\n", 1);
#endif
}

char* DiagStr(char* out, const char* s) {
    while (*s != '\0') {
        *out++ = *s++;
    }
    return out;
}

char* DiagHex(char* out, u64 value, int digits) {
    static constexpr char kHex[] = "0123456789abcdef";
    for (int i = digits - 1; i >= 0; --i) {
        out[i] = kHex[value & 0xF];
        value >>= 4;
    }
    return out + digits;
}

u64 DiagHexVal(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<u64>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<u64>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<u64>(c - 'A' + 10);
    }
    return 0;
}

// Emits one (non null-terminated) maps line with a prefix.
void DiagLogLine(const char* prefix, const char* begin, const char* end) {
    char buf[320];
    char* out = DiagStr(buf, prefix);
    const char* limit = buf + sizeof(buf) - 1;
    while (begin < end && out < limit) {
        *out++ = *begin++;
    }
    *out = '\0';
    DiagLog(buf);
}

// Load-time-captured layout info (written from KProcess::LoadModule, normal context).
Core::ArmNce::DiagRegionInfo g_diag_regions{};
bool g_diag_regions_valid = false;

struct DiagModule {
    u64 base;
    u64 size;
};
DiagModule g_diag_modules[16];
size_t g_diag_module_count = 0;

// Readable-range index parsed from /proc/self/maps at fault time.
struct DiagRange {
    u64 start;
    u64 end;
};
DiagRange g_diag_ranges[8192];
size_t g_diag_range_count = 0;

void DiagBuildRangeIndex() {
    g_diag_range_count = 0;
    const int fd = ::open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        return;
    }
    size_t total = 0;
    while (total < sizeof(g_diag_maps) - 1) {
        const ssize_t n = ::read(fd, g_diag_maps + total, sizeof(g_diag_maps) - 1 - total);
        if (n <= 0) {
            break;
        }
        total += static_cast<size_t>(n);
    }
    ::close(fd);
    g_diag_maps[total] = '\0';

    const char* const buf_end = g_diag_maps + total;
    const char* line = g_diag_maps;
    while (line < buf_end && g_diag_range_count < 8192) {
        const char* eol = line;
        while (eol < buf_end && *eol != '\n') {
            ++eol;
        }
        u64 start = 0;
        u64 end = 0;
        const char* p = line;
        while (p < eol && *p != '-') {
            start = (start << 4) | DiagHexVal(*p);
            ++p;
        }
        if (p < eol) {
            ++p; // skip '-'
        }
        while (p < eol && *p != ' ') {
            end = (end << 4) | DiagHexVal(*p);
            ++p;
        }
        // Permissions sit immediately after the address range; keep readable ranges.
        if (p + 1 < eol && p[1] == 'r') {
            g_diag_ranges[g_diag_range_count++] = {start, end};
        }
        line = (eol < buf_end) ? eol + 1 : buf_end;
    }
}

bool DiagReadable(u64 addr, u64 len) {
    for (size_t i = 0; i < g_diag_range_count; ++i) {
        if (addr >= g_diag_ranges[i].start && addr + len <= g_diag_ranges[i].end) {
            return true;
        }
    }
    return false;
}

char* DiagResolveModule(char* out, u64 addr) {
    for (size_t i = 0; i < g_diag_module_count; ++i) {
        if (addr >= g_diag_modules[i].base &&
            addr < g_diag_modules[i].base + g_diag_modules[i].size) {
            out = DiagStr(out, " [mod");
            out = DiagHex(out, static_cast<u64>(i), 1);
            out = DiagStr(out, "+0x");
            out = DiagHex(out, addr - g_diag_modules[i].base, 8);
            out = DiagStr(out, "]");
            return out;
        }
    }
    return out;
}

// Raw dump of [sp, sp+0x400), 8 words per line, per-line readability check.
void DiagDumpStack(u64 sp) {
    for (int line_i = 0; line_i < 16; ++line_i) {
        const u64 base = sp + static_cast<u64>(line_i) * 64;
        char buf[320];
        char* out = DiagStr(buf, "stack +0x");
        out = DiagHex(out, static_cast<u64>(line_i) * 64, 3);
        out = DiagStr(out, ":");
        if (!DiagReadable(base, 64)) {
            out = DiagStr(out, " <unmapped>");
            *out = '\0';
            DiagLog(buf);
            continue;
        }
        const u64* words = reinterpret_cast<const u64*>(base);
        for (int i = 0; i < 8; ++i) {
            out = DiagStr(out, " ");
            out = DiagHex(out, words[i], 16);
        }
        *out = '\0';
        DiagLog(buf);
    }
}

// AArch64 frame record walk: [fp] = prev fp, [fp+8] = lr. Hard cap, monotonic, validated.
void DiagWalkFrames(u64 fp) {
    for (int i = 0; i < 40; ++i) {
        if (fp == 0 || (fp & 7) != 0 || !DiagReadable(fp, 16)) {
            char buf[96];
            char* out = DiagStr(buf, "frame walk stop: fp=0x");
            out = DiagHex(out, fp, 16);
            *out = '\0';
            DiagLog(buf);
            return;
        }
        const u64 next_fp = reinterpret_cast<const u64*>(fp)[0];
        const u64 lr = reinterpret_cast<const u64*>(fp)[1];
        char buf[192];
        char* out = DiagStr(buf, "frame ");
        out = DiagHex(out, static_cast<u64>(i), 2);
        out = DiagStr(out, ": fp=0x");
        out = DiagHex(out, fp, 16);
        out = DiagStr(out, " lr=0x");
        out = DiagHex(out, lr, 16);
        out = DiagResolveModule(out, lr);
        *out = '\0';
        DiagLog(buf);
        if (lr == 0 || next_fp <= fp) {
            return;
        }
        fp = next_fp;
    }
}

// Log region bounds, then every (YY << 32) | low32(x0) candidate that lands in a region.
// The code region (256 GiB) is only tested against registered modules to avoid 64 junk lines.
void DiagClassifyX0(u64 x0) {
    const u64 low = x0 & 0xFFFFFFFFULL;
    {
        char buf[128];
        char* out = DiagStr(buf, "arena=0x");
        out = DiagHex(out, g_diag_regions.arena_base, 16);
        out = DiagStr(out, " x0=0x");
        out = DiagHex(out, x0, 16);
        out = DiagStr(out, g_diag_regions_valid ? "" : " (regions not captured)");
        *out = '\0';
        DiagLog(buf);
    }
    if (!g_diag_regions_valid) {
        return;
    }
    struct RegionRef {
        const char* name;
        u64 start;
        u64 size;
    };
    const RegionRef regions[3] = {
        {"stack", g_diag_regions.stack_start, g_diag_regions.stack_size},
        {"alias", g_diag_regions.alias_start, g_diag_regions.alias_size},
        {"heap ", g_diag_regions.heap_start, g_diag_regions.heap_size},
    };
    for (const RegionRef& r : regions) {
        char buf[128];
        char* out = DiagStr(buf, "region ");
        out = DiagStr(out, r.name);
        out = DiagStr(out, " [0x");
        out = DiagHex(out, r.start, 16);
        out = DiagStr(out, ", 0x");
        out = DiagHex(out, r.start + r.size, 16);
        out = DiagStr(out, ")");
        *out = '\0';
        DiagLog(buf);
        for (u64 yy = r.start >> 32; yy <= (r.start + r.size - 1) >> 32; ++yy) {
            const u64 cand = (yy << 32) | low;
            if (cand >= r.start && cand < r.start + r.size) {
                char buf2[128];
                char* out2 = DiagStr(buf2, "  x0|hi -> 0x");
                out2 = DiagHex(out2, cand, 16);
                out2 = DiagStr(out2, " in ");
                out2 = DiagStr(out2, r.name);
                out2 = DiagStr(out2, " +0x");
                out2 = DiagHex(out2, cand - r.start, 10);
                *out2 = '\0';
                DiagLog(buf2);
            }
        }
    }
    {
        char buf[128];
        char* out = DiagStr(buf, "region code  [0x");
        out = DiagHex(out, g_diag_regions.code_start, 16);
        out = DiagStr(out, ", +0x");
        out = DiagHex(out, g_diag_regions.code_size, 12);
        out = DiagStr(out, ") - testing modules only");
        *out = '\0';
        DiagLog(buf);
    }
    for (size_t i = 0; i < g_diag_module_count; ++i) {
        const u64 mstart = g_diag_modules[i].base;
        const u64 mend = mstart + g_diag_modules[i].size;
        for (u64 yy = mstart >> 32; yy <= (mend - 1) >> 32; ++yy) {
            const u64 cand = (yy << 32) | low;
            if (cand >= mstart && cand < mend) {
                char buf2[128];
                char* out2 = DiagStr(buf2, "  x0|hi -> 0x");
                out2 = DiagHex(out2, cand, 16);
                out2 = DiagResolveModule(out2, cand);
                *out2 = '\0';
                DiagLog(buf2);
            }
        }
    }
}

// Reports the mapping containing pc, its immediate neighbours, and the bytes at pc.
void DiagReportMapping(u64 pc) {
    const int fd = ::open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        DiagLog("maps: open failed");
        return;
    }

    size_t total = 0;
    while (total < sizeof(g_diag_maps) - 1) {
        const ssize_t n = ::read(fd, g_diag_maps + total, sizeof(g_diag_maps) - 1 - total);
        if (n <= 0) {
            break;
        }
        total += static_cast<size_t>(n);
    }
    ::close(fd);
    g_diag_maps[total] = '\0';

    const char* const buf_end = g_diag_maps + total;
    const char* prev_begin = nullptr;
    const char* prev_end = nullptr;
    const char* line = g_diag_maps;
    bool found = false;

    while (line < buf_end) {
        const char* eol = line;
        while (eol < buf_end && *eol != '\n') {
            ++eol;
        }

        u64 start = 0;
        u64 end = 0;
        const char* p = line;
        while (p < eol && *p != '-') {
            start = (start << 4) | DiagHexVal(*p);
            ++p;
        }
        if (p < eol) {
            ++p; // skip '-'
        }
        while (p < eol && *p != ' ') {
            end = (end << 4) | DiagHexVal(*p);
            ++p;
        }

        if (pc >= start && pc < end) {
            found = true;
            if (prev_begin != nullptr) {
                DiagLogLine("maps prev: ", prev_begin, prev_end);
            }
            DiagLogLine("maps  PC : ", line, eol);

            const char* next = (eol < buf_end) ? eol + 1 : buf_end;
            if (next < buf_end) {
                const char* next_eol = next;
                while (next_eol < buf_end && *next_eol != '\n') {
                    ++next_eol;
                }
                DiagLogLine("maps next: ", next, next_eol);
            }

            // Permissions sit immediately after the address range.
            const bool readable = (p + 1 < eol) && (p[1] == 'r');
            if (readable) {
                char out[160];
                char* w = DiagStr(out, "bytes at pc:");
                const u32* words = reinterpret_cast<const u32*>(pc);
                for (int i = 0; i < 8; ++i) {
                    w = DiagStr(w, " ");
                    w = DiagHex(w, words[i], 8);
                }
                *w = '\0';
                DiagLog(out);
            } else {
                DiagLog("bytes at pc: region not readable");
            }
            break;
        }

        prev_begin = line;
        prev_end = eol;
        line = (eol < buf_end) ? eol + 1 : buf_end;
    }

    if (!found) {
        DiagLog("maps: no mapping contains pc");
    }
}

void DiagIllegalInstructionHandler(int sig, siginfo_t* info, void* raw_context) {
    auto& host_ctx = static_cast<ucontext_t*>(raw_context)->uc_mcontext;

    const u64 pc = host_ctx.pc;
    const u64 x16 = host_ctx.regs[16];
    const u64 x17 = host_ctx.regs[17];
    const u64 lr = host_ctx.regs[30];

    char line[320];
    char* out = DiagStr(line, "SIGILL si_code=");
    out = DiagHex(out, static_cast<u64>(info->si_code), 2);
    out = DiagStr(out, " pc=0x");
    out = DiagHex(out, pc, 16);
    out = DiagStr(out, " x16=0x");
    out = DiagHex(out, x16, 16);
    out = DiagStr(out, " x17=0x");
    out = DiagHex(out, x17, 16);
    out = DiagStr(out, " lr=0x");
    out = DiagHex(out, lr, 16);
    out = DiagStr(out, " lr-pc=0x");
    out = DiagHex(out, lr - pc, 16);
    out = DiagStr(out, (x16 == pc) ? " [branched via x16]" : "");
    *out = '\0';
    DiagLog(line);

    DiagReportMapping(pc);

    // Extended dump: readable-range index, x0 restore-and-classify, raw stack, frame chain.
    // Must run after DiagReportMapping, which shares the g_diag_maps buffer.
    DiagBuildRangeIndex();
    DiagClassifyX0(host_ctx.regs[0]);
    {
        char buf2[96];
        char* out2 = DiagStr(buf2, "sp=0x");
        out2 = DiagHex(out2, host_ctx.sp, 16);
        out2 = DiagStr(out2, " x29=0x");
        out2 = DiagHex(out2, host_ctx.regs[29], 16);
        *out2 = '\0';
        DiagLog(buf2);
    }
    DiagDumpStack(host_ctx.sp);
    DiagWalkFrames(host_ctx.regs[29]);

    // Restore the default action and return, so the faulting instruction re-executes
    // and produces the normal tombstone.
    struct sigaction dfl {};
    dfl.sa_handler = SIG_DFL;
    Common::SigAction(sig, &dfl, nullptr);
}

// Verify assembly offsets.
using NativeExecutionParameters = Kernel::KThread::NativeExecutionParameters;
static_assert(offsetof(NativeExecutionParameters, native_context) == TpidrEl0NativeContext);
static_assert(offsetof(NativeExecutionParameters, lock) == TpidrEl0Lock);
static_assert(offsetof(NativeExecutionParameters, magic) == TpidrEl0TlsMagic);

fpsimd_context* GetFloatingPointState(mcontext_t& host_ctx) {
    _aarch64_ctx* header = reinterpret_cast<_aarch64_ctx*>(&host_ctx.__reserved);
    while (header->magic != FPSIMD_MAGIC) {
        header = reinterpret_cast<_aarch64_ctx*>(reinterpret_cast<char*>(header) + header->size);
    }
    return reinterpret_cast<fpsimd_context*>(header);
}

using namespace Common::Literals;
constexpr u32 StackSize = 128_KiB;

} // namespace

void ArmNce::DiagSetRegions(const DiagRegionInfo& info) {
    g_diag_regions = info;
    g_diag_regions_valid = true;
}

void ArmNce::DiagAddModule(u64 base, u64 size) {
    if (g_diag_module_count < 16) {
        g_diag_modules[g_diag_module_count++] = {base, size};
    }
}

void* ArmNce::RestoreGuestContext(void* raw_context) {
    // Retrieve the host context.
    auto& host_ctx = static_cast<ucontext_t*>(raw_context)->uc_mcontext;

    // Thread-local parameters will be located in x9.
    auto* tpidr = reinterpret_cast<NativeExecutionParameters*>(host_ctx.regs[9]);
    auto* guest_ctx = static_cast<GuestContext*>(tpidr->native_context);

    // Retrieve the host floating point state.
    auto* fpctx = GetFloatingPointState(host_ctx);

    // Save host callee-saved registers.
    std::memcpy(guest_ctx->host_ctx.host_saved_vregs.data(), &fpctx->vregs[8],
                sizeof(guest_ctx->host_ctx.host_saved_vregs));
    std::memcpy(guest_ctx->host_ctx.host_saved_regs.data(), &host_ctx.regs[19],
                sizeof(guest_ctx->host_ctx.host_saved_regs));

    // Save stack pointer.
    guest_ctx->host_ctx.host_sp = host_ctx.sp;

    // Restore all guest state except tpidr_el0.
    host_ctx.sp = guest_ctx->sp;
    host_ctx.pc = guest_ctx->pc;
    host_ctx.pstate = guest_ctx->pstate;
    fpctx->fpcr = guest_ctx->fpcr;
    fpctx->fpsr = guest_ctx->fpsr;
    std::memcpy(host_ctx.regs, guest_ctx->cpu_registers.data(), sizeof(host_ctx.regs));
    std::memcpy(fpctx->vregs, guest_ctx->vector_registers.data(), sizeof(fpctx->vregs));

    // Return the new thread-local storage pointer.
    return tpidr;
}

void ArmNce::SaveGuestContext(GuestContext* guest_ctx, void* raw_context) {
    // Retrieve the host context.
    auto& host_ctx = static_cast<ucontext_t*>(raw_context)->uc_mcontext;

    // Retrieve the host floating point state.
    auto* fpctx = GetFloatingPointState(host_ctx);

    // Save all guest registers except tpidr_el0.
    std::memcpy(guest_ctx->cpu_registers.data(), host_ctx.regs, sizeof(host_ctx.regs));
    std::memcpy(guest_ctx->vector_registers.data(), fpctx->vregs, sizeof(fpctx->vregs));
    guest_ctx->fpsr = fpctx->fpsr;
    guest_ctx->fpcr = fpctx->fpcr;
    guest_ctx->pstate = static_cast<u32>(host_ctx.pstate);
    guest_ctx->pc = host_ctx.pc;
    guest_ctx->sp = host_ctx.sp;

    // Restore stack pointer.
    host_ctx.sp = guest_ctx->host_ctx.host_sp;

    // Restore host callee-saved registers.
    std::memcpy(&host_ctx.regs[19], guest_ctx->host_ctx.host_saved_regs.data(),
                sizeof(guest_ctx->host_ctx.host_saved_regs));
    std::memcpy(&fpctx->vregs[8], guest_ctx->host_ctx.host_saved_vregs.data(),
                sizeof(guest_ctx->host_ctx.host_saved_vregs));

    // Return from the call on exit by setting pc to x30.
    host_ctx.pc = guest_ctx->host_ctx.host_saved_regs[11];

    // Clear esr_el1 and return it.
    host_ctx.regs[0] = guest_ctx->esr_el1.exchange(0);
}

bool ArmNce::HandleFailedGuestFault(GuestContext* guest_ctx, void* raw_info, void* raw_context) {
    auto& host_ctx = static_cast<ucontext_t*>(raw_context)->uc_mcontext;
    auto* info = static_cast<siginfo_t*>(raw_info);

    // We can't handle the access, so determine why we crashed.
    const bool is_prefetch_abort = host_ctx.pc == reinterpret_cast<u64>(info->si_addr);

    // Diagnostic: this skip was previously completely silent. DiagLog (not LOG_*) because
    // we are inside the SIGSEGV/SIGBUS handler and fmt-based logging allocates.
    {
        char buf[192];
        char* out = DiagStr(buf, "unhandled guest fault: pc=0x");
        out = DiagHex(out, host_ctx.pc, 16);
        out = DiagStr(out, " si_addr=0x");
        out = DiagHex(out, reinterpret_cast<u64>(info->si_addr), 16);
        if (!is_prefetch_abort) {
            out = DiagStr(out, " insn=0x");
            out = DiagHex(out, *reinterpret_cast<const u32*>(host_ctx.pc), 8);
            out = DiagStr(out, " SKIPPING (pc += 4)");
        } else {
            out = DiagStr(out, " (prefetch abort)");
        }
        *out = '\0';
        DiagLog(buf);
    }

    // For data aborts, skip the instruction and return to guest code.
    // This will allow games to continue in many scenarios where they would otherwise crash.
    if (!is_prefetch_abort) {
        host_ctx.pc += 4;
        return true;
    }

    // This is a prefetch abort.
    guest_ctx->esr_el1.fetch_or(static_cast<u64>(HaltReason::PrefetchAbort));

    // Forcibly mark the context as locked. We are still running.
    // We may race with SignalInterrupt here:
    // - If we lose the race, then SignalInterrupt will send us a signal we are masking,
    //   and it will do nothing when it is unmasked, as we have already left guest code.
    // - If we win the race, then SignalInterrupt will wait for us to unlock first.
    auto& thread_params = guest_ctx->parent->m_running_thread->GetNativeExecutionParameters();
    thread_params.lock.store(SpinLockLocked);

    // Return to host.
    SaveGuestContext(guest_ctx, raw_context);
    return false;
}

bool ArmNce::HandleGuestAlignmentFault(GuestContext* guest_ctx, void* raw_info, void* raw_context) {
    auto& host_ctx = static_cast<ucontext_t*>(raw_context)->uc_mcontext;
    auto* fpctx = GetFloatingPointState(host_ctx);
    auto& memory = guest_ctx->parent->m_running_thread->GetOwnerProcess()->GetMemory();

    // Match and execute an instruction.
    auto next_pc = MatchAndExecuteOneInstruction(memory, &host_ctx, fpctx);
    if (next_pc) {
        host_ctx.pc = *next_pc;
        return true;
    }

    // We couldn't handle the access.
    return HandleFailedGuestFault(guest_ctx, raw_info, raw_context);
}

bool ArmNce::HandleGuestAccessFault(GuestContext* guest_ctx, void* raw_info, void* raw_context) {
    auto* info = static_cast<siginfo_t*>(raw_info);

    // Try to handle an invalid access.
    // TODO: handle accesses which split a page?
    const Common::ProcessAddress addr =
        (reinterpret_cast<u64>(info->si_addr) & ~Memory::YUZU_PAGEMASK);
    auto& memory = guest_ctx->parent->m_running_thread->GetOwnerProcess()->GetMemory();
    if (memory.InvalidateNCE(addr, Memory::YUZU_PAGESIZE)) {
        // We handled the access successfully and are returning to guest code.
        return true;
    }

    // We couldn't handle the access.
    return HandleFailedGuestFault(guest_ctx, raw_info, raw_context);
}

void ArmNce::HandleHostAlignmentFault(int sig, void* raw_info, void* raw_context) {
    return g_orig_bus_action.sa_sigaction(sig, static_cast<siginfo_t*>(raw_info), raw_context);
}

void ArmNce::HandleHostAccessFault(int sig, void* raw_info, void* raw_context) {
    return g_orig_segv_action.sa_sigaction(sig, static_cast<siginfo_t*>(raw_info), raw_context);
}

void ArmNce::LockThread(Kernel::KThread* thread) {
    auto* thread_params = &thread->GetNativeExecutionParameters();
    LockThreadParameters(thread_params);
}

void ArmNce::UnlockThread(Kernel::KThread* thread) {
    auto* thread_params = &thread->GetNativeExecutionParameters();
    m_guest_ctx.tpidr_el0 = thread_params->tpidr_el0;
    m_guest_ctx.tpidrro_el0 = thread_params->tpidrro_el0;
    thread_params->native_context = nullptr;
    UnlockThreadParameters(thread_params);
}

HaltReason ArmNce::RunThread(Kernel::KThread* thread) {
    // Check if we're already interrupted.
    // If we are, we can just return immediately.
    HaltReason hr = static_cast<HaltReason>(m_guest_ctx.esr_el1.exchange(0));
    if (True(hr)) {
        return hr;
    }

    // Pre-fetch thread context data to improve cache locality
    auto* thread_params = &thread->GetNativeExecutionParameters();
    auto* process = thread->GetOwnerProcess();

    // Move non-critical operations outside the locked section
    const u64 tpidr_el0_cache = m_guest_ctx.tpidr_el0;
    const u64 tpidrro_el0_cache = m_guest_ctx.tpidrro_el0;

    // Critical section begins - minimize operations here
    m_running_thread = thread;
    m_guest_ctx.parent = this;
    thread_params->native_context = &m_guest_ctx;
    thread_params->tpidr_el0 = tpidr_el0_cache;
    thread_params->tpidrro_el0 = tpidrro_el0_cache;

    // Memory barrier to ensure visibility of changes
    std::atomic_thread_fence(std::memory_order_release);
    thread_params->is_running = true;

    // TODO: finding and creating the post handler needs to be locked
    // to deal with dynamic loading of NROs.
    const auto& post_handlers = process->GetPostHandlers();
    if (auto it = post_handlers.find(m_guest_ctx.pc); it != post_handlers.end()) {
        hr = ReturnToRunCodeByTrampoline(thread_params, &m_guest_ctx, it->second);
    } else {
        hr = ReturnToRunCodeByExceptionLevelChange(m_thread_id, thread_params);  // Android: Use "process handle SIGUSR2 -n true -p true -s false" (and SIGURG) in LLDB when debugging
    }

    // Critical section for thread cleanup
    std::atomic_thread_fence(std::memory_order_acquire);

    // Cache values before releasing thread
    const u64 final_tpidr_el0 = thread_params->tpidr_el0;

    // Minimize critical section
    thread_params->is_running = false;
    thread_params->native_context = nullptr;
    m_running_thread = nullptr;

    // Non-critical updates can happen after releasing the thread
    m_guest_ctx.tpidr_el0 = final_tpidr_el0;

    // Return the halt reason.
    return hr;
}

HaltReason ArmNce::StepThread(Kernel::KThread* thread) {
    return HaltReason::StepThread;
}

u32 ArmNce::GetSvcNumber() const {
    return m_guest_ctx.svc;
}

void ArmNce::GetSvcArguments(std::span<uint64_t, 8> args) const {
    for (size_t i = 0; i < 8; i++) {
        args[i] = m_guest_ctx.cpu_registers[i];
    }
}

void ArmNce::SetSvcArguments(std::span<const uint64_t, 8> args) {
    for (size_t i = 0; i < 8; i++) {
        m_guest_ctx.cpu_registers[i] = args[i];
    }
}

ArmNce::ArmNce(System& system, bool uses_wall_clock, std::size_t core_index)
    : ArmInterface{uses_wall_clock}, m_system{system}, m_core_index{core_index} {
    m_guest_ctx.system = &m_system;
}

ArmNce::~ArmNce() = default;

void ArmNce::Initialize() {
    if (m_thread_id == -1) {
        m_thread_id = gettid();
    }

    // Configure signal stack.
    if (!m_stack) {
        m_stack = std::make_unique<u8[]>(StackSize);

        stack_t ss{};
        ss.ss_sp = m_stack.get();
        ss.ss_size = StackSize;
        sigaltstack(&ss, nullptr);
    }

    // Set up signals.
    static std::once_flag flag;
    std::call_once(flag, [] {
        using HandlerType = decltype(sigaction::sa_sigaction);

        sigset_t signal_mask;
        sigemptyset(&signal_mask);
        sigaddset(&signal_mask, ReturnToRunCodeByExceptionLevelChangeSignal);
        sigaddset(&signal_mask, BreakFromRunCodeSignal);
        sigaddset(&signal_mask, GuestAlignmentFaultSignal);
        sigaddset(&signal_mask, GuestAccessFaultSignal);

        struct sigaction return_to_run_code_action {};
        return_to_run_code_action.sa_flags = SA_SIGINFO | SA_ONSTACK;
        return_to_run_code_action.sa_sigaction = reinterpret_cast<HandlerType>(
            &ArmNce::ReturnToRunCodeByExceptionLevelChangeSignalHandler);
        return_to_run_code_action.sa_mask = signal_mask;
        Common::SigAction(ReturnToRunCodeByExceptionLevelChangeSignal, &return_to_run_code_action,
                          nullptr);

        struct sigaction break_from_run_code_action {};
        break_from_run_code_action.sa_flags = SA_SIGINFO | SA_ONSTACK;
        break_from_run_code_action.sa_sigaction =
            reinterpret_cast<HandlerType>(&ArmNce::BreakFromRunCodeSignalHandler);
        break_from_run_code_action.sa_mask = signal_mask;
        Common::SigAction(BreakFromRunCodeSignal, &break_from_run_code_action, nullptr);

        struct sigaction alignment_fault_action {};
        alignment_fault_action.sa_flags = SA_SIGINFO | SA_ONSTACK;
        alignment_fault_action.sa_sigaction =
            reinterpret_cast<HandlerType>(&ArmNce::GuestAlignmentFaultSignalHandler);
        alignment_fault_action.sa_mask = signal_mask;
        Common::SigAction(GuestAlignmentFaultSignal, &alignment_fault_action, nullptr);

        struct sigaction access_fault_action {};
        access_fault_action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
        access_fault_action.sa_sigaction =
            reinterpret_cast<HandlerType>(&ArmNce::GuestAccessFaultSignalHandler);
        access_fault_action.sa_mask = signal_mask;
        Common::SigAction(GuestAccessFaultSignal, &access_fault_action, &g_orig_segv_action);

        // Temporary diagnostic: NCE has no SIGILL handler, so an illegal instruction in
        // guest code kills the process with no emulator-side context. Record what we can.
        struct sigaction ill_diag_action {};
        ill_diag_action.sa_flags = SA_SIGINFO | SA_ONSTACK;
        ill_diag_action.sa_sigaction = &DiagIllegalInstructionHandler;
        ill_diag_action.sa_mask = signal_mask;
        Common::SigAction(SIGILL, &ill_diag_action, &g_orig_ill_action);
    });
}

void ArmNce::SetTpidrroEl0(u64 value) {
    m_guest_ctx.tpidrro_el0 = value;
}

void ArmNce::GetContext(Kernel::Svc::ThreadContext& ctx) const {
    for (size_t i = 0; i < 29; i++) {
        ctx.r[i] = m_guest_ctx.cpu_registers[i];
    }
    ctx.fp = m_guest_ctx.cpu_registers[29];
    ctx.lr = m_guest_ctx.cpu_registers[30];
    ctx.sp = m_guest_ctx.sp;
    ctx.pc = m_guest_ctx.pc;
    ctx.pstate = m_guest_ctx.pstate;
    ctx.v = m_guest_ctx.vector_registers;
    ctx.fpcr = m_guest_ctx.fpcr;
    ctx.fpsr = m_guest_ctx.fpsr;
    ctx.tpidr = m_guest_ctx.tpidr_el0;
}

void ArmNce::SetContext(const Kernel::Svc::ThreadContext& ctx) {
    for (size_t i = 0; i < 29; i++) {
        m_guest_ctx.cpu_registers[i] = ctx.r[i];
    }
    m_guest_ctx.cpu_registers[29] = ctx.fp;
    m_guest_ctx.cpu_registers[30] = ctx.lr;
    m_guest_ctx.sp = ctx.sp;
    m_guest_ctx.pc = ctx.pc;
    m_guest_ctx.pstate = ctx.pstate;
    m_guest_ctx.vector_registers = ctx.v;
    m_guest_ctx.fpcr = ctx.fpcr;
    m_guest_ctx.fpsr = ctx.fpsr;
    m_guest_ctx.tpidr_el0 = ctx.tpidr;
}

void ArmNce::SignalInterrupt(Kernel::KThread* thread) {
    // Add break loop condition.
    m_guest_ctx.esr_el1.fetch_or(static_cast<u64>(HaltReason::BreakLoop));

    auto* params = &thread->GetNativeExecutionParameters();
    LockThreadParameters(params);

    // Ensure visibility of is_running after lock acquire
    std::atomic_thread_fence(std::memory_order_acquire);

    if (params->is_running) {
        // We should signal to the running thread.
        // The running thread will unlock the thread context.
        syscall(SYS_tkill, m_thread_id, BreakFromRunCodeSignal);
    } else {
        // If the thread is no longer running, we have nothing to do.
        UnlockThreadParameters(params);
    }
}

[[maybe_unused]] const std::size_t CACHE_PAGE_SIZE = 4096;

void ArmNce::ClearInstructionCache() {
#ifdef __aarch64__
    // Ensure all previous memory operations complete
    asm volatile("dsb ish\n"
                 "dsb ish\n"
                 "isb" ::: "memory");
#endif
}

void ArmNce::InvalidateCacheRange(u64 addr, std::size_t size) {
    this->ClearInstructionCache();
}

} // namespace Core
