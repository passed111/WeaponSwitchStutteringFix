#include "Internal.h"

namespace wslf
{
    // ------------------------------------------------------------------ //

    // ------------------------------------------------------------------ //
    // Install helpers
    // ------------------------------------------------------------------ //

    // Shared with ExamineLagFix - see that project for the rationale.
    // (SigAnchor itself is defined in Internal.h.)
    [[nodiscard]] bool IsInsideExe(std::uintptr_t a_addr)
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base || a_addr < base) return false;
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        return a_addr < base + nt->OptionalHeader.SizeOfImage;
    }
    std::uintptr_t ScanTextSig(const std::uint8_t* a_sig, std::size_t a_len,
        const SigAnchor* a_anchors, std::size_t a_nAnchors,
        bool a_allowMiss, const char* a_tag)
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base) return 0;
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (std::uint32_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            if (std::memcmp(sec->Name, ".text", 6) != 0) continue;
            const auto* begin = reinterpret_cast<const std::uint8_t*>(base + sec->VirtualAddress);
            const auto* end = begin + sec->Misc.VirtualSize;
            std::uintptr_t found = 0;
            int survivors = 0;
            const auto* p = begin;
            while (p < end &&
                   (p = reinterpret_cast<const std::uint8_t*>(
                        std::memchr(p, a_sig[0], static_cast<std::size_t>(end - p)))) != nullptr) {
                if (end - p >= static_cast<std::ptrdiff_t>(a_len) &&
                    std::memcmp(p, a_sig, a_len) == 0) {
                    bool ok = true;
                    for (std::size_t a = 0; a < a_nAnchors && ok; ++a) {
                        const auto& an = a_anchors[a];
                        ok = (p + an.off + an.len <= end) &&
                             std::memcmp(p + an.off, an.bytes, an.len) == 0;
                    }
                    if (ok) {
                        ++survivors;
                        found = base + sec->VirtualAddress + (p - begin);
                        if (survivors > 1) break;
                    }
                }
                ++p;
            }
            if (survivors == 1) return found;
            if (survivors == 0 && a_allowMiss) return 0;
            REX::ERROR("WeaponSwapLagFix: [{}] signature survivors={} (need exactly 1)",
                a_tag, survivors);
            return 0;
        }
        return 0;
    }

    // JMP14 entry hook (InventoryLagFix pattern): save the prologue, build a
    // trampoline stub (prologue + jmp back), write a jmp to the hook over the
    // prologue. The displaced prologue must be at least JMP14-sized and end
    // on an instruction boundary - both verified per target below.
    std::uintptr_t PatchFuncEntry(std::uintptr_t a_addr, std::size_t a_hookSize,
        void* a_hookFn, const char* a_tag)
    {
        if (a_hookSize < sizeof(REL::ASM::JMP14)) {
            REX::ERROR("WeaponSwapLagFix: [{}] displacement {} < JMP14 size {}, hook NOT installed",
                a_tag, a_hookSize, sizeof(REL::ASM::JMP14));
            return 0;
        }

        std::byte saved[32];
        std::memcpy(saved, reinterpret_cast<const void*>(a_addr), a_hookSize);

        auto& tramp = REL::GetTrampoline();
        auto* stub = static_cast<std::byte*>(tramp.allocate(a_hookSize + sizeof(REL::ASM::JMP14)));
        if (!stub) {
            REX::ERROR("WeaponSwapLagFix: [{}] trampoline alloc failed", a_tag);
            return 0;
        }
        std::memcpy(stub, saved, a_hookSize);
        REL::ASM::JMP14 jmpBack(a_addr + a_hookSize);
        std::memcpy(stub + a_hookSize, &jmpBack, sizeof(jmpBack));

        REL::ASM::JMP14 jmpHook(reinterpret_cast<std::uintptr_t>(a_hookFn));
        REL::WriteSafe(a_addr, reinterpret_cast<const std::byte*>(&jmpHook), sizeof(jmpHook));

        if (std::memcmp(reinterpret_cast<const void*>(a_addr), &jmpHook, sizeof(jmpHook)) != 0) {
            REL::WriteSafe(a_addr, saved, a_hookSize);
            REX::ERROR("WeaponSwapLagFix: [{}] patch readback MISMATCH @ 0x{:X}, restored", a_tag, a_addr);
            return 0;
        }
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return reinterpret_cast<std::uintptr_t>(stub);
    }

    // Scan the executing module's .text for a byte pattern; returns the only
    // match or 0 (same search style as CraftingMenuFix's GetKeywordByIndex
    // scan - zero hardcoded RVAs, unique-match-or-bail).
    std::uintptr_t ScanTextUnique(const std::uint8_t* a_sig, std::size_t a_len, const char* a_tag)
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base) return 0;
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (std::uint32_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            if (std::memcmp(sec->Name, ".text", 6) != 0) continue;
            const auto* begin = reinterpret_cast<const std::uint8_t*>(base + sec->VirtualAddress);
            const auto* end = begin + sec->Misc.VirtualSize;
            std::uintptr_t found = 0;
            int matches = 0;
            const auto* p = begin;
            while (p < end &&
                   (p = reinterpret_cast<const std::uint8_t*>(
                        std::memchr(p, a_sig[0], static_cast<std::size_t>(end - p)))) != nullptr) {
                if (end - p >= static_cast<std::ptrdiff_t>(a_len) &&
                    std::memcmp(p, a_sig, a_len) == 0) {
                    ++matches;
                    found = base + sec->VirtualAddress + (p - begin);
                    if (matches > 1) break;
                }
                ++p;
            }
            if (matches != 1) {
                REX::ERROR("WeaponSwapLagFix: [{}] signature matches={} (need exactly 1)", a_tag, matches);
                return 0;
            }
            return found;
        }
        return 0;
    }

    // Walk back from a hit to the function start (int3 padding). The three
    // runtime families place the OR opcode 0xA..0xF bytes into the function.
    [[nodiscard]] std::uintptr_t FuncStartFromHit(std::uintptr_t a_hit, std::size_t a_back)
    {
        auto* p = reinterpret_cast<const std::uint8_t*>(a_hit);
        for (std::size_t i = 0; i < a_back; ++i) {
            if (*(p - 1) == 0xCC) return a_hit - i;
            --p;
        }
        return 0;
    }

    bool VerifyBytes(std::uintptr_t a_addr, const std::uint8_t* a_expected, std::size_t a_len)
    {
        return std::memcmp(reinterpret_cast<const void*>(a_addr), a_expected, a_len) == 0;
    }

    // TEMP DIAG helper (weapon-switch stall hunt) - remove together with the
    // equip timing hook.
    [[nodiscard]] std::int64_t NowUs()
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    // rel32 target of the E8 at a_fn+a_off, or 0 when it is not a call.
    [[nodiscard]] std::uintptr_t CallTargetAt(std::uintptr_t a_fn, std::size_t a_off)
    {
        const auto* p = reinterpret_cast<const std::uint8_t*>(a_fn + a_off);
        if (p[0] != 0xE8) return 0;
        const auto tgt = a_fn + a_off + 5 + *reinterpret_cast<const std::int32_t*>(p + 1);
        return IsInsideExe(tgt) ? tgt : 0;
    }
}
