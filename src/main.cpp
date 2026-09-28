#include "F4SE/F4SE.h"
#include "RE/Fallout.h"
#include <REX/REX.h>
#include <Windows.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdio>
#undef ERROR

// ============================================================================
// WeaponSwapLagFix
//
// Removes the stall that fires the moment the player swaps a weapon, whether
// from the Pip-Boy or from a hotkey. Three separate costs, each measured
// before it was touched:
//
//  1. Equip pipeline repetition. One swap runs the pipeline three to four
//     times (old weapon unequip + new weapon equip inside AEM::Equip, then
//     Actor::EquipAmmo recurses for the ammo swap), and every
//     Actor::EquipObject/UnequipObject tail repeats the same two closures:
//     CalcEquippedWeight walks the entire inventory item array and
//     ForceUpdateCachedMovementType sweeps perk entries (HandleEntryPoint)
//     plus two AV reads. Only the last pass survives - so inside the
//     player's outermost EquipObject both are skipped and flushed once on
//     the way out, in vanilla order.
//
//  2. Pip-Boy category rebuild. A perk event (PerkEntryUpdated /
//     PerkValueChanged, raised constantly by mods that refresh a perk value
//     with RemovePerk + AddPerk) queues WEAP/ARMO/ALCH and every item card
//     in those categories is rebuilt from scratch - 0.75 to 2.3 seconds,
//     on the same thread that runs the game. Requests raised by the two
//     perk sinks are rate limited; equips, inventory and AV changes run
//     vanilla.
//
//  3. Item card construction. RepopulateItem rebuilds one card per stack
//     and each card starts with CombatFormulas::GetWeaponDisplayDamage,
//     ~4ms on its own. The result is memoised on the weapon form, its
//     instance data, the ammo and the (dead) health percentage, and dropped
//     whenever a non-weapon is equipped.
//
// Everything is resolved by signature / prologue verification with a hard
// fail-safe: any mismatch leaves that hook uninstalled. No hardcoded RVAs.
//
// There is no ini file. The diagnostics are compile-time constants next to the
// code they govern - g_verbose (per-tap timing lines), g_diagHooks (set 0 to
// install no timing hooks at all, the A/B switch for crash triage),
// g_perkTraceMax (stack walk when a perk sink queues a rebuild) and
// g_perkLogMax (log each perk Papyrus adds/removes). All of them self-limit.
// ============================================================================
namespace
{
    // Shared with ExamineLagFix - see that project for the rationale.
    struct SigAnchor { std::size_t off; const std::uint8_t* bytes; std::size_t len; };

    // Shared with ExamineLagFix - see that project for the rationale.
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

    // ------------------------------------------------------------------ //

    // ------------------------------------------------------------------ //
    // Install helpers
    // ------------------------------------------------------------------ //

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

    // ------------------------------------------------------------------ //

    // ------------------------------------------------------------------ //
    // TEMP DIAG: weapon-switch stall hunt. Both the Pip-Boy equip and the
    // hotkey path funnel through ActorEquipManager::EquipObject - time it
    // (player only, with the Pip-Boy state) to see whether the stall lives
    // in the equip pipeline at all. Remove after verification.
    // ------------------------------------------------------------------ //

    using EquipObjectFn = bool (*)(RE::ActorEquipManager*, RE::Actor*,
        const RE::BGSObjectInstance&, std::uint32_t, std::uint32_t,
        const RE::BGSEquipSlot*, bool, bool, bool, bool, bool);
    EquipObjectFn g_origEquipObject = nullptr;

    // Player-equip depth: taps only accumulate while a player EquipObject is
    // in flight, so NPC equips (different threads) do not pollute the numbers.
    std::atomic<std::int32_t> g_diagDepth{ 0 };

    // Weapon-switch defer fix. One swap runs the equip pipeline three to
    // four times (old weapon unequip + new weapon equip inside AEM::Equip,
    // then Actor::EquipAmmo recurses into a second full AEM::EquipObject
    // for the ammo swap), and every Actor::EquipObject/UnequipObject tail
    // repeats the same two expensive closures: CalcEquippedWeight walks
    // the entire inventory item array and ForceUpdateCachedMovementType
    // sweeps perk entries (HandleEntryPoint) plus two AV reads. Only the
    // last pass's result survives, so inside the player's outermost
    // EquipObject both are skipped and flushed exactly once on the way
    // out, in vanilla order (weight first, then movement type).
    float g_deferWeight{ 0.0f };
    bool  g_deferWeightDirty{ false };
    bool  g_deferMoveDirty{ false };
    bool  g_deferActive{ false };

    struct TapStats {
        std::atomic<std::uint32_t> n{ 0 };
        std::atomic<std::int64_t> totalUs{ 0 };
        std::atomic<std::int64_t> maxUs{ 0 };
        void Record(std::int64_t a_us)
        {
            n.fetch_add(1, std::memory_order_relaxed);
            totalUs.fetch_add(a_us, std::memory_order_relaxed);
            auto m = maxUs.load(std::memory_order_relaxed);
            while (a_us > m && !maxUs.compare_exchange_weak(m, a_us,
                       std::memory_order_relaxed)) {}
        }
        void Reset()
        {
            n.store(0, std::memory_order_relaxed);
            totalUs.store(0, std::memory_order_relaxed);
            maxUs.store(0, std::memory_order_relaxed);
        }
    };

    // Tap indices, keep in sync with InstallEquipTaps.
    enum TapIdx {
        kTapApplyToActor = 0,
        kTapEquipApply,
        kTapWeightRecompute,
        kTapTailFn2,
        kTapFindEntry,
        kTapCollectItems,
        kTapInvUpdate,
        kTapHolster,
        kTapPostEquip,
        kTapApplyQueue,
        kTapPerItemCheck,
        kTapLoopEquip,
        kTapPostApply,
        kTapWrapper1,
        kTapLoopEquipMain,
        kTapLoopSlotResolve,
        kTapLoopCheck,
        kTapWrapperSlot,
        kTapInvBig,
        kTapEventNotify,
        kTapRepItem,
        kTapComparison,
        kTapRepRemove,
        kTapRepA,
        kTapRepB,
        kTapRepC,
        kTapRepD,
        kTapCardInfo,
        kTapQueueCard,
        kTapSecRepop,
        kTapBaseAdd,
        kTapAddEntry,
        kTapFillDmg,
        kTapFillRes,
        kTapReqAnim,
        kTapPollEquip,
        kTapReloadGraph,
        kTapDispDmg,
        kTapCount
    };
    TapStats g_taps[kTapCount];
    std::uint64_t g_tapOrig[kTapCount]{};

    // (actor, objInst*, int*) -> void
    using T0_t = void (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    // (mgr, actor, instData, u8, char) -> u64
    using T1_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t,
        std::uint64_t, std::uint64_t);
    // (actor) -> float   [equippedWeight recompute]
    using T2_t = float (*)(std::uint64_t);
    // (actor) -> void
    using T3_t = void (*)(std::uint64_t);
    // (actor, form) -> int
    using T4_t = std::uint64_t (*)(std::uint64_t, std::uint64_t);
    // (invChanges, instData, out) -> ptr
    using T5_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    // (invChanges, actor, objInst*, instData) -> void
    using T6_t = void (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
    // (actor, char) -> void
    using T7_t = void (*)(std::uint64_t, std::uint64_t);
    // (actor, int) -> void
    using T8_t = void (*)(std::uint64_t, std::uint64_t);
    // (actor, objInst, param3) -> u64
    using T9_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);

    void HookedT0(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        reinterpret_cast<T0_t>(g_tapOrig[kTapApplyToActor])(a1, a2, a3);
        if (on) g_taps[kTapApplyToActor].Record(NowUs() - t0);
    }
    std::uint64_t HookedT1(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3,
        std::uint64_t a4, std::uint64_t a5)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T1_t>(g_tapOrig[kTapEquipApply])(a1, a2, a3, a4, a5);
        if (on) g_taps[kTapEquipApply].Record(NowUs() - t0);
        return r;
    }
    float HookedT2(std::uint64_t a1)
    {
        // Equip-transaction defer: skip the full inventory walk while a
        // player equip is in flight; the outermost EquipObject flushes it
        // once. Callers inside the pipeline ignore the return value (the
        // result lands in the actor's equippedWeight field, refreshed by
        // the flush), and non-player actors always run vanilla.
        if (g_deferActive
            && g_diagDepth.load(std::memory_order_relaxed) > 0
            && reinterpret_cast<void*>(a1) == RE::PlayerCharacter::GetSingleton()) {
            g_deferWeightDirty = true;
            return g_deferWeight;
        }
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T2_t>(g_tapOrig[kTapWeightRecompute])(a1);
        if (on) g_taps[kTapWeightRecompute].Record(NowUs() - t0);
        return r;
    }
    void HookedT3(std::uint64_t a1)
    {
        // Same defer as the weight walk above: the movement-type refresh
        // sweeps perk entries and re-reads movement AVs, and only the last
        // invocation per equip transaction is observable.
        if (g_deferActive
            && g_diagDepth.load(std::memory_order_relaxed) > 0
            && reinterpret_cast<void*>(a1) == RE::PlayerCharacter::GetSingleton()) {
            g_deferMoveDirty = true;
            return;
        }
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        reinterpret_cast<T3_t>(g_tapOrig[kTapTailFn2])(a1);
        if (on) g_taps[kTapTailFn2].Record(NowUs() - t0);
    }
    std::uint64_t HookedT4(std::uint64_t a1, std::uint64_t a2)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T4_t>(g_tapOrig[kTapFindEntry])(a1, a2);
        if (on) g_taps[kTapFindEntry].Record(NowUs() - t0);
        return r;
    }
    std::uint64_t HookedT5(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T5_t>(g_tapOrig[kTapCollectItems])(a1, a2, a3);
        if (on) g_taps[kTapCollectItems].Record(NowUs() - t0);
        return r;
    }
    void HookedT6(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        reinterpret_cast<T6_t>(g_tapOrig[kTapInvUpdate])(a1, a2, a3, a4);
        if (on) g_taps[kTapInvUpdate].Record(NowUs() - t0);
    }
    void HookedT7(std::uint64_t a1, std::uint64_t a2)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        reinterpret_cast<T7_t>(g_tapOrig[kTapHolster])(a1, a2);
        if (on) g_taps[kTapHolster].Record(NowUs() - t0);
    }
    void HookedT8(std::uint64_t a1, std::uint64_t a2)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        reinterpret_cast<T8_t>(g_tapOrig[kTapPostEquip])(a1, a2);
        if (on) g_taps[kTapPostEquip].Record(NowUs() - t0);
    }
    std::uint64_t HookedT9(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T9_t>(g_tapOrig[kTapApplyQueue])(a1, a2, a3);
        if (on) g_taps[kTapApplyQueue].Record(NowUs() - t0);
        return r;
    }
    // (actor, entry, form) -> bool - runs once per collected item inside
    // EquipApply, each call walks the full BGSInventoryList
    using T10_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    std::uint64_t HookedT10(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T10_t>(g_tapOrig[kTapPerItemCheck])(a1, a2, a3);
        if (on) g_taps[kTapPerItemCheck].Record(NowUs() - t0);
        return r;
    }
    // 11 scalar args, return ignored by the caller
    using T11_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t,
        std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t,
        std::uint64_t, std::uint64_t, std::uint64_t);
    std::uint64_t HookedT11(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3,
        std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, std::uint64_t a7,
        std::uint64_t a8, std::uint64_t a9, std::uint64_t a10, std::uint64_t a11)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T11_t>(g_tapOrig[kTapLoopEquip])(a1, a2, a3,
            a4, a5, a6, a7, a8, a9, a10, a11);
        if (on) g_taps[kTapLoopEquip].Record(NowUs() - t0);
        return r;
    }
    // (actor, objInst*, count) -> void - ApplyToActor case 0x2B tail
    using T12_t = void (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    void HookedT12(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        reinterpret_cast<T12_t>(g_tapOrig[kTapPostApply])(a1, a2, a3);
        if (on) g_taps[kTapPostApply].Record(NowUs() - t0);
    }
    // (actor, form, flags) -> instanceData default - EquipObject head
    using T13_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    std::uint64_t HookedT13(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T13_t>(g_tapOrig[kTapWrapper1])(a1, a2, a3);
        if (on) g_taps[kTapWrapper1].Record(NowUs() - t0);
        return r;
    }
    // (mgr, actor, objInst, args) -> ? - LoopEquip's main work call
    using T14_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
    std::uint64_t HookedT14(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T14_t>(g_tapOrig[kTapLoopEquipMain])(a1, a2, a3, a4);
        if (on) g_taps[kTapLoopEquipMain].Record(NowUs() - t0);
        return r;
    }
    // (mgr, actor, objInst*) -> slot - LoopEquip slot resolve
    using T15_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    std::uint64_t HookedT15(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T15_t>(g_tapOrig[kTapLoopSlotResolve])(a1, a2, a3);
        if (on) g_taps[kTapLoopSlotResolve].Record(NowUs() - t0);
        return r;
    }
    // (actor, form) -> bool - LoopEquip equip check
    using T16_t = std::uint64_t (*)(std::uint64_t, std::uint64_t);
    std::uint64_t HookedT16(std::uint64_t a1, std::uint64_t a2)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T16_t>(g_tapOrig[kTapLoopCheck])(a1, a2);
        if (on) g_taps[kTapLoopCheck].Record(NowUs() - t0);
        return r;
    }
    // (mgr, actor, objInst*) -> slot - EquipObject wrapper slot resolve
    using T17_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    std::uint64_t HookedT17(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T17_t>(g_tapOrig[kTapWrapperSlot])(a1, a2, a3);
        if (on) g_taps[kTapWrapperSlot].Record(NowUs() - t0);
        return r;
    }
    // (invChanges, actor, form, instData) -> void - equipped-array edit with
    // linear scans and per-removal memmoves inside LoopEquipMain
    using T18_t = void (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
    void HookedT18(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        reinterpret_cast<T18_t>(g_tapOrig[kTapInvBig])(a1, a2, a3, a4);
        if (on) g_taps[kTapInvBig].Record(NowUs() - t0);
    }
    // (eventSource, event) -> refcount - the Notify body is ICF-folded across
    // event-source types, so the hook filters on the actual ActorEquipManager
    // source before counting anything.
    using T19_t = std::int64_t (*)(std::uint64_t, std::uint64_t);
    std::uint64_t g_aemSource = 0;  // ActorEquipManager singleton + 8
    std::int64_t HookedT19(std::uint64_t a1, std::uint64_t a2)
    {
        const bool isAem = g_aemSource != 0 && a1 == g_aemSource;
        if (isAem) {
            static bool s_sunkSinks = false;
            if (!s_sunkSinks) {
                s_sunkSinks = true;
                const auto* sinkArr = *reinterpret_cast<void* const* const*>(a1 + 0x20);
                const auto count = *reinterpret_cast<std::uint32_t*>(a1 + 0x30);
                if (!sinkArr) {
                    REX::INFO("WeaponSwapLagFix DIAG: AEM sinks at dispatch: <none>");
                } else {
                    REX::INFO("WeaponSwapLagFix DIAG: AEM sinks at dispatch: {}", count);
                    for (std::uint32_t i = 0; i < count && i < 64; ++i) {
                        const auto sink = sinkArr[i];
                        if (!sink) continue;
                        const auto vtbl = *reinterpret_cast<void* const*>(sink);
                        HMODULE mod = nullptr;
                        wchar_t wpath[MAX_PATH]{};
                        char name[MAX_PATH]{ "unknown" };
                        if (GetModuleHandleExW(
                                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(vtbl), &mod) && mod) {
                            GetModuleFileNameW(mod, wpath, MAX_PATH);
                            const auto* wbase = std::wcsrchr(wpath, L'\\');
                            WideCharToMultiByte(CP_UTF8, 0, wbase ? wbase + 1 : wpath, -1,
                                name, sizeof(name), nullptr, nullptr);
                        }
                        REX::INFO("WeaponSwapLagFix DIAG: AEM sink[{}] vtable 0x{:X} ({})",
                            i, reinterpret_cast<std::uintptr_t>(vtbl), name);
                    }
                }
            }
        }
        const bool on = isAem && g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T19_t>(g_tapOrig[kTapEventNotify])(a1, a2);
        if (on) g_taps[kTapEventNotify].Record(NowUs() - t0);
        return r;
    }

    // ------------------------------------------------------------------ //
    // Round 6 taps: the Pip-Boy refresh driven by ActorEquipManagerEvent.
    //
    // Offline-proof (1.10.155 PDB build, then carried to all four shipping
    // exe families through address-library IDs): inside
    // PipboyInventoryData::ProcessEvent(ActorEquipManagerEvent) the call
    // sequence is byte-for-byte at the same offsets on OG163/NG984/AE221/
    // AE240 - LockDataGroup at +0x2D, then per equipped form:
    //   +0x62  RepopulateItem(this, BGSInventoryItem*)          <- single item
    //   +0x70  PopulateComparisonInfoForSection(this, formType) <- every item
    //          of that category, each difference field recomputed and pushed
    //   +0xAE  QueueItemCardRepopulate(WEAP)   (armour branch only)
    //   +0xBA  UnlockDataGroup
    // The second one is O(items in category), so it is the prime suspect for
    // "lag scales with how much junk I carry". These taps measure both.
    //
    // (pipboyInventoryData, BGSInventoryItem*) -> void
    using T20_t = void (*)(std::uint64_t, std::uint64_t);
    // (pipboyInventoryData, ENUM_FORM_ID) -> void
    using T21_t = void (*)(std::uint64_t, std::uint64_t);

    // Bit mask of the categories whose comparison info got rebuilt, printed
    // once per equip window so we can see which enum values are hit.
    std::atomic<std::uint64_t> g_cmpSectionMask{ 0 };

    // Round 8 counters - counted for every call, in-equip or not (see the
    // HookedT27/T28/T29 comments). The per-equip delta shows work that ran
    // outside any EquipObject call.
    std::atomic<std::uint32_t> g_cardAllN{ 0 };
    std::atomic<std::int64_t>  g_cardAllUs{ 0 };
    std::atomic<std::uint32_t> g_secAllN{ 0 };
    std::atomic<std::int64_t>  g_secAllUs{ 0 };
    std::atomic<std::uint64_t> g_queueMask{ 0 };

    // Round 7 measurement:
    //   RepopulateItem 8.4-12ms/equip, of which RepSubA ~= all of it and
    //   PopulateItemCardInfo ~= 97% of RepSubA (~4.2ms per call, once per
    //   stack - an item with 13 stacks paid 54ms for one equip).
    //
    // Round 8: skipping that call is NOT safe. RepopulateItem is
    //   RemoveItem -> AddItemToData (a *fresh* PipboyObject) ->
    //   PopulateComparisonInfoForItem, and the comparison step reads members
    //   out of the card. With no card ever built the entry simply has no
    //   ItemCardInfo member and the next dereference is null:
    //     Fallout4.exe+0ACA130 mov eax,[rcx+0x28] with rcx = 0
    //   (crash-2026-09-19-20-10-11.log, first hotkey swap with mode 1).
    // So the card is a required construction step here, not a cache refresh.
    // Kept off until a variant that keeps the
    // entry consistent exists (e.g. skipping the whole RepopulateItem while
    // the menu is closed, which needs to know whether opening the menu
    // rebuilds the data anyway - that is what the Round 8 counters measure).
    // 0 = off, 1 = only while the Pip-Boy is closed, 2 = always on equip.
    // Compile-time only: nothing reads an ini any more.
    int  g_cardSkipMode = 0;
    std::atomic<int>  g_inRepopulateItem{ 0 };
    std::atomic<int>  g_cardSkipped{ 0 };

    // Round 8 - the actual seconds-level stall. Measured with the Round 8 taps:
    //   RepopulateItemCardOnSection(0x2B) 786042 / 840953 / 998106 / 1120362 us
    // i.e. every weapon swap queues a job that rebuilds the item card of EVERY
    // weapon in the category, 0.8-1.1s a pop, running after EquipObject has
    // already returned - which is why the equip itself only measured 20-100ms
    // while the player saw a two-second stall and 60 -> 30 fps.
    // The engine already refreshes the affected item individually through
    // RepopulateItem, so this category-wide pass is belt-and-braces. We drop
    // only the weapons-category queue raised while equipping a weapon; armour
    // equips (whose perks really can change weapon damage) keep vanilla
    // behaviour, and so does every non-equip caller.
    int  g_skipCatQueue = 1;
    // Round 9: BreakRebuildLoop (drop a category queue raised while a rebuild
    // is already running) and ThrottleMs (minimum gap between two rebuilds of
    // the same category). Both default on; see HookedT28.
    int  g_breakLoop = 1;
    std::int64_t g_throttleMs = 500;
    // Round 10: the two perk sinks (PerkEntryUpdated @ base+0xB0 and
    // PerkValueChanged @ base+0xB8) are the ones spamming the queue. Resolved
    // at install time from VTABLE[4] / VTABLE[5] - no hardcoded RVA - and
    // rate-limited to one request per PerkQueueGapMs instead of one per second.
    // Raised from 8000 to 20000: the 8s value the player confirmed removed
    // most of the stall, but a rebuild still costs ~200 damage computations
    // (~840ms). 20s keeps a real perk change well inside the time it takes to
    // open the Pip-Boy; lower it if the numbers on screen ever look stale.
    std::uintptr_t g_perkSink[2]{ 0, 0 };
    std::atomic<std::int64_t> g_lastPerkQueueUs{ 0 };
    std::int64_t g_perkQueueGapMs = 20000;
    std::atomic<int>          g_perkDropped{ 0 };
    std::atomic<std::uint32_t> g_equipFormType{ 0 };
    std::atomic<int>           g_catQueueSkipped{ 0 };

    void HookedT20(std::uint64_t a1, std::uint64_t a2)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        g_inRepopulateItem.fetch_add(1, std::memory_order_relaxed);
        reinterpret_cast<T20_t>(g_tapOrig[kTapRepItem])(a1, a2);
        g_inRepopulateItem.fetch_sub(1, std::memory_order_relaxed);
        if (on) g_taps[kTapRepItem].Record(NowUs() - t0);
    }
    void HookedT21(std::uint64_t a1, std::uint64_t a2)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        reinterpret_cast<T21_t>(g_tapOrig[kTapComparison])(a1, a2);
        if (on) {
            g_taps[kTapComparison].Record(NowUs() - t0);
            if (a2 < 64) {
                g_cmpSectionMask.fetch_or(std::uint64_t{ 1 } << a2, std::memory_order_relaxed);
            }
        }
    }

    // Round 7 taps - the inside of RepopulateItem. 155 pseudocode:
    //   RemoveItem(this, item)
    //   loop stacks: IsValidItem -> AddItemToData(this, item, stack, i)
    //   loop stacks: GetMergeableStackEntry -> PopulateComparisonInfoForItem
    // plus PopulateItemCardInfo (a ~3.8KB card builder with an ID of its own).
    // Nothing here can be located by VariantID except the last one, so the
    // callees are resolved at runtime by walking RepopulateItem's own body at
    // a fixed delta and checking the target's prologue bytes first. Deltas are
    // identical on NG984/AE221/AE240 (verified offline with every candidate's
    // prologue byte-identical across the three builds); OG keeps its own
    // table. Every target takes <= 4 register args, so one 4-arg shape fits.
    using T22_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
    std::uintptr_t g_repItemAddr = 0;

    // MUST return the original's rax: RepSubA dereferences what RepSubB
    // returns (call at +0xFF, `mov rcx,[rax]` right after). Dropping it once
    // crashed the game on the very first hotkey swap.
    std::uint64_t RunSub(TapIdx a_idx, std::uint64_t a1, std::uint64_t a2,
        std::uint64_t a3, std::uint64_t a4)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T22_t>(g_tapOrig[a_idx])(a1, a2, a3, a4);
        if (on) g_taps[a_idx].Record(NowUs() - t0);
        return r;
    }
    std::uint64_t HookedT22(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
    {
        return RunSub(kTapRepRemove, a1, a2, a3, a4);
    }
    std::uint64_t HookedT23(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
    {
        return RunSub(kTapRepA, a1, a2, a3, a4);
    }
    std::uint64_t HookedT24(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
    {
        return RunSub(kTapRepB, a1, a2, a3, a4);
    }
    std::uint64_t HookedT25(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
    {
        return RunSub(kTapRepC, a1, a2, a3, a4);
    }
    std::uint64_t HookedT26(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
    {
        return RunSub(kTapRepD, a1, a2, a3, a4);
    }
    std::uint64_t HookedT27(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
    {
        if (g_cardSkipMode != 0 && g_inRepopulateItem.load(std::memory_order_relaxed) > 0) {
            bool menuOpen = false;
            if (const auto* ui = RE::UI::GetSingleton()) {
                menuOpen = ui->GetMenuOpen<RE::PipboyMenu>();
            }
            if (g_cardSkipMode == 2 || !menuOpen) {
                g_cardSkipped.fetch_add(1, std::memory_order_relaxed);
                return 0;  // CommonLib declares this one void
            }
        }
        // Counted unconditionally: a rebuild triggered outside the equip
        // window (menu open, deferred job) is invisible to the per-equip
        // table and is exactly where the seconds-level stall should show up.
        const auto t0 = NowUs();
        const auto r = reinterpret_cast<T22_t>(g_tapOrig[kTapCardInfo])(a1, a2, a3, a4);
        const auto dt = NowUs() - t0;
        g_cardAllN.fetch_add(1, std::memory_order_relaxed);
        g_cardAllUs.fetch_add(dt, std::memory_order_relaxed);
        if (g_diagDepth.load(std::memory_order_relaxed) > 0) {
            g_taps[kTapCardInfo].Record(dt);
        }
        return r;
    }

    // Round 8: what happens OUTSIDE the EquipObject window. The measured equip
    // is only 20-100ms but the player sees a ~2s stall, so the missing time
    // must be work queued by the equip and consumed later - most likely the
    // category-wide rebuild: QueueItemCardRepopulate(WEAP) puts the category
    // in queuedRepopulateCategories and a JobListManager job then runs
    // RepopulateItemCardOnSection over every item of it. Both have IDs, and
    // these taps count every call (not just in-equip ones) so a rebuild that
    // lands on the next frame - or on a job thread - still shows up.
    using T23_t = std::uint64_t (*)(std::uint64_t, std::uint64_t);

    // The engine passes the category as a *reference*: the call site is
    //   mov dword [rsp+0x48], 2B ; lea r8,[rsp+0x48] ; lea rdx,[rsp+0x48] ; call
    // so a2 is the address, not the value. Accept both shapes.
    [[nodiscard]] std::uint32_t CatOf(std::uint64_t a2)
    {
        if (a2 > 0x1000) {
            return *reinterpret_cast<const std::uint32_t*>(a2);
        }
        return static_cast<std::uint32_t>(a2);
    }

    // Round 16 - who keeps raising the perk event? Instead of guessing, walk
    // the stack at the moment a perk sink queues a rebuild and name the module
    // behind every frame. A mod's own DLL in there settles it; an all
    // Fallout4.exe stack means it is plain engine behaviour.
    using CaptureStack_t = std::uint16_t(__stdcall*)(std::uint32_t, std::uint32_t,
        void**, std::uint32_t*);
    CaptureStack_t g_captureStack = nullptr;
    // Traces stay on while the perk flood is still being attributed to specific
    // mods; both stop on their own after the sample count (once per 300ms /
    // 250ms, so a normal session never fills the log).
    int            g_perkTraceMax = 24;
    int            g_verbose = 0;   // per-tap timing lines
    int            g_diagHooks = 1; // 0 = install no timing hooks at all (A/B switch)
    std::atomic<int>          g_perkTraceLeft{ 0 };
    std::atomic<std::int64_t> g_perkTraceLastUs{ 0 };
    std::atomic<std::int64_t> g_perkFired{ 0 };

    void FrameLabel(void* a_pc, char* a_out, std::size_t a_len)
    {
        HMODULE mod = nullptr;
        wchar_t wpath[MAX_PATH]{};
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(a_pc), &mod) && mod) {
            GetModuleFileNameW(mod, wpath, MAX_PATH);
            const auto* wbase = std::wcsrchr(wpath, L'\\');
            char name[MAX_PATH]{ "?" };
            WideCharToMultiByte(CP_UTF8, 0, wbase ? wbase + 1 : wpath, -1,
                name, sizeof(name), nullptr, nullptr);
            std::snprintf(a_out, a_len, "%s+0x%llX", name,
                static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(a_pc) -
                    reinterpret_cast<std::uintptr_t>(mod)));
        } else {
            std::snprintf(a_out, a_len, "0x%llX",
                static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(a_pc)));
        }
    }

    void TracePerkSource(int a_which)
    {
        g_perkFired.fetch_add(1, std::memory_order_relaxed);
        if (!g_captureStack || g_perkTraceMax <= 0) return;
        const auto now = NowUs();
        const auto prev = g_perkTraceLastUs.exchange(now, std::memory_order_relaxed);
        if (prev && now - prev < 300000) return;          // at most one per 300ms
        const auto left = g_perkTraceLeft.fetch_sub(1, std::memory_order_relaxed);
        if (left <= 0) return;

        void* frames[12]{};
        const auto n = g_captureStack(0, 12, frames, nullptr);
        char buf[896];
        std::size_t used = 0;
        buf[0] = '\0';
        for (std::uint16_t i = 0; i < n && i < 12; ++i) {
            char one[320];
            FrameLabel(frames[i], one, sizeof(one));
            const auto w = std::snprintf(buf + used, sizeof(buf) - used, "%s[%s]",
                used ? " " : "", one);
            if (w <= 0 || static_cast<std::size_t>(w) >= sizeof(buf) - used) break;
            used += static_cast<std::size_t>(w);
        }
        REX::INFO("WeaponSwapLagFix DIAG: perk sink #{} ({}) raised the category queue - {}",
            a_which, a_which == 0 ? "PerkEntryUpdated" : "PerkValueChanged", buf);
        if (left == 1) {
            REX::INFO("WeaponSwapLagFix DIAG: perk trace done ({} samples). The perk sinks "
                      "raised a rebuild {} times in this session - raise "
                      "[Diag] TracePerkSource for more",
                g_perkTraceMax, static_cast<long long>(g_perkFired.load(std::memory_order_relaxed)));
        }
    }

    // Round 18: the trace above showed the flood comes from Papyrus calling
    // AddPerk / RemovePerk on the player over and over. Timing tells us the
    // cost, but only the perk's name tells us whose script it is, so log the
    // perks themselves (CommonLib declares both functions, and the prologues
    // are identical on OG163/NG984/AE221/AE240).
    // The stall the player actually feels after spending a point does not
    // happen while the menu is up - it lands AFTER the perk menu and the
    // Pip-Boy are closed. So every menu open/close is stamped, and any
    // category rebuild that follows within 15s of a close is reported with the
    // delay, which is what ties the two together.
    std::atomic<std::int64_t> g_menuCloseUs{ 0 };
    void DropDamageCache();   // defined with the damage memo below
    // 0 = keep the memo across a perk purchase (smooth; a displayed damage
    //     number can lag by up to g_dmgTtlUs)
    // 1 = drop it, so the next rebuild is exact but costs the full ~860ms
    int g_flushOnAddPerk = 0;

    class MenuWatcher : public RE::BSTEventSink<RE::MenuOpenCloseEvent>
    {
    public:
        RE::BSEventNotifyControl ProcessEvent(const RE::MenuOpenCloseEvent& a_event,
            RE::BSTEventSource<RE::MenuOpenCloseEvent>*) override
        {
            const char* n = a_event.menuName.c_str();
            if (!n) return RE::BSEventNotifyControl::kContinue;
            const bool pipboy = std::strcmp(n, "PipboyMenu") == 0;
            const bool levelUp = std::strstr(n, "Level") != nullptr ||
                                 std::strstr(n, "Perk") != nullptr ||
                                 std::strstr(n, "Skill") != nullptr;
            if (!pipboy && !levelUp) return RE::BSEventNotifyControl::kContinue;
            if (a_event.opening) {
                g_menuCloseUs.store(0, std::memory_order_relaxed);
            } else {
                g_menuCloseUs.store(NowUs(), std::memory_order_relaxed);
            }
            REX::INFO("WeaponSwapLagFix DIAG: menu {} {}", n,
                a_event.opening ? "opened" : "closed");
            return RE::BSEventNotifyControl::kContinue;
        }
    };
    MenuWatcher g_menuWatcher;

    using TPerk_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    std::uintptr_t            g_origAddPerk = 0;
    std::uintptr_t            g_origRemovePerk = 0;
    std::atomic<std::int64_t> g_perkLogLastUs{ 0 };
    std::atomic<int>          g_perkLogLeft{ 0 };
    int                       g_perkLogMax = 40;

    // The interesting thing is *which* perks, not how often, so each perk is
    // reported once (the total call count is logged per equip instead).
    constexpr std::size_t kPerkSeenSlots = 96;
    std::atomic<std::uint64_t> g_perkSeen[kPerkSeenSlots]{};
    std::atomic<std::int64_t>  g_perkCalls{ 0 };
    std::atomic<int>           g_perkDistinct{ 0 };

    void LogPerkCall(const char* a_what, std::uint64_t a_actor, std::uint64_t a_perk,
        std::uint64_t a_rank)
    {
        if (g_perkLogMax <= 0) return;
        auto* player = RE::PlayerCharacter::GetSingleton();
        if (!player || a_actor != reinterpret_cast<std::uint64_t>(player)) return;
        g_perkCalls.fetch_add(1, std::memory_order_relaxed);

        std::uint32_t fid = 0;
        const char* edid = "";
        if (auto* p = reinterpret_cast<RE::BGSPerk*>(a_perk)) {
            fid = p->GetFormID();
            if (const auto* e = p->GetFormEditorID()) edid = e;
        }
        if (!fid) return;

        // Ranked by (formID, rank): spending a point on a perk the player
        // already has is a new rank, and that is exactly what a level-up looks
        // like, so it has to be reported again. RemovePerk has no rank - its
        // third argument is junk - and collapses to the formID alone.
        const bool adding = std::strcmp(a_what, "AddPerk") == 0;
        const auto rank = adding ? (a_rank & 0xFF) : 0;
        const auto key = (static_cast<std::uint64_t>(fid) << 8) | rank;
        bool fresh = false;
        const auto h = key * 0x9E3779B97F4A7C15ull;
        for (std::size_t k = 0; k < kPerkSeenSlots; ++k) {
            const auto s = (h + k * k) & (kPerkSeenSlots - 1);
            auto cur = g_perkSeen[s].load(std::memory_order_relaxed);
            if (cur == key) break;                       // already reported
            if (cur == 0) {
                if (g_perkSeen[s].compare_exchange_strong(cur, key, std::memory_order_relaxed)) {
                    fresh = true;
                    g_perkDistinct.fetch_add(1, std::memory_order_relaxed);
                }
                break;
            }
        }
        if (!fresh) return;
        // The level is printed alongside so a level-up session is obvious in
        // the log: every AddPerk from the perk menu carries the level it
        // happened at.
        const auto lvl = player->GetLevel();
        REX::INFO("WeaponSwapLagFix DIAG: {} - perk 0x{:08X} \"{}\" rank {} at level {} "
                  "thread {}", a_what, fid, edid, static_cast<std::uint32_t>(rank),
            static_cast<std::uint32_t>(lvl), static_cast<std::uint32_t>(GetCurrentThreadId()));
        // A genuine perk addition is the one event that can change a weapon's
        // displayed damage, so it is the natural place to invalidate the memo.
        // It is off by default, though: flushing guarantees that the rebuild
        // right after a level-up pays full price (~860ms), which is precisely
        // the stall being complained about. The memo only feeds
        // GetWeaponDisplayDamage - the number printed on the card, never the
        // damage actually dealt - so leaving it alone can only leave a DISPLAYED
        // number stale for at most g_dmgTtlUs. Set to 1 to prefer exactness
        // over smoothness.
        if (adding && g_flushOnAddPerk != 0) DropDamageCache();
    }

    std::uint64_t HookedT38(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {   // Actor::AddPerk(BGSPerk*, uint8_t rank)
        LogPerkCall("AddPerk", a1, a2, a3);
        return reinterpret_cast<TPerk_t>(g_origAddPerk)(a1, a2, a3);
    }
    std::uint64_t HookedT39(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {   // Actor::RemovePerk(BGSPerk*)
        LogPerkCall("RemovePerk", a1, a2, a3);
        return reinterpret_cast<TPerk_t>(g_origRemovePerk)(a1, a2, a3);
    }

    // Per-category timestamp of the last finished rebuild, for the throttle.
    std::atomic<std::int64_t> g_lastRebuildUs[64]{};
    std::atomic<int>          g_inCardRebuild{ 0 };
    // Memo hit/miss counters for GetWeaponDisplayDamage. They live here rather
    // than with the cache itself because the category-rebuild hook reports the
    // delta across one rebuild.
    std::atomic<std::int64_t> g_dmgHits{ 0 };
    std::atomic<std::int64_t> g_dmgMisses{ 0 };
    // Round 20: why a miss happened matters. "expired" = the entry was there
    // and just aged out (raise the TTL); "new key" = the weapon, its instance
    // data or the ammo really changed, which no TTL can help with.
    std::atomic<std::int64_t> g_dmgMissExpired{ 0 };
    std::atomic<std::int64_t> g_dmgMissNewKey{ 0 };
    std::atomic<int>          g_loopSuppressed{ 0 };
    std::atomic<int>          g_throttleSuppressed{ 0 };

    // ------------------------------------------------------------------ //
    // Round 20 - the precise fix, replacing the blunt rate limit.
    //
    // A weapon's displayed damage only goes through two entry points
    // (verified in the 155 PDB + confirmed at the call sites):
    //     0x23 kModAttackDamage        - GetWeaponDisplayDamage, FillDamageTypeInfo
    //     0x63 kModPlayerExplosionDamage - GetWeaponDisplayDamage
    // and the rest of the item card uses
    //     0x55 kModArmorRating         - FillResistTypeInfo, FillDamageTypeInfo
    //     0x1D kModSpellMagnitude      - the damage-type lambdas
    //     0x5D kModTypedAttackDamage   - the damage-type lambdas
    // Everything else (the ENM_* AP drain / movement perks, the REP_UTIL_*
    // reputation perks, ...) cannot change a single number on an item card,
    // yet each of them queues a full three-category rebuild that costs ~840ms
    // on the game thread.
    //
    // The event hands us the answer: PerkEntryUpdatedEvent carries the very
    // entry that changed (+0x08) and BGSEntryPointPerkEntry::GetEntryPoint is
    // just `movzx eax,[rcx+0x10]`. So we let the queue through only for the
    // five entry points above and drop the rest - no throttle, no staleness,
    // nothing to trade off.
    //
    // PerkValueChangedEvent has no entry (only { type, hOwner, pPerk, rank }),
    // so there we walk BGSPerk::perkEntries (+0x68) and use the same test.
    // ------------------------------------------------------------------ //
    int  g_perkEntryFilter = 1;
    // vtable slot addresses and the originals they held.
    std::uintptr_t g_perkSlot[2]{ 0, 0 };
    std::uintptr_t g_origPerkProcess[2]{ 0, 0 };
    // Set while an irrelevant perk event is being processed; the queue hook
    // checks it and returns without registering the category.
    thread_local int g_skipPerkQueue = 0;
    // ...and a relevant one must not be held back by the throttle, which only
    // exists to tame the spam. Real damage-perk changes are rare.
    thread_local int g_forcePerkQueue = 0;
    std::atomic<std::int64_t> g_perkPass{ 0 };
    std::atomic<std::int64_t> g_perkDrop{ 0 };
    std::atomic<std::int64_t> g_perkQueueSkipped{ 0 };
    std::atomic<int>          g_perkEntryLogLeft{ 0 };
    // Distribution of the entry points that were let through / dropped. If an
    // unexpected value shows up on the "passed" side it belongs in the
    // whitelist; if a rebuild ever feels stale this is where to look first.
    std::atomic<int>          g_epPassed[256]{};
    std::atomic<int>          g_epDropped[256]{};
    // How many rebuilds actually ran and what they cost, whatever the size -
    // the >=100ms line alone cannot show that they got cheap instead of gone.
    std::atomic<int>          g_rebuildCount{ 0 };
    std::atomic<std::int64_t> g_rebuildUs{ 0 };

    [[nodiscard]] bool EntryPointAffectsItemCard(std::uint8_t a_ep)
    {
        switch (a_ep) {
            case 0x1D:  // kModSpellMagnitude
            case 0x23:  // kModAttackDamage
            case 0x55:  // kModArmorRating
            case 0x5D:  // kModTypedAttackDamage
            case 0x63:  // kModPlayerExplosionDamage
                return true;
            default:
                return false;
        }
    }

    // A null or wild pointer means "do not touch vanilla behaviour".
    [[nodiscard]] bool EntryAffectsItemCard(std::uint64_t a_entry)
    {
        if (a_entry < 0x10000) return true;
        return EntryPointAffectsItemCard(*reinterpret_cast<const std::uint8_t*>(a_entry + 0x10));
    }

    [[nodiscard]] bool PerkAffectsItemCard(std::uint64_t a_perk)
    {
        if (a_perk < 0x10000) return true;
        // BGSPerk::perkEntries (@0x68): data @+0x00, size @+0x10.
        const auto data = *reinterpret_cast<const std::uintptr_t*>(a_perk + 0x68);
        const auto n = *reinterpret_cast<const std::uint32_t*>(a_perk + 0x78);
        if (!data || n == 0 || n > 64) return true;   // unknown shape - let it pass
        for (std::uint32_t i = 0; i < n; ++i) {
            const auto e = reinterpret_cast<std::uint64_t*>(data)[i];
            if (e >= 0x10000 &&
                EntryPointAffectsItemCard(*reinterpret_cast<const std::uint8_t*>(e + 0x10))) {
                return true;
            }
        }
        return false;
    }

    using PerkProcess_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);

    std::uint64_t RunPerkProcess(int a_which, std::uint64_t a1, std::uint64_t a2,
        std::uint64_t a3)
    {
        bool pass = true;
        std::uint8_t ep = 0xFF;
        if (g_perkEntryFilter != 0) {
            if (a_which == 0) {
                const auto entry = a2 ? *reinterpret_cast<const std::uint64_t*>(a2 + 8) : 0;
                if (entry >= 0x10000) {
                    ep = *reinterpret_cast<const std::uint8_t*>(entry + 0x10);
                }
                pass = EntryAffectsItemCard(entry);
                (pass ? g_epPassed : g_epDropped)[ep].fetch_add(1, std::memory_order_relaxed);
            } else {
                const auto perk = a2 ? *reinterpret_cast<const std::uint64_t*>(a2 + 8) : 0;
                pass = PerkAffectsItemCard(perk);
            }
            if (g_perkEntryLogLeft.load(std::memory_order_relaxed) > 0 &&
                g_perkEntryLogLeft.fetch_sub(1, std::memory_order_relaxed) > 0) {
                REX::INFO("WeaponSwapLagFix DIAG: perk event #{} entry point 0x{:02X} -> {}",
                    a_which, static_cast<std::uint32_t>(ep), pass ? "rebuild" : "dropped");
            }
        }
        if (pass) {
            g_perkPass.fetch_add(1, std::memory_order_relaxed);
            ++g_forcePerkQueue;
            const auto r = reinterpret_cast<PerkProcess_t>(g_origPerkProcess[a_which])(a1, a2, a3);
            --g_forcePerkQueue;
            return r;
        }
        // Still run the original - it does more than queueing - but make the
        // queue calls inside it no-ops for the duration.
        g_perkDrop.fetch_add(1, std::memory_order_relaxed);
        ++g_skipPerkQueue;
        const auto r = reinterpret_cast<PerkProcess_t>(g_origPerkProcess[a_which])(a1, a2, a3);
        --g_skipPerkQueue;
        return r;
    }

    std::uint64_t HookedPerkEntryUpdated(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        return RunPerkProcess(0, a1, a2, a3);
    }

    std::uint64_t HookedPerkValueChanged(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        return RunPerkProcess(1, a1, a2, a3);
    }

    std::uint64_t HookedT28(std::uint64_t a1, std::uint64_t a2)  // QueueItemCardRepopulate
    {
        // Round 20: a perk event that cannot touch an item card already told us
        // to ignore every category it queues.
        if (g_skipPerkQueue > 0) {
            g_perkQueueSkipped.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }
        // Round 10. The queue spam is NOT feedback from the rebuild
        // (BreakRebuildLoop fired zero times) - it comes from the two perk
        // sinks, which raise it about once a second for ever. The rebuild then
        // runs on the same thread that runs EquipObject, blocking it for
        // 0.75-1.0s. Rather than throttling blindly, rate-limit just the
        // perk-driven requests: they still get through often enough to keep
        // the cards correct, but not once per second.
        {
            const auto ret = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
            int which = -1;
            if (g_perkSink[0] && ret >= g_perkSink[0] && ret < g_perkSink[0] + 0x400) {
                which = 0;
            } else if (g_perkSink[1] && ret >= g_perkSink[1] && ret < g_perkSink[1] + 0x400) {
                which = 1;
            }
            if (which >= 0) {
                // Round 20: the sinks are now reached through our own vtable
                // slots, so a stack walk would only ever show this dll. The
                // question it answered is settled - the sources were the mods'
                // periodic RemovePerk/AddPerk.
                if (g_verbose != 0) TracePerkSource(which);
                if (g_forcePerkQueue > 0) {
                    // A perk that really can move a number on an item card is
                    // let through regardless of the throttle.
                    g_lastPerkQueueUs.store(NowUs(), std::memory_order_relaxed);
                }
                const auto now = NowUs();
                auto last = g_lastPerkQueueUs.load(std::memory_order_relaxed);
                if (last && now - last < g_perkQueueGapMs * 1000) {
                    g_perkDropped.fetch_add(1, std::memory_order_relaxed);
                    return 0;
                }
                g_lastPerkQueueUs.store(now, std::memory_order_relaxed);
            }
        }
        const auto cat = CatOf(a2);
        // Round 9 - break the self-feeding loop. Measured with no equip at all:
        // PerkEntryUpdatedEvent's sink (0xAD0100) queues 0x2B/0x1D/0x30 about
        // once a second and the consumer (caller RVA 0xACF30C) then spends
        // 0.75-2.35s rebuilding every weapon card. Rule A: a queue raised while
        // a rebuild is already running is dropped - rebuilding values is what
        // re-raises the perk event, so this is the loop's own feedback.
        if (g_breakLoop != 0 && g_inCardRebuild.load(std::memory_order_relaxed) > 0) {
            g_loopSuppressed.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }
        // Rule B: rate limit per category, for the case where the trigger is
        // external (a mod re-raising the event) rather than feedback.
        if (g_throttleMs > 0 && cat < 64) {
            const auto last = g_lastRebuildUs[cat].load(std::memory_order_relaxed);
            if (last && NowUs() - last < g_throttleMs * 1000) {
                g_throttleSuppressed.fetch_add(1, std::memory_order_relaxed);
                return 0;
            }
        }
        // The caller-RVA log that used to live here did its job (it named the
        // perk sinks as the source of the flood) and is now just log spam.
        // 0x2B = WEAP. Only skipped inside a player EquipObject for a weapon.
        if (g_skipCatQueue != 0 && g_diagDepth.load(std::memory_order_relaxed) > 0 &&
            a2 == 0x2B && g_equipFormType.load(std::memory_order_relaxed) == 0x2B) {
            g_catQueueSkipped.fetch_add(1, std::memory_order_relaxed);
            return 0;  // declared void in CommonLib
        }
        const auto t0 = NowUs();
        const auto r = reinterpret_cast<T23_t>(g_tapOrig[kTapQueueCard])(a1, a2);
        const auto dt = NowUs() - t0;
        if (a2 < 64) g_queueMask.fetch_or(std::uint64_t{ 1 } << a2, std::memory_order_relaxed);
        if (g_diagDepth.load(std::memory_order_relaxed) > 0) g_taps[kTapQueueCard].Record(dt);
        return r;
    }
    std::uint64_t HookedT29(std::uint64_t a1, std::uint64_t a2)  // RepopulateItemCardOnSection
    {
        const auto t0 = NowUs();
        // How much of this rebuild was damage recomputation, and how much of
        // that the memo absorbed - the one number that says whether the cache
        // is working where it actually matters.
        const auto hit0 = g_dmgHits.load(std::memory_order_relaxed);
        const auto mis0 = g_dmgMisses.load(std::memory_order_relaxed);
        g_inCardRebuild.fetch_add(1, std::memory_order_relaxed);
        const auto r = reinterpret_cast<T23_t>(g_tapOrig[kTapSecRepop])(a1, a2);
        g_inCardRebuild.fetch_sub(1, std::memory_order_relaxed);
        const auto dt = NowUs() - t0;
        const auto dmgHits = g_dmgHits.load(std::memory_order_relaxed) - hit0;
        const auto dmgMiss = g_dmgMisses.load(std::memory_order_relaxed) - mis0;
        const auto cat = CatOf(a2);
        if (cat < 64) g_lastRebuildUs[cat].store(NowUs(), std::memory_order_relaxed);
        g_secAllN.fetch_add(1, std::memory_order_relaxed);
        g_secAllUs.fetch_add(dt, std::memory_order_relaxed);
        // Round 20: unconditional totals. The per-rebuild line only fires above
        // 100ms, so on its own it cannot tell "gone" from "became cheap".
        g_rebuildCount.fetch_add(1, std::memory_order_relaxed);
        g_rebuildUs.fetch_add(dt, std::memory_order_relaxed);
        if (g_diagDepth.load(std::memory_order_relaxed) > 0) {
            g_taps[kTapSecRepop].Record(dt);
        }
        // Any single category rebuild worth more than half a millisecond is
        // printed straight away - in-equip or not - together with the caller's
        // RVA. The 0x2B (weapon) pass measures 0.75-1.1s and repeats roughly
        // once per second even with no equip happening, so the caller is what
        // tells us whether it is the deferred job, the menu, or a mod.
        // A finished rebuild is the single biggest stall in the whole pipeline
        // (~840ms measured), so it is always reported - this is the line that
        // tells us what a level-up or a perk purchase actually cost. The
        // caller RVA is dropped unless the timing tables are on.
        if (dt >= 100000) {
            const auto closed = g_menuCloseUs.load(std::memory_order_relaxed);
            if (closed) {
                const auto since = (NowUs() - closed) / 1000;
                if (since >= 0 && since < 15000) {
                    REX::INFO("WeaponSwapLagFix DIAG: category rebuild 0x{:X} took {}us - "
                              "{}ms after the menu closed "
                              "(damage {} hits / {} misses, thread {})",
                        static_cast<std::uint32_t>(cat), static_cast<long long>(dt),
                        static_cast<long long>(since), static_cast<long long>(dmgHits),
                        static_cast<long long>(dmgMiss),
                        static_cast<std::uint32_t>(GetCurrentThreadId()));
                    return r;
                }
            }
            REX::INFO("WeaponSwapLagFix DIAG: category rebuild 0x{:X} took {}us "
                      "(damage {} hits / {} misses, thread {})",
                static_cast<std::uint32_t>(cat), static_cast<long long>(dt),
                static_cast<long long>(dmgHits), static_cast<long long>(dmgMiss),
                static_cast<std::uint32_t>(GetCurrentThreadId()));
        }
        if (dt >= 500 && g_verbose != 0) {
            const auto ret = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
            const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            REX::INFO("WeaponSwapLagFix DIAG: RepopulateItemCardOnSection(0x{:X}) {}us "
                      "caller RVA 0x{:X} depth {} thread {}",
                static_cast<std::uint32_t>(a2), static_cast<long long>(dt), ret - base,
                g_diagDepth.load(std::memory_order_relaxed),
                static_cast<std::uint32_t>(GetCurrentThreadId()));
        }
        return r;
    }

    // Round 11: why is one item card ~4.2ms? The two helpers with a declared
    // signature are timed per call - if they add up to most of it, the cost is
    // per-field overhead (hash + allocate + notify, once per card field) and
    // not one expensive computation. InitializeItem / FillDamageTypeInfo are
    // deliberately NOT tapped: their signatures are unknown and forwarding a
    // float argument through an integer hook would corrupt the card.
    using T24_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    using T25_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, float, std::uint64_t);

    std::uint64_t HookedT30(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T24_t>(g_tapOrig[kTapBaseAdd])(a1, a2, a3);
        if (on) g_taps[kTapBaseAdd].Record(NowUs() - t0);
        return r;
    }
    std::uint64_t HookedT31(std::uint64_t a1, std::uint64_t a2, float a3, std::uint64_t a4)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T25_t>(g_tapOrig[kTapAddEntry])(a1, a2, a3, a4);
        if (on) g_taps[kTapAddEntry].Record(NowUs() - t0);
        return r;
    }

    // PipboyInventoryUtils::FillDamageTypeInfo(param_1, param_2, outArray) -
    // a free function with three pointer arguments, confirmed both by the 155
    // PDB text and by its call sites (`mov rcx,r12 / mov rdx,rax / lea r8,...`).
    // Safe to forward unchanged.
    std::uint64_t HookedT32(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T24_t>(g_tapOrig[kTapFillDmg])(a1, a2, a3);
        if (on) g_taps[kTapFillDmg].Record(NowUs() - t0);
        return r;
    }

    // PipboyInventoryUtils::FillResistTypeInfo(item, stack, outArray, float) -
    // also called straight from PopulateItemCardInfo (NG984: call at +0x74A of
    // the card builder). The float sits in xmm3, so the hook keeps it typed.
    using T26_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t, float);

    std::uint64_t HookedT33(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, float a4)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T26_t>(g_tapOrig[kTapFillRes])(a1, a2, a3, a4);
        if (on) g_taps[kTapFillRes].Record(NowUs() - t0);
        return r;
    }

    // Round 13. The 1-2s outliers are not Pip-Boy at all: the "Holster" tap is
    // Actor::HandleItemEquip(Actor*, bool) (named from the 155 PDB; the tap
    // name was a leftover guess). Its body is
    //   ... AIProcess::RequestLoadAnimationsForWeaponChange(proc, this)
    //   PollItemEquip(this, !loaded)          <- "Poll" = wait for the anim load
    //   lock / GetExtraData(0xCE) / unlock
    //   ExtraAnimGraphPreload::ReloadWeaponGraph(preload, this)
    // so a weapon whose behaviour graph is not resident blocks the main thread
    // while the animation set is loaded. These three say which step it is.
    std::uintptr_t g_holsterAddr = 0;

    std::uint64_t TimedPair(TapIdx a_idx, std::uint64_t a1, std::uint64_t a2)
    {
        const bool on = g_diagDepth.load(std::memory_order_relaxed) > 0;
        const auto t0 = on ? NowUs() : 0;
        const auto r = reinterpret_cast<T23_t>(g_tapOrig[a_idx])(a1, a2);
        const auto dt = on ? NowUs() - t0 : 0;
        if (on) {
            g_taps[a_idx].Record(dt);
            if (dt >= 20000) {
                REX::INFO("WeaponSwapLagFix DIAG: slow step {} {}us thread {}",
                    a_idx == kTapReqAnim ? "RequestLoadAnimationsForWeaponChange"
                        : a_idx == kTapPollEquip ? "PollItemEquip"
                        : "ReloadWeaponGraph",
                    static_cast<long long>(dt),
                    static_cast<std::uint32_t>(GetCurrentThreadId()));
            }
        }
        return r;
    }
    std::uint64_t HookedT34(std::uint64_t a1, std::uint64_t a2)
    {
        return TimedPair(kTapReqAnim, a1, a2);
    }
    std::uint64_t HookedT35(std::uint64_t a1, std::uint64_t a2)
    {
        return TimedPair(kTapPollEquip, a1, a2);
    }
    std::uint64_t HookedT36(std::uint64_t a1, std::uint64_t a2)
    {
        return TimedPair(kTapReloadGraph, a1, a2);
    }

    using T27_t = float (*)(std::uint64_t, std::uint64_t, float);

    // Round 14 - the actual fix. RepopulateItem rebuilds a card for EVERY
    // stack of the item, and each card starts with
    //   CombatFormulas::GetWeaponDisplayDamage(instance, ammo, healthPerc)
    // which costs milliseconds on its own. Switching back and forth between
    // the same weapons recomputes the same numbers over and over, so the
    // result is memoised here.
    //
    // Key: the weapon form, its instance data (the mods) and the ammo. The
    // third argument is a health percentage that comes from
    //   fVar21 = 1.0f;
    //   if (stack != null) fVar21 = ExtraDataList::GetHealthPerc(stack->extra);
    // i.e. the leftover durability value FO4 never shipped - it is 1.0 unless
    // a mod puts ExtraHealth on a stack. It still goes into the key, but it is
    // snapped to 1.0 when it is within a hair of it, so bit noise in an unused
    // register cannot silently defeat the whole cache. Anything meaningfully
    // different from 1.0 is counted and reported, so a durability mod would
    // show up in the log instead of being guessed at.
    //
    // The cache is dropped only on an armour equip - armour perks can carry
    // conditional weapon damage. Ammunition is NOT a flush: it is part of the
    // key, so swapping ammo simply produces a different entry. Everything else
    // is covered by the TTL.
    //
    // Slot count has to exceed the number of distinct items a category rebuild
    // walks (~205 measured), or entries evict each other and the rebuild pays
    // full price anyway - that was the original 128-slot bug.
    constexpr std::size_t kDmgSlots = 1024;
    std::atomic<std::uint64_t> g_dmgKeyA[kDmgSlots]{};   // object pointer
    std::atomic<std::uint64_t> g_dmgKeyB[kDmgSlots]{};   // instance ^ ammo ^ health bits
    std::atomic<std::uint64_t> g_dmgVal[kDmgSlots]{};    // bit-cast float
    std::atomic<std::int64_t>  g_dmgTime[kDmgSlots]{};   // when it was computed
    // (defined next to g_inCardRebuild - HookedT29 reads them too)
    std::atomic<std::int64_t>  g_dmgHealthOdd{ 0 };   // calls with a real health %
    std::atomic<std::uint64_t> g_dmgHealthSample{ 0 };

    // Measured: one card costs ~4ms and ~97% of it is GetWeaponDisplayDamage,
    // paid once per stack (a 13-stack weapon paid 54ms per swap). The inputs
    // are the weapon form, its instance data and the ammo, so the result is
    // memoised; 3s TTL plus a flush on any non-weapon equip keeps a level-up
    // or a perk change from leaving stale numbers on screen.
    int  g_cacheDamage = 1;
    // The TTL has to OUTLAST the real gap between two rebuilds, not the
    // nominal one. Rebuilds are driven by whatever the perk sinks raise, and
    // the measured spacing was 20-95s even with a 20s gap - so a gap-derived
    // 24s TTL still expired before the next rebuild and every one of the ~205
    // damage calls paid full price (~4.2ms each, ~860ms total).
    //
    // Measured spacing between two rebuilds in real play: 29s, 126s, 187s,
    // 253s, 350s, 430s. A TTL derived from the *nominal* gap (24s, then 120s)
    // therefore expired before almost every rebuild and all ~205 damage calls
    // paid full price. 600s covers all but the longest idle stretches.
    //
    // Freshness is not left to the TTL alone: a real AddPerk drops the cache
    // (see LogPerkCall), and ammo plus mod data are part of the key, so a
    // damage number can only be stale if a perk changed by some route that
    // bypasses Actor::AddPerk - which the traces show never happens.
    std::int64_t g_dmgTtlUs = 600000000;  // 600s

    void DropDamageCache()
    {
        for (std::size_t i = 0; i < kDmgSlots; ++i) {
            g_dmgKeyA[i].store(0, std::memory_order_relaxed);
        }
    }

    float HookedT37(std::uint64_t a1, std::uint64_t a2, float a3)
    {
        const auto obj = *reinterpret_cast<const std::uint64_t*>(a1);
        const auto inst = *reinterpret_cast<const std::uint64_t*>(a1 + 8);
        // ExtraDataList::GetHealthPerc answers with the SENTINEL -1.0 when a
        // stack carries no ExtraHealth (measured: every call in a vanilla-ish
        // save logs -1.0000), not with 1.0 as the decompilation's default
        // suggests. Both constants are snapped to their exact bit pattern so
        // noise in an unused register can never defeat the cache; anything
        // else would be a mod writing real durability, and gets reported.
        float hp = a3;
        if (hp > 0.9995f && hp < 1.0005f) {
            hp = 1.0f;
        } else if (hp > -1.0005f && hp < -0.9995f) {
            hp = -1.0f;
        } else {
            if (g_dmgHealthOdd.fetch_add(1, std::memory_order_relaxed) < 8) {
                std::uint64_t raw = 0;
                std::memcpy(&raw, &hp, sizeof(raw));
                g_dmgHealthSample.store(raw, std::memory_order_relaxed);
            }
        }
        std::uint32_t bits = 0;
        std::memcpy(&bits, &hp, sizeof(bits));
        const auto keyB = inst ^ a2 ^ bits;

        if (g_cacheDamage != 0 && obj != 0) {
            // Two-way: a rebuild walks ~205 distinct items, so a single slot
            // per hash loses too many entries to collisions.
            const auto h = obj ^ (keyB * 0x9E3779B97F4A7C15ull);
            const auto s0 = h & (kDmgSlots - 1);
            const auto s1 = (s0 + 1) & (kDmgSlots - 1);
            const auto now = NowUs();
            for (const auto slot : { s0, s1 }) {
                if (g_dmgKeyA[slot].load(std::memory_order_relaxed) == obj &&
                    g_dmgKeyB[slot].load(std::memory_order_relaxed) == keyB &&
                    now - g_dmgTime[slot].load(std::memory_order_relaxed) <= g_dmgTtlUs) {
                    const auto raw = g_dmgVal[slot].load(std::memory_order_relaxed);
                    float v = 0.0f;
                    std::memcpy(&v, &raw, sizeof(v));
                    g_dmgHits.fetch_add(1, std::memory_order_relaxed);
                    return v;
                }
            }
        }

        const float r = reinterpret_cast<T27_t>(g_tapOrig[kTapDispDmg])(a1, a2, a3);

        if (g_cacheDamage != 0 && obj != 0) {
            const auto h = obj ^ (keyB * 0x9E3779B97F4A7C15ull);
            const auto s0 = h & (kDmgSlots - 1);
            const auto s1 = (s0 + 1) & (kDmgSlots - 1);
            const auto now = NowUs();
            const auto slot =
                (g_dmgKeyA[s0].load(std::memory_order_relaxed) == obj &&
                    g_dmgKeyB[s0].load(std::memory_order_relaxed) == keyB) ||
                    g_dmgKeyA[s0].load(std::memory_order_relaxed) == 0 ||
                    now - g_dmgTime[s0].load(std::memory_order_relaxed) > g_dmgTtlUs
                    ? s0
                    : s1;
            // Classify BEFORE overwriting: was an identical key already
            // sitting here (it just aged out), or is this genuinely new?
            bool expired = false;
            for (const auto s : { s0, s1 }) {
                if (g_dmgKeyA[s].load(std::memory_order_relaxed) == obj &&
                    g_dmgKeyB[s].load(std::memory_order_relaxed) == keyB) {
                    expired = true;
                    break;
                }
            }
            (expired ? g_dmgMissExpired : g_dmgMissNewKey)
                .fetch_add(1, std::memory_order_relaxed);
            std::uint64_t raw = 0;
            std::memcpy(&raw, &r, sizeof(raw));
            g_dmgVal[slot].store(raw, std::memory_order_relaxed);
            g_dmgKeyB[slot].store(keyB, std::memory_order_relaxed);
            g_dmgTime[slot].store(now, std::memory_order_relaxed);
            g_dmgKeyA[slot].store(obj, std::memory_order_relaxed);
            g_dmgMisses.fetch_add(1, std::memory_order_relaxed);
        }
        return r;
    }
    //   CombatFormulas::GetWeaponDisplayDamage(&instance, ammo, healthPerc)
    // (arg 3 in xmm2, returns a float - so the hook has to keep both the
    // parameter and the return value typed). If this turns out to be most of
    // the 3.7ms, the fix is caching damage numbers instead of recomputing
    // them for every stack on every equip.
    std::uintptr_t g_fillDmgAddr = 0;

    // NOT tapped: PipboyInventoryData::InitializeItem. Its call site stages
    //   mov rcx,r15 / mov rdx,r12 / mov r9,r14
    //   mov [rsp+0x20],rax / mov [rsp+0x28],r13d
    // i.e. five or six arguments, two of them on the stack. A register-only
    // trampoline cannot forward stack arguments, so hooking it would corrupt
    // the call. Whatever it costs shows up as the unexplained remainder inside
    // ItemCardInfo.
    // FillResistTypeInfo takes a float (`..., out, fVar36`) and is not on this
    // path at all - no direct call to it was found in the whole .text.

    // rel32 target of the E8 at a_fn+a_off, or 0 when it is not a call.
    [[nodiscard]] std::uintptr_t CallTargetAt(std::uintptr_t a_fn, std::size_t a_off)
    {
        const auto* p = reinterpret_cast<const std::uint8_t*>(a_fn + a_off);
        if (p[0] != 0xE8) return 0;
        const auto tgt = a_fn + a_off + 5 + *reinterpret_cast<const std::int32_t*>(p + 1);
        return IsInsideExe(tgt) ? tgt : 0;
    }

    struct SubDef {
        TapIdx idx;
        void* hook;
        const char* tag;
        const std::uint8_t* pro;   // verified first, then copied into the
        std::size_t proLen;        // trampoline - same bytes, so it must end
        std::size_t delta;         // on an instruction boundary and be >= JMP14
    };

    // Prologue bytes used both as the verification and as the displaced
    // prefix; every one is position-independent and ends on an instruction
    // boundary (crash log/verify_pipboychain_v9.py).
    static constexpr std::uint8_t kProRepRemoveNG[]{
        0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x56, 0x41, 0x54, 0x41, 0x55, 0x41,
        0x57, 0x48, 0x8D, 0x6C, 0x24, 0xC9 };
    static constexpr std::uint8_t kProRepANG[]{
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x56, 0x57,
        0x41, 0x56 };
    static constexpr std::uint8_t kProRepBNG[]{
        0x48, 0x89, 0x5C, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x56,
        0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57 };
    static constexpr std::uint8_t kProRepCNG[]{
        0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x30,
        0x48, 0x8B, 0x99, 0xF8, 0x00, 0x00, 0x00 };
    static constexpr std::uint8_t kProRepDNG[]{
        0x48, 0x89, 0x5C, 0x24, 0x18, 0x48, 0x89, 0x6C, 0x24, 0x20, 0x56, 0x57,
        0x41, 0x57, 0x48, 0x83, 0xEC, 0x40 };

    const SubDef kSubsNG[] = {
        { kTapRepRemove, &HookedT22, "RepRemove", kProRepRemoveNG, sizeof(kProRepRemoveNG), 0x21 },
        { kTapRepA, &HookedT23, "RepSubA", kProRepANG, sizeof(kProRepANG), 0x67 },
        { kTapRepB, &HookedT24, "RepSubB", kProRepBNG, sizeof(kProRepBNG), 0x92 },
        { kTapRepC, &HookedT25, "RepSubC", kProRepCNG, sizeof(kProRepCNG), 0xF7 },
        { kTapRepD, &HookedT26, "RepSubD", kProRepDNG, sizeof(kProRepDNG), 0x108 },
    };

    static constexpr std::uint8_t kProRepRemoveOG[]{
        0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x56, 0x41, 0x54, 0x41, 0x55, 0x41,
        0x56, 0x48, 0x83, 0xEC, 0x50 };
    static constexpr std::uint8_t kProRepAOG[]{
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x56, 0x57,
        0x41, 0x56 };
    static constexpr std::uint8_t kProRepBOG[]{
        0x40, 0x53, 0x55, 0x41, 0x54, 0x41, 0x55, 0x48, 0x83, 0xEC, 0x38,
        0x48, 0x8B, 0x02 };
    static constexpr std::uint8_t kProRepCOG[]{
        0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10,
        0x48, 0x89, 0x70, 0x18, 0x57 };
    static constexpr std::uint8_t kProRepDOG[]{
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x7C, 0x24, 0x10, 0x41, 0x8B,
        0xC0, 0x45, 0x8B, 0xC8 };

    const SubDef kSubsOG[] = {
        { kTapRepRemove, &HookedT22, "RepRemove", kProRepRemoveOG, sizeof(kProRepRemoveOG), 0x12 },
        { kTapRepA, &HookedT23, "RepSubA", kProRepAOG, sizeof(kProRepAOG), 0x54 },
        { kTapRepB, &HookedT24, "RepSubB", kProRepBOG, sizeof(kProRepBOG), 0x73 },
        { kTapRepC, &HookedT25, "RepSubC", kProRepCOG, sizeof(kProRepCOG), 0x8A },
        { kTapRepD, &HookedT26, "RepSubD", kProRepDOG, sizeof(kProRepDOG), 0xEF },
    };

    static constexpr std::uint8_t kProCardInfoNG[]{
        0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18,
        0x48, 0x89, 0x50, 0x10, 0x48, 0x89, 0x48, 0x08, 0x55, 0x41, 0x57 };
    static constexpr std::uint8_t kProCardInfoOG[]{
        0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18,
        0x48, 0x89, 0x50, 0x10, 0x48, 0x89, 0x48, 0x08, 0x55 };

    // The equip pipeline's global recursive spin lock {owner:i32, count:i32}.
    // Resolved from the "lea rcx, lock; call acquire" pattern inside
    // EquipObject, then cross-verified by any lea to the same address
    // inside LoopEquip before the probe trusts it.
    std::uintptr_t g_equipLockAddr = 0;
    std::uintptr_t g_loopEquipAddr = 0;

    [[nodiscard]] std::uintptr_t FindLockRef(std::uintptr_t a_fn, std::size_t a_scanLen)
    {
        for (std::size_t off = 0x14; off + 12 < a_scanLen; ++off) {
            const auto* p = reinterpret_cast<const std::uint8_t*>(a_fn + off);
            // lea rcx, [rip+disp32]; call rel32
            if (p[0] == 0x48 && p[1] == 0x8D && p[2] == 0x0D && p[7] == 0xE8) {
                const auto lea = a_fn + off + 7 +
                    *reinterpret_cast<const std::int32_t*>(p + 3);
                if (IsInsideExe(lea)) return lea;
            }
        }
        return 0;
    }

    [[nodiscard]] bool ContainsLeaTo(std::uintptr_t a_fn, std::size_t a_scanLen,
        std::uintptr_t a_target)
    {
        for (std::size_t off = 0x14; off + 7 < a_scanLen; ++off) {
            const auto* p = reinterpret_cast<const std::uint8_t*>(a_fn + off);
            if (p[0] == 0x48 && p[1] == 0x8D && p[2] == 0x0D) {
                const auto lea = a_fn + off + 7 +
                    *reinterpret_cast<const std::int32_t*>(p + 3);
                if (lea == a_target) return true;
            }
        }
        return false;
    }

    // One-shot dump of the ActorEquipManagerEvent sink list - who actually
    // receives the two ~11ms event dispatches per equip. Layout comes from
    // the Notify decompilation: source = mgr+0x08, sink array data @
    // +0x20, count @ +0x30, sink vtable slot 1 is ProcessEvent.
    void DumpEquipSinks()
    {
        auto* mgr = RE::ActorEquipManager::GetSingleton();
        if (!mgr) return;
        const auto source = reinterpret_cast<std::uintptr_t>(mgr) + 0x08;
        const auto* sinkArr = *reinterpret_cast<void* const* const*>(source + 0x20);
        const auto count = *reinterpret_cast<std::uint32_t*>(source + 0x30);
        if (!sinkArr) {
            REX::INFO("WeaponSwapLagFix DIAG: equip-event sinks: <none registered>");
            return;
        }
        REX::INFO("WeaponSwapLagFix DIAG: equip-event sinks: {}", count);
        for (std::uint32_t i = 0; i < count && i < 64; ++i) {
            const auto sink = sinkArr[i];
            if (!sink) continue;
            const auto vtbl = *reinterpret_cast<void* const*>(sink);
            HMODULE mod = nullptr;
            wchar_t wpath[MAX_PATH]{};
            char name[MAX_PATH]{ "unknown" };
            if (GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCWSTR>(vtbl), &mod) && mod) {
                GetModuleFileNameW(mod, wpath, MAX_PATH);
                const auto* wbase = std::wcsrchr(wpath, L'\\');
                WideCharToMultiByte(CP_UTF8, 0, wbase ? wbase + 1 : wpath, -1,
                    name, sizeof(name), nullptr, nullptr);
            }
            REX::INFO("WeaponSwapLagFix DIAG: sink[{}] vtable 0x{:X} ({})",
                i, reinterpret_cast<std::uintptr_t>(vtbl), name);
        }
    }

    void DumpAndResetTaps(std::int64_t a_equipUs)
    {
        static constexpr const char* kNames[kTapCount] = {
            "ApplyToActor", "EquipApply", "WeightRecompute", "TailFn2",
            "FindEntry", "CollectItems", "InvUpdate", "Holster",
            "PostEquip", "ApplyQueue", "PerItemCheck", "LoopEquip",
            "PostApply", "Wrapper1", "LoopEquipMain", "LoopSlotResolve",
            "LoopCheck", "WrapperSlot", "InvBig", "EventNotify",
            "RepItem", "Comparison",
            "RepRemove", "RepSubA", "RepSubB", "RepSubC", "RepSubD", "ItemCardInfo",
            "QueueCard", "SecRepop", "BaseAdd", "AddEntry", "FillDmg", "FillRes",
            "ReqAnim", "PollEquip", "ReloadGraph", "DispDmg",
        };
        bool any = false;
        for (int i = 0; i < kTapCount; ++i) {
            if (g_taps[i].n.load() != 0) { any = true; break; }
        }
        if (any && g_verbose != 0) {
            char line[256];
            for (int i = 0; i < kTapCount; ++i) {
                const auto n = g_taps[i].n.load();
                if (!n) continue;
                std::snprintf(line, sizeof(line),
                    "WeaponSwapLagFix DIAG tap: %-14s n=%-4u total=%-7lld max=%lldus",
                    kNames[i], n,
                    static_cast<long long>(g_taps[i].totalUs.load()),
                    static_cast<long long>(g_taps[i].maxUs.load()));
                REX::INFO("{}", line);
            }
        }
        const auto loopSup = g_loopSuppressed.exchange(0, std::memory_order_relaxed);
        const auto thrSup = g_throttleSuppressed.exchange(0, std::memory_order_relaxed);
        // Round 20 counters - the fix itself, so they print even when quiet.
        {
            const auto pass = g_perkPass.exchange(0, std::memory_order_relaxed);
            const auto drop = g_perkDrop.exchange(0, std::memory_order_relaxed);
            const auto qskip = g_perkQueueSkipped.exchange(0, std::memory_order_relaxed);
            const auto rn = g_rebuildCount.exchange(0, std::memory_order_relaxed);
            const auto rus = g_rebuildUs.exchange(0, std::memory_order_relaxed);
            if (pass || drop || rn) {
                REX::INFO("WeaponSwapLagFix DIAG: perk events - {} rebuilt, {} dropped as "
                          "harmless ({} category queues suppressed)",
                    static_cast<long long>(pass), static_cast<long long>(drop),
                    static_cast<long long>(qskip));
                REX::INFO("WeaponSwapLagFix DIAG: category rebuilds since last equip: {} "
                          "({}ms total{})", rn, static_cast<long long>(rus / 1000),
                    rn ? "" : " - none");
                if (rn) {
                    REX::INFO("WeaponSwapLagFix DIAG: damage memo on rebuilds - {} hits, "
                              "{} misses ({} expired / {} new key)",
                        static_cast<long long>(g_dmgHits.load(std::memory_order_relaxed)),
                        static_cast<long long>(g_dmgMisses.load(std::memory_order_relaxed)),
                        static_cast<long long>(g_dmgMissExpired.exchange(0, std::memory_order_relaxed)),
                        static_cast<long long>(g_dmgMissNewKey.exchange(0, std::memory_order_relaxed)));
                }
            }
            // Which entry points the whitelist let through. Anything here that
            // is not 0x1D/0x23/0x55/0x5D/0x63 is a hole in the reasoning.
            if (pass) {
                char top[192];
                std::size_t used = 0;
                for (int i = 0; i < 256 && used < sizeof(top) - 12; ++i) {
                    const auto n = g_epPassed[i].exchange(0, std::memory_order_relaxed);
                    if (!n) continue;
                    const auto w = std::snprintf(top + used, sizeof(top) - used, "0x%02X:%d ",
                        static_cast<std::uint32_t>(i), n);
                    if (w > 0) used += static_cast<std::size_t>(w);
                }
                top[used ? used - 1 : 0] = '\0';
                REX::INFO("WeaponSwapLagFix DIAG: entry points let through: {}",
                    used ? top : "(none)");
            } else {
                for (int i = 0; i < 256; ++i) g_epPassed[i].store(0, std::memory_order_relaxed);
            }
        }
        if (g_verbose != 0) {  // everything below is measurement detail
        const auto perkSup = g_perkDropped.exchange(0, std::memory_order_relaxed);
        if (loopSup || thrSup || perkSup) {
            REX::INFO("WeaponSwapLagFix DIAG: category queues suppressed - loop {} throttle {} "
                      "perk {}", loopSup, thrSup, perkSup);
        }
        const auto catSkip = g_catQueueSkipped.exchange(0, std::memory_order_relaxed);
        if (catSkip) {
            REX::INFO("WeaponSwapLagFix DIAG: WEAP category rebuilds skipped this equip: {}",
                catSkip);
        }
        const auto skipped = g_cardSkipped.exchange(0, std::memory_order_relaxed);
        if (skipped || g_cardSkipMode != 0) {
            REX::INFO("WeaponSwapLagFix DIAG: item cards skipped this equip: {} (mode {})",
                skipped, g_cardSkipMode);
        }
        // Cumulative counters - the delta since the previous dump is work that
        // happened OUTSIDE any EquipObject call, i.e. the deferred rebuild.
        static std::uint32_t s_lastCardN = 0;
        static std::int64_t  s_lastCardUs = 0;
        static std::uint32_t s_lastSecN = 0;
        static std::int64_t  s_lastSecUs = 0;
        const auto cardN = g_cardAllN.load(std::memory_order_relaxed);
        const auto cardUs = g_cardAllUs.load(std::memory_order_relaxed);
        const auto secN = g_secAllN.load(std::memory_order_relaxed);
        const auto secUs = g_secAllUs.load(std::memory_order_relaxed);
        REX::INFO("WeaponSwapLagFix DIAG: since last equip - cards +{} ({}us), "
                  "category rebuilds +{} ({}us)",
            cardN - s_lastCardN, static_cast<long long>(cardUs - s_lastCardUs),
            secN - s_lastSecN, static_cast<long long>(secUs - s_lastSecUs));
        s_lastCardN = cardN; s_lastCardUs = cardUs;
        s_lastSecN = secN; s_lastSecUs = secUs;
        const auto qm = g_queueMask.exchange(0, std::memory_order_relaxed);
        if (qm) {
            char q[160];
            int n = std::snprintf(q, sizeof(q), "WeaponSwapLagFix DIAG: categories queued:");
            for (std::uint32_t i = 0; i < 64 && n < static_cast<int>(sizeof(q)) - 6; ++i) {
                if (qm & (std::uint64_t{ 1 } << i)) {
                    n += std::snprintf(q + n, sizeof(q) - n, " 0x%X", i);
                }
            }
            if (n > 0) REX::INFO("{}", q);
        }
        const auto mask = g_cmpSectionMask.exchange(0, std::memory_order_relaxed);
        if (mask) {
            char secs[192];
            int n = std::snprintf(secs, sizeof(secs), "WeaponSwapLagFix DIAG comparison sections:");
            for (std::uint32_t i = 0; i < 64 && n < static_cast<int>(sizeof(secs)) - 6; ++i) {
                if (mask & (std::uint64_t{ 1 } << i)) {
                    n += std::snprintf(secs + n, sizeof(secs) - n, " 0x%X", i);
                }
            }
            REX::INFO("{}", secs);
        }
        }  // g_verbose
        const auto churn = g_perkCalls.exchange(0, std::memory_order_relaxed);
        if (churn) {
            REX::INFO("WeaponSwapLagFix DIAG: perk churn since last equip - {} AddPerk/"
                      "RemovePerk calls on the player, {} distinct perks seen so far",
                static_cast<long long>(churn),
                static_cast<int>(g_perkDistinct.load(std::memory_order_relaxed)));
        }
        // The damage cache is a fix, not a measurement, so its hit rate is
        // reported even when the timing tables are quiet.
        if (g_cacheDamage != 0) {
            REX::INFO("WeaponSwapLagFix DIAG: weapon damage cache - hits {} misses {}",
                static_cast<long long>(g_dmgHits.exchange(0, std::memory_order_relaxed)),
                static_cast<long long>(g_dmgMisses.exchange(0, std::memory_order_relaxed)));
        }
        const auto odd = g_dmgHealthOdd.exchange(0, std::memory_order_relaxed);
        if (odd) {
            const auto raw = g_dmgHealthSample.load(std::memory_order_relaxed);
            float s = 0.0f;
            std::memcpy(&s, &raw, sizeof(s));
            REX::INFO("WeaponSwapLagFix DIAG: health%% is neither 1.0 nor the -1 sentinel "
                      "on {} calls (sample {:.4f}) - a durability mod is writing "
                      "ExtraHealth; those are cached per health value",
                static_cast<long long>(odd), s);
        }
        for (auto& t : g_taps) t.Reset();
    }

    bool HookedEquipObject(RE::ActorEquipManager* a_mgr, RE::Actor* a_actor,
        const RE::BGSObjectInstance& a_object, std::uint32_t a_stackID,
        std::uint32_t a_number, const RE::BGSEquipSlot* a_slot, bool a_queueEquip,
        bool a_forceEquip, bool a_playSounds, bool a_applyNow, bool a_locked)
    {
        const bool isPlayer = a_actor == RE::PlayerCharacter::GetSingleton();
        if (isPlayer) {
            static bool s_sinksDumped = false;
            if (!s_sinksDumped && g_verbose != 0) {
                s_sinksDumped = true;
                DumpEquipSinks();
            }
            // Lock contention probe: if another thread owns the equip spin
            // lock on entry, this equip is going to sleep-wait inside.
            if (g_equipLockAddr) {
                const auto owner = *reinterpret_cast<volatile std::int32_t*>(g_equipLockAddr);
                const auto me = static_cast<std::int32_t>(GetCurrentThreadId());
                if (owner != 0 && owner != me) {
                    REX::INFO("WeaponSwapLagFix DIAG: equip lock held by thread {} on entry",
                        owner);
                }
            }
            g_diagDepth.fetch_add(1, std::memory_order_relaxed);
            if (a_object.object) {
                const auto ft = static_cast<std::uint32_t>(
                    std::to_underlying(a_object.object->GetFormType()));
                g_equipFormType.store(ft, std::memory_order_relaxed);
                // No flush here any more. Measured: 27 of 88 player equips in
                // one session were armour (0x1D), so flushing on armour wiped
                // the cache constantly and the next rebuild paid full price
                // again (hits 0 / misses 203). Armour perks that alter weapon
                // damage are rare enough that the TTL covers them: a stale
                // number can survive g_dmgTtlUs at most.
            }
        }
        const std::int64_t t0 = isPlayer ? NowUs() : 0;
        const auto result = g_origEquipObject(a_mgr, a_actor, a_object, a_stackID,
            a_number, a_slot, a_queueEquip, a_forceEquip, a_playSounds, a_applyNow, a_locked);
        if (isPlayer) {
            const auto dt = NowUs() - t0;
            g_diagDepth.fetch_sub(1, std::memory_order_relaxed);
            // Outermost player equip finished: run the deferred tail work
            // once. The original functions are reached through the tap
            // trampolines, so this does not re-enter the defer branches.
            if (g_deferActive
                && g_diagDepth.load(std::memory_order_relaxed) == 0
                && (g_deferWeightDirty || g_deferMoveDirty)) {
                const auto player =
                    reinterpret_cast<std::uint64_t>(RE::PlayerCharacter::GetSingleton());
                std::int64_t tw = 0, tm = 0;
                if (g_deferWeightDirty && g_tapOrig[kTapWeightRecompute]) {
                    const auto t1 = NowUs();
                    g_deferWeight =
                        reinterpret_cast<T2_t>(g_tapOrig[kTapWeightRecompute])(player);
                    tw = NowUs() - t1;
                    g_deferWeightDirty = false;
                }
                if (g_deferMoveDirty && g_tapOrig[kTapTailFn2]) {
                    const auto t2 = NowUs();
                    reinterpret_cast<T3_t>(g_tapOrig[kTapTailFn2])(player);
                    tm = NowUs() - t2;
                    g_deferMoveDirty = false;
                }
                REX::INFO("WeaponSwapLagFix DIAG: defer flush weight={}us move={}us", tw, tm);
            }
            const auto* form = a_object.object;
            const bool pipboy = RE::UI::GetSingleton()
                && RE::UI::GetSingleton()->GetMenuOpen<RE::PipboyMenu>();
            REX::INFO("WeaponSwapLagFix DIAG: EquipObject \"{}\" (type 0x{:X}) {}us "
                       "pipboy={} queue={} applyNow={} result={}",
                form ? std::string_view{ RE::TESFullName::GetFullName(*form) } : std::string_view{ "<null>" },
                form ? std::to_underlying(form->GetFormType()) : 0,
                dt, pipboy, a_queueEquip, a_applyNow, result);
            DumpAndResetTaps(dt);
        }
        return result;
    }

    bool InstallEquipTaps()
    {
        if (g_diagHooks == 0) {
            REX::INFO("WeaponSwapLagFix DIAG: DiagTaps=0 - equip pipeline taps not installed");
            return false;
        }
        struct TapDef {
            TapIdx idx;
            void* hook;
            const std::uint8_t* sig;
            std::size_t sigLen;
            const SigAnchor* anchors;
            std::size_t nAnchors;
        };
        // All signatures offline-verified unique on NG984/AE221/AE240; on OG
        // some layouts differ - those taps simply stay off (logged).
        static constexpr std::uint8_t kSigApplyToActor[]{
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57,
            0x41, 0x54, 0x41, 0x55, 0x41, 0x56 };
        static constexpr std::uint8_t kA1[]{ 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0x90 };
        static constexpr std::uint8_t kA2[]{ 0x48, 0x81, 0xEC, 0x70, 0x01, 0x00, 0x00 };
        static constexpr std::uint8_t kA3[]{ 0x4C, 0x8B, 0xF9, 0x65, 0x48, 0x8B, 0x04,
            0x25, 0x58, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xE2 };
        static constexpr SigAnchor kAnchApplyToActor[]{
            { 14, kA1, sizeof(kA1) }, { 21, kA2, sizeof(kA2) }, { 35, kA3, sizeof(kA3) },
        };

        static constexpr std::uint8_t kSigEquipApply[]{
            0x48, 0x8B, 0xC4, 0x48, 0x89, 0x68, 0x20, 0x56, 0x57, 0x41, 0x56,
            0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00 };
        static constexpr std::uint8_t kA4[]{ 0x45, 0x0F, 0xB6, 0xF1, 0x49, 0x8B, 0xF0, 0x48, 0x8B, 0xFA };
        static constexpr SigAnchor kAnchEquipApply[]{ { 18, kA4, sizeof(kA4) } };

        static constexpr std::uint8_t kSigWeight[]{
            0x40, 0x53, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x48,
            0x48, 0x8B, 0x99, 0xF8, 0x00, 0x00, 0x00 };
        static constexpr std::uint8_t kA5[]{ 0x4C, 0x8B, 0xF1, 0x0F, 0x29, 0x74, 0x24, 0x30 };
        static constexpr SigAnchor kAnchWeight[]{ { 15, kA5, sizeof(kA5) } };

        static constexpr std::uint8_t kSigTailFn2[]{
            0x40, 0x53, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x81, 0x00, 0x03, 0x00, 0x00 };
        static constexpr std::uint8_t kA6[]{ 0x48, 0x8B, 0xD9, 0x48, 0x85, 0xC0, 0x0F, 0x84 };
        static constexpr SigAnchor kAnchTailFn2[]{ { 16, kA6, sizeof(kA6) } };

        static constexpr std::uint8_t kSigFindEntry[]{
            0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xDA,
            0x48, 0x85, 0xD2, 0x74, 0x44 };
        static constexpr std::uint8_t kA7[]{ 0x48, 0x8B, 0x81, 0xF8, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0 };
        static constexpr SigAnchor kAnchFindEntry[]{ { 14, kA7, sizeof(kA7) } };

        static constexpr std::uint8_t kSigCollectItems[]{
            0x4C, 0x89, 0x44, 0x24, 0x18, 0x41, 0x54, 0x41, 0x55,
            0x48, 0x83, 0xEC, 0x58, 0x48, 0x83, 0x79, 0x08, 0x00 };
        static constexpr std::uint8_t kA8[]{ 0x4C, 0x8B, 0xE2, 0x4C, 0x8B, 0xE9, 0x0F, 0x84 };
        static constexpr SigAnchor kAnchCollectItems[]{ { 18, kA8, sizeof(kA8) } };

        static constexpr std::uint8_t kSigInvUpdate[]{
            0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x53, 0x10, 0x53, 0x55, 0x56,
            0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x78 };
        static constexpr std::uint8_t kA9[]{ 0x4C, 0x8B, 0xE9, 0x65, 0x48 };
        static constexpr SigAnchor kAnchInvUpdate[]{ { 27, kA9, sizeof(kA9) } };

        static constexpr std::uint8_t kSigHolster[]{
            0x48, 0x89, 0x5C, 0x24, 0x10, 0x56, 0x48, 0x83, 0xEC, 0x20,
            0x48, 0x83, 0xB9, 0x00, 0x03, 0x00, 0x00, 0x00 };
        static constexpr std::uint8_t kA10[]{ 0x0F, 0xB6, 0xDA, 0x48, 0x8B, 0xF1, 0x0F, 0x84 };
        static constexpr SigAnchor kAnchHolster[]{ { 18, kA10, sizeof(kA10) } };

        static constexpr std::uint8_t kSigPostEquip[]{
            0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20,
            0x48, 0x8B, 0xB9, 0x00, 0x03, 0x00, 0x00 };
        static constexpr std::uint8_t kA11[]{ 0x48, 0x8B, 0xF1, 0x48, 0x85, 0xFF, 0x0F, 0x84 };
        static constexpr SigAnchor kAnchPostEquip[]{ { 17, kA11, sizeof(kA11) } };

        static constexpr std::uint8_t kSigApplyQueue[]{
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10,
            0x57, 0x48, 0x83, 0xEC, 0x40 };
        static constexpr std::uint8_t kA12[]{ 0x48, 0x83, 0xB9, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x49, 0x8B, 0xF0 };
        static constexpr SigAnchor kAnchApplyQueue[]{ { 15, kA12, sizeof(kA12) } };

        // Round 2: EquipApply / ApplyToActor drill-down (offline-verified
        // unique on NG984/AE221/AE240).
        static constexpr std::uint8_t kSigPerItemCheck[]{
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10,
            0x48, 0x89, 0x74, 0x24, 0x18, 0x57 };
        static constexpr std::uint8_t kA13[]{ 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0xE9, 0x49, 0x8B, 0xF0 };
        static constexpr SigAnchor kAnchPerItemCheck[]{ { 16, kA13, sizeof(kA13) } };

        static constexpr std::uint8_t kSigLoopEquip[]{
            0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x18, 0x55, 0x57,
            0x41, 0x56, 0x48, 0x83, 0xEC, 0x70 };
        static constexpr std::uint8_t kA14[]{ 0x45, 0x8B, 0xF1, 0x49, 0x8B, 0xD8, 0x48, 0x8B, 0xFA };
        static constexpr SigAnchor kAnchLoopEquip[]{ { 15, kA14, sizeof(kA14) } };

        static constexpr std::uint8_t kSigPostApply[]{
            0x40, 0x53, 0x55, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x50,
            0x48, 0x8B, 0xE9, 0x41, 0x8B, 0xD8 };
        static constexpr std::uint8_t kA15[]{ 0x48, 0x8B, 0x0A, 0x4C, 0x8B, 0xF2, 0x48, 0x85, 0xC9 };
        static constexpr SigAnchor kAnchPostApply[]{ { 15, kA15, sizeof(kA15) } };

        static constexpr std::uint8_t kSigWrapper1[]{
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20,
            0x48, 0x8B, 0xD9, 0x41, 0x8B, 0xF8 };
        static constexpr std::uint8_t kA16[]{ 0x48, 0x8B, 0x89, 0xF8, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC9 };
        static constexpr SigAnchor kAnchWrapper1[]{ { 16, kA16, sizeof(kA16) } };

        // Round 3: LoopEquip drill-down. EventNotify (0xC63450) cannot be
        // signature-located - BSTEventSource template, 152 identical
        // instances in .text - its share is inferred from the difference.
        static constexpr std::uint8_t kSigLoopEquipMain[]{
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x4C, 0x89, 0x44, 0x24, 0x18,
            0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56 };
        static constexpr std::uint8_t kA17[]{ 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00 };
        static constexpr SigAnchor kAnchLoopEquipMain[]{ { 19, kA17, sizeof(kA17) } };

        static constexpr std::uint8_t kSigLoopSlotResolve[]{
            0x48, 0x89, 0x5C, 0x24, 0x18, 0x56, 0x57, 0x41, 0x56,
            0x48, 0x83, 0xEC, 0x20, 0x45, 0x33, 0xF6 };
        static constexpr std::uint8_t kA18[]{ 0x49, 0x8B, 0xF0, 0x4C, 0x89, 0x74, 0x24, 0x48, 0x48, 0x8B, 0xDA, 0x41, 0x8B, 0xFE };
        static constexpr SigAnchor kAnchLoopSlotResolve[]{ { 16, kA18, sizeof(kA18) } };

        static constexpr std::uint8_t kSigLoopCheck[]{
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20,
            0x0F, 0xB6, 0x42, 0x1A };
        static constexpr std::uint8_t kA19[]{ 0x48, 0x8B, 0xF9, 0x83, 0xC0, 0xE6, 0xB3, 0x01, 0x83, 0xF8, 0x19, 0x77 };
        static constexpr SigAnchor kAnchLoopCheck[]{ { 14, kA19, sizeof(kA19) } };

        static constexpr std::uint8_t kSigWrapperSlot[]{
            0x40, 0x53, 0x57, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x30,
            0x49, 0x8B, 0x08, 0x33, 0xDB };
        static constexpr std::uint8_t kA20[]{ 0x49, 0x8B, 0xF8, 0x4C, 0x8B, 0xF2, 0x0F, 0xB6, 0x41, 0x1A, 0x83, 0xE8 };
        static constexpr SigAnchor kAnchWrapperSlot[]{ { 14, kA20, sizeof(kA20) } };

        // Round 4: the equipped-array editor inside LoopEquipMain. Apply2
        // (0xC27EE0) cannot be safely entry-patched - its prologue opens
        // with a rel32 je - its share shows up in the LoopEquipMain
        // difference.
        static constexpr std::uint8_t kSigInvBig[]{
            0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x4B, 0x08, 0x57, 0x41, 0x57,
            0x48, 0x81, 0xEC, 0x98, 0x00, 0x00, 0x00 };
        static constexpr std::uint8_t kA21[]{ 0x48, 0x83, 0x79, 0x08, 0x00, 0x49, 0x8B, 0xF9, 0x49, 0x8B, 0xC0 };
        static constexpr SigAnchor kAnchInvBig[]{ { 17, kA21, sizeof(kA21) } };

        const TapDef defs[] = {
            { kTapApplyToActor,   &HookedT0, kSigApplyToActor, sizeof(kSigApplyToActor), kAnchApplyToActor, std::size(kAnchApplyToActor) },
            { kTapEquipApply,     &HookedT1, kSigEquipApply,   sizeof(kSigEquipApply),   kAnchEquipApply,   std::size(kAnchEquipApply) },
            { kTapWeightRecompute,&HookedT2, kSigWeight,       sizeof(kSigWeight),       kAnchWeight,       std::size(kAnchWeight) },
            { kTapTailFn2,        &HookedT3, kSigTailFn2,      sizeof(kSigTailFn2),      kAnchTailFn2,      std::size(kAnchTailFn2) },
            { kTapCollectItems,   &HookedT5, kSigCollectItems, sizeof(kSigCollectItems), kAnchCollectItems, std::size(kAnchCollectItems) },
            { kTapInvUpdate,      &HookedT6, kSigInvUpdate,    sizeof(kSigInvUpdate),    kAnchInvUpdate,    std::size(kAnchInvUpdate) },
            { kTapHolster,        &HookedT7, kSigHolster,      sizeof(kSigHolster),      kAnchHolster,      std::size(kAnchHolster) },
            { kTapPostEquip,      &HookedT8, kSigPostEquip,    sizeof(kSigPostEquip),    kAnchPostEquip,    std::size(kAnchPostEquip) },
            { kTapApplyQueue,     &HookedT9, kSigApplyQueue,   sizeof(kSigApplyQueue),   kAnchApplyQueue,   std::size(kAnchApplyQueue) },
            { kTapPerItemCheck,   &HookedT10, kSigPerItemCheck, sizeof(kSigPerItemCheck), kAnchPerItemCheck, std::size(kAnchPerItemCheck) },
            { kTapLoopEquip,      &HookedT11, kSigLoopEquip,    sizeof(kSigLoopEquip),    kAnchLoopEquip,    std::size(kAnchLoopEquip) },
            { kTapPostApply,      &HookedT12, kSigPostApply,    sizeof(kSigPostApply),    kAnchPostApply,    std::size(kAnchPostApply) },
            { kTapWrapper1,       &HookedT13, kSigWrapper1,     sizeof(kSigWrapper1),     kAnchWrapper1,     std::size(kAnchWrapper1) },
            { kTapLoopEquipMain,  &HookedT14, kSigLoopEquipMain, sizeof(kSigLoopEquipMain), kAnchLoopEquipMain, std::size(kAnchLoopEquipMain) },
            { kTapLoopSlotResolve,&HookedT15, kSigLoopSlotResolve, sizeof(kSigLoopSlotResolve), kAnchLoopSlotResolve, std::size(kAnchLoopSlotResolve) },
            { kTapLoopCheck,      &HookedT16, kSigLoopCheck,    sizeof(kSigLoopCheck),    kAnchLoopCheck,    std::size(kAnchLoopCheck) },
            { kTapWrapperSlot,    &HookedT17, kSigWrapperSlot,  sizeof(kSigWrapperSlot),  kAnchWrapperSlot,  std::size(kAnchWrapperSlot) },
            { kTapInvBig,         &HookedT18, kSigInvBig,       sizeof(kSigInvBig),       kAnchInvBig,       std::size(kAnchInvBig) },
        };

        int installed = 0;
        for (const auto& d : defs) {
            // FindEntry is deliberately absent: its first clean >=14B
            // boundary is unreachable - the prologue carries a rel8 je at
            // +12 (null-form early-out), and displaced bytes re-executed in
            // the trampoline would jump into garbage on that path.
            const auto addr = ScanTextSig(d.sig, d.sigLen, d.anchors, d.nAnchors,
                true, "EquipTap");
            if (!addr) {
                REX::INFO("WeaponSwapLagFix DIAG: tap idx {} not found (layout differs), skipped",
                    static_cast<int>(d.idx));
                continue;
            }
            if (d.idx == kTapLoopEquip) g_loopEquipAddr = addr;
            if (d.idx == kTapHolster) g_holsterAddr = addr;
            const auto stub = PatchFuncEntry(addr, d.sigLen, d.hook, "EquipTap");
            if (!stub) continue;
            g_tapOrig[d.idx] = stub;
            ++installed;
        }

        // Round 13: the three steps inside Actor::HandleItemEquip. Same
        // deltas on every build; prologues byte-identical on NG984/AE221/
        // AE240, with an OG variant for two of them.
        if (g_holsterAddr) {
            struct HieDef {
                TapIdx idx; void* hook; const char* tag;
                const std::uint8_t* ng; std::size_t ngLen;
                const std::uint8_t* og; std::size_t ogLen;
                std::size_t delta;
            };
            static constexpr std::uint8_t kPReqAnim[]{
                0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18,
                0x48, 0x89, 0x74, 0x24, 0x20, 0x57, 0x48, 0x83, 0xEC, 0x20 };
            static constexpr std::uint8_t kPReqAnimOG[]{
                0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18,
                0x57, 0x48, 0x83, 0xEC, 0x20 };
            static constexpr std::uint8_t kPPoll[]{
                0x40, 0x55, 0x53, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xB9,
                0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00 };
            static constexpr std::uint8_t kPReload[]{
                0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x10, 0x57,
                0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00 };
            static constexpr std::uint8_t kPReloadOG[]{
                0x40, 0x55, 0x53, 0x57, 0x48, 0x8B, 0xEC,
                0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00 };
            const HieDef hies[] = {
                { kTapReqAnim, &HookedT34, "RequestLoadAnimationsForWeaponChange",
                  kPReqAnim, sizeof(kPReqAnim), kPReqAnimOG, sizeof(kPReqAnimOG), 0x93 },
                { kTapPollEquip, &HookedT35, "PollItemEquip",
                  kPPoll, sizeof(kPPoll), kPPoll, sizeof(kPPoll), 0xA0 },
                { kTapReloadGraph, &HookedT36, "ReloadWeaponGraph",
                  kPReload, sizeof(kPReload), kPReloadOG, sizeof(kPReloadOG), 0xDE },
            };
            for (const auto& h : hies) {
                const auto tgt = CallTargetAt(g_holsterAddr, h.delta);
                if (!tgt) {
                    REX::INFO("WeaponSwapLagFix DIAG: {} - no call at HandleItemEquip+0x{:X}",
                        h.tag, h.delta);
                    continue;
                }
                const std::uint8_t* pro = h.ng;
                std::size_t len = h.ngLen;
                if (!VerifyBytes(tgt, pro, len)) {
                    pro = h.og; len = h.ogLen;
                    if (!VerifyBytes(tgt, pro, len)) {
                        REX::INFO("WeaponSwapLagFix DIAG: {} - prologue mismatch, skipped", h.tag);
                        continue;
                    }
                }
                const auto stub = PatchFuncEntry(tgt, len, h.hook, h.tag);
                if (!stub) continue;
                g_tapOrig[h.idx] = stub;
                REX::INFO("WeaponSwapLagFix DIAG: {} tap @ 0x{:X} (HandleItemEquip+0x{:X}, "
                          "{} bytes)", h.tag, tgt, h.delta, len);
                ++installed;
            }
        }

        // EventNotify instance: the BSTEventSource<ActorEquipManagerEvent>
        // Notify body is a shared template (152 identical copies, impossible
        // to signature-locate). Instead scan LoopEquip's body for the rel32
        // call whose target matches the known Notify prologue - the call is
        // verified against the offline disassembly on every runtime family.
        if (g_loopEquipAddr) {
            static constexpr std::uint8_t kProEventNotify[]{
                0x48, 0x8B, 0xC4, 0x57, 0x41, 0x54, 0x48, 0x83, 0xEC, 0x58,
                0x48, 0x89, 0x58, 0x08 };
            for (std::size_t off = 0x14; off < 0x200; ++off) {
                const auto* p = reinterpret_cast<const std::uint8_t*>(g_loopEquipAddr + off);
                if (p[0] != 0xE8) continue;
                const auto rel = *reinterpret_cast<const std::int32_t*>(p + 1);
                const auto tgt = g_loopEquipAddr + off + 5 + rel;
                if (!IsInsideExe(tgt) || !VerifyBytes(tgt, kProEventNotify, sizeof(kProEventNotify))) {
                    continue;
                }
                const auto stub = PatchFuncEntry(tgt, sizeof(kProEventNotify),
                    &HookedT19, "EventNotifyTap");
                if (stub) {
                    g_tapOrig[kTapEventNotify] = stub;
                    REX::INFO("WeaponSwapLagFix DIAG: EventNotify instance hooked @ 0x{:X} "
                              "(resolved from LoopEquip+0x{:X})", tgt, off);
                    ++installed;
                }
                break;
            }
        }
        REX::INFO("WeaponSwapLagFix DIAG: {} equip taps installed", installed);

        // CalcEquippedWeight OG fallback: the NG/AE signature (kSigWeight)
        // never matches OG's codegen family. OG shares its codegen with the
        // 155 PDB build, whose prologue (offline-verified unique on OG163,
        // hook lands on the clean 20-byte boundary before the movaps pair)
        // works directly.
        if (!g_tapOrig[kTapWeightRecompute]) {
            static constexpr std::uint8_t kSigWeightOG[]{
                0x48, 0x8B, 0xC4, 0x48, 0x89, 0x68, 0x20, 0x41, 0x56,
                0x48, 0x83, 0xEC, 0x40, 0x4C, 0x8B, 0xB1, 0xF8, 0x00, 0x00, 0x00 };
            static constexpr std::uint8_t kA5OG[]{
                0x0F, 0x29, 0x70, 0xE8, 0x0F, 0x57, 0xF6, 0x48, 0x8B, 0xE9 };
            static constexpr SigAnchor kAnchWeightOG[]{ { 20, kA5OG, sizeof(kA5OG) } };
            const auto addr = ScanTextSig(kSigWeightOG, sizeof(kSigWeightOG),
                kAnchWeightOG, std::size(kAnchWeightOG), true, "WeightOG");
            if (addr) {
                const auto stub = PatchFuncEntry(addr, sizeof(kSigWeightOG), &HookedT2,
                    "WeightOG");
                if (stub) {
                    g_tapOrig[kTapWeightRecompute] = stub;
                    REX::INFO("WeaponSwapLagFix DIAG: CalcEquippedWeight (OG prologue) "
                              "hooked @ 0x{:X}", addr);
                }
            }
        }

        // Defer fix needs both tail hooks; without them everything runs
        // vanilla (per-tap skips are independent and harmless).
        g_deferActive = g_tapOrig[kTapWeightRecompute] && g_tapOrig[kTapTailFn2];
        REX::INFO("WeaponSwapLagFix DIAG: equip defer fix {}",
            g_deferActive ? "ACTIVE" : "inactive (weight/movement hook missing)");
        return installed > 0;
    }

    // Install a two-argument member function the address library knows by ID.
    // Prologue must match before anything is patched, and the displaced prefix
    // must be >= JMP14 and end on an instruction boundary.
    bool InstallIdTap(TapIdx a_idx, REL::VariantID a_id, void* a_hook,
        const std::uint8_t* a_ng, std::size_t a_ngLen,
        const std::uint8_t* a_og, std::size_t a_ogLen, const char* a_tag)
    {
        REL::Relocation<std::uintptr_t> rel{ a_id };
        const auto addr = rel.address();
        if (!addr) {
            REX::INFO("WeaponSwapLagFix DIAG: {} ID unresolvable, tap skipped", a_tag);
            return false;
        }
        const std::uint8_t* pro = nullptr;
        std::size_t len = 0;
        if (VerifyBytes(addr, a_ng, a_ngLen)) {
            pro = a_ng; len = a_ngLen;
        } else if (VerifyBytes(addr, a_og, a_ogLen)) {
            pro = a_og; len = a_ogLen;
        }
        if (!pro) {
            REX::INFO("WeaponSwapLagFix DIAG: {} prologue mismatch, tap skipped", a_tag);
            return false;
        }
        const auto stub = PatchFuncEntry(addr, len, a_hook, a_tag);
        if (!stub) return false;
        g_tapOrig[a_idx] = stub;
        REX::INFO("WeaponSwapLagFix DIAG: {} tap @ 0x{:X} ({} bytes)", a_tag, addr, len);
        return true;
    }

    // Round 6 installs. Neither target has an address-library ID, so both are
    // located by prologue signature, offline-verified unique in .text on
    // OG163 / NG984 / AE221 / AE240 (scripts in crash log/verify_pipboychain_*).
    // The NG/AE family and the OG family differ (OG keeps the 155 codegen), so
    // each target carries two candidate signatures; whichever matches win, and
    // neither is guessed - a zero-match is logged and the tap stays off.
    bool InstallPipboyTaps()
    {
        // PipboyInventoryData::RepopulateItem(this, BGSInventoryItem*)
        static constexpr std::uint8_t kRepNG[]{
            0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57,
            0x41, 0x54, 0x41, 0x55, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xD9,
            0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00 };  // 27 = whole prologue
        static constexpr std::uint8_t kRepOG[]{
            0x40, 0x53, 0x56, 0x57, 0x41, 0x55, 0x41, 0x56,
            0x48, 0x83, 0xEC, 0x70, 0x48, 0x8B, 0xFA };  // 15 = 6 pushes + call
        // PipboyInventoryData::PopulateComparisonInfoForSection(this, formType)
        static constexpr std::uint8_t kCmpNG[]{
            0x48, 0x8B, 0xC4, 0x55, 0x48, 0x8D, 0x68, 0xA1,
            0x48, 0x81, 0xEC, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x89, 0x58, 0xF0 };
        static constexpr std::uint8_t kCmpOG[]{
            0x48, 0x8B, 0xC4, 0x55, 0x48, 0x8D, 0x68, 0xA1,
            0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00, 0x48, 0x89, 0x58, 0x10 };

        struct Def {
            TapIdx idx;
            void* hook;
            const std::uint8_t* ng;
            std::size_t ngLen;
            const std::uint8_t* og;
            std::size_t ogLen;
            const char* tag;
        };
        const Def defs[] = {
            { kTapRepItem, &HookedT20, kRepNG, sizeof(kRepNG), kRepOG, sizeof(kRepOG), "RepopulateItem" },
            { kTapComparison, &HookedT21, kCmpNG, sizeof(kCmpNG), kCmpOG, sizeof(kCmpOG), "Comparison" },
        };

        int installed = 0;
        // Everything down to the perk-sink block is pure measurement; with
        // [Diag] DiagTaps=0 none of it is patched, which is the A/B switch for
        // "did one of these hooks cause that crash?".
        if (g_diagHooks != 0) {
        int repFamily = 0;  // 1 = NG/AE signature matched, 2 = OG
        for (const auto& d : defs) {
            auto addr = ScanTextSig(d.ng, d.ngLen, nullptr, 0, true, d.tag);
            std::size_t hookSize = d.ngLen;
            const bool usingNG = addr != 0;
            if (!addr) {
                addr = ScanTextSig(d.og, d.ogLen, nullptr, 0, true, d.tag);
                hookSize = d.ogLen;
            }
            if (!addr) {
                REX::INFO("WeaponSwapLagFix DIAG: {} signature not found, tap skipped", d.tag);
                continue;
            }
            const auto stub = PatchFuncEntry(addr, hookSize, d.hook, d.tag);
            if (!stub) continue;
            g_tapOrig[d.idx] = stub;
            REX::INFO("WeaponSwapLagFix DIAG: {} tap @ 0x{:X} ({} bytes)", d.tag, addr, hookSize);
            ++installed;
            if (d.idx == kTapRepItem) {
                g_repItemAddr = addr;
                repFamily = usingNG ? 1 : 2;
            }
        }

        // Round 7: walk RepopulateItem's own body for the five callees it uses
        // per equip. Each candidate is verified byte-by-byte before anything is
        // patched, so a build whose layout differs simply gets no deep taps.
        if (g_repItemAddr) {
            const auto* subs = repFamily == 1 ? kSubsNG : kSubsOG;
            const std::size_t nSubs = repFamily == 1 ? std::size(kSubsNG) : std::size(kSubsOG);
            for (std::size_t i = 0; i < nSubs; ++i) {
                const auto& s = subs[i];
                const auto tgt = CallTargetAt(g_repItemAddr, s.delta);
                if (!tgt || !VerifyBytes(tgt, s.pro, s.proLen)) {
                    REX::INFO("WeaponSwapLagFix DIAG: {} not confirmed (delta 0x{:X}), skipped",
                        s.tag, s.delta);
                    continue;
                }
                const auto stub = PatchFuncEntry(tgt, s.proLen, s.hook, s.tag);
                if (!stub) continue;
                g_tapOrig[s.idx] = stub;
                REX::INFO("WeaponSwapLagFix DIAG: {} tap @ 0x{:X} (RepopulateItem+0x{:X}, "
                          "{} bytes)", s.tag, tgt, s.delta, s.proLen);
                ++installed;
            }
        }
        }  // g_diagHooks

        // Round 10: resolve the two perk sinks that spam the category queue.
        // VTABLE[4] = PerkEntryUpdatedEvent sink (base +0xB0), VTABLE[5] =
        // PerkValueChangedEvent sink (base +0xB8). Slot 1 of each chunk is the
        // ProcessEvent body.
        {
            REL::Relocation<std::uintptr_t> v4{ REL::ID(859541) };
            REL::Relocation<std::uintptr_t> v5{ REL::ID(1517939) };
            if (v4.address() && v5.address()) {
                const auto f4 = *reinterpret_cast<std::uintptr_t*>(v4.address() + 8);
                const auto f5 = *reinterpret_cast<std::uintptr_t*>(v5.address() + 8);
                if (IsInsideExe(f4) && IsInsideExe(f5)) {
                    g_perkSink[0] = f4;
                    g_perkSink[1] = f5;
                    REX::INFO("WeaponSwapLagFix DIAG: perk queue sinks @ 0x{:X} / 0x{:X} "
                              "(rate-limited to 1 per {}ms)", f4, f5,
                        static_cast<long long>(g_perkQueueGapMs));
                } else {
                    REX::INFO("WeaponSwapLagFix DIAG: perk sink resolve failed, rate limit off");
                }

                // Round 20: swap the two slots. These are virtuals, so the
                // clean way in is the vtable - their prologues start with
                // `mov eax,[rip+...]` which cannot be relocated into a
                // trampoline. Nothing about the original code is touched.
                std::uintptr_t slots[2]{ v4.address() + 8, v5.address() + 8 };
                void* hooks[2]{ reinterpret_cast<void*>(&HookedPerkEntryUpdated),
                    reinterpret_cast<void*>(&HookedPerkValueChanged) };
                g_perkEntryLogLeft.store(40, std::memory_order_relaxed);
                for (int i = 0; i < 2; ++i) {
                    if (!IsInsideExe(g_perkSink[i])) continue;
                    auto* slot = reinterpret_cast<std::uintptr_t*>(slots[i]);
                    DWORD old = 0;
                    if (!VirtualProtect(slot, sizeof(std::uintptr_t), PAGE_EXECUTE_READWRITE,
                            &old)) {
                        REX::INFO("WeaponSwapLagFix DIAG: perk sink #{} slot not writable, "
                                  "entry filter off", i);
                        continue;
                    }
                    g_perkSlot[i] = slots[i];
                    g_origPerkProcess[i] = *slot;
                    *slot = reinterpret_cast<std::uintptr_t>(hooks[i]);
                    VirtualProtect(slot, sizeof(std::uintptr_t), old, &old);
                }
                if (g_origPerkProcess[0] && g_origPerkProcess[1]) {
                    REX::INFO("WeaponSwapLagFix DIAG: perk entry filter ON - only entry points "
                              "0x1D/0x23/0x55/0x5D/0x63 queue a rebuild");
                } else {
                    REX::INFO("WeaponSwapLagFix DIAG: perk entry filter NOT installed");
                }
            }
        }

        // Round 18: name the perks that Papyrus keeps adding/removing. Same
        // prologue on all four builds, so one signature each.
        {
            static constexpr std::uint8_t kProAddPerk[]{
                0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10,
                0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x40 };   // 17, ends on sub rsp
            static constexpr std::uint8_t kProRemovePerk[]{
                0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18,
                0x57, 0x48, 0x83, 0xEC, 0x40 };                      // 14, ends on sub rsp
            REL::Relocation<std::uintptr_t> a{ REL::VariantID(187096, 2230121) };
            REL::Relocation<std::uintptr_t> r{ REL::VariantID(1316475, 2230122) };
            if (a.address() && VerifyBytes(a.address(), kProAddPerk, sizeof(kProAddPerk))) {
                if (const auto stub = PatchFuncEntry(a.address(), sizeof(kProAddPerk),
                        &HookedT38, "AddPerk")) {
                    g_origAddPerk = stub;
                    REX::INFO("WeaponSwapLagFix DIAG: AddPerk traced @ 0x{:X}", a.address());
                }
            } else {
                REX::INFO("WeaponSwapLagFix DIAG: AddPerk not confirmed, trace skipped");
            }
            if (r.address() && VerifyBytes(r.address(), kProRemovePerk, sizeof(kProRemovePerk))) {
                if (const auto stub = PatchFuncEntry(r.address(), sizeof(kProRemovePerk),
                        &HookedT39, "RemovePerk")) {
                    g_origRemovePerk = stub;
                    REX::INFO("WeaponSwapLagFix DIAG: RemovePerk traced @ 0x{:X}", r.address());
                }
            } else {
                REX::INFO("WeaponSwapLagFix DIAG: RemovePerk not confirmed, trace skipped");
            }
        }

        // Round 8: the deferred, category-wide rebuild path. Both have IDs.
        {
            static constexpr std::uint8_t kProQueueNG[]{
                0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18,
                0x48, 0x89, 0x74, 0x24, 0x20, 0x57, 0x41, 0x56, 0x41, 0x57,
                0x48, 0x83, 0xEC, 0x30 };
            static constexpr std::uint8_t kProQueueOG[]{
                0x48, 0x89, 0x5C, 0x24, 0x20, 0x89, 0x54, 0x24, 0x10, 0x57,
                0x48, 0x83, 0xEC, 0x30 };
            if (InstallIdTap(kTapQueueCard, REL::VariantID(1034299, 2225311), &HookedT28,
                    kProQueueNG, sizeof(kProQueueNG), kProQueueOG, sizeof(kProQueueOG),
                    "QueueItemCardRepopulate")) {
                ++installed;
            }
            static constexpr std::uint8_t kProSecNG[]{
                0x89, 0x54, 0x24, 0x10, 0x55, 0x53, 0x41, 0x54, 0x41, 0x55,
                0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xC9 };
            static constexpr std::uint8_t kProSecOG[]{
                0x89, 0x54, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55,
                0x53, 0x56, 0x41, 0x54 };
            if (InstallIdTap(kTapSecRepop, REL::VariantID(892255, 2225279), &HookedT29,
                    kProSecNG, sizeof(kProSecNG), kProSecOG, sizeof(kProSecOG),
                    "RepopulateItemCardOnSection")) {
                ++installed;
            }
        }

        // Round 11: the two card-field helpers. Prologues are byte-identical on
        // NG984/AE221/AE240 and OG163 for BaseAdd; AddEntry differs on OG.
        if (g_diagHooks != 0) {
            static constexpr std::uint8_t kProBaseAdd[]{
                0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10,
                0x57, 0x48, 0x83, 0xEC, 0x20 };
            if (InstallIdTap(kTapBaseAdd, REL::VariantID(1150364, 2225270), &HookedT30,
                    kProBaseAdd, sizeof(kProBaseAdd), kProBaseAdd, sizeof(kProBaseAdd),
                    "BaseAddItemCardInfoEntry")) {
                ++installed;
            }
            static constexpr std::uint8_t kProAddEntry[]{
                0x48, 0x89, 0x5C, 0x24, 0x08, 0xF3, 0x0F, 0x11, 0x54, 0x24,
                0x18, 0x57, 0x48, 0x83, 0xEC, 0x30 };
            static constexpr std::uint8_t kProAddEntryOG[]{
                0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x40,
                0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x4C, 0x24, 0x20 };
            if (InstallIdTap(kTapAddEntry, REL::VariantID(1191786, 2225267), &HookedT31,
                    kProAddEntry, sizeof(kProAddEntry), kProAddEntryOG, sizeof(kProAddEntryOG),
                    "AddItemCardInfoEntry")) {
                ++installed;
            }
        }  // g_diagHooks

        if (g_diagHooks != 0) {
            // `48 8D 68 A1` (lea rbp,[rax-0x5F]) is FOUR bytes - no SIB, unlike
            // `48 8D 6C 24 C9` (lea rbp,[rsp-0x37]) which needs one. Both stop
            // right after the lea; the following `48 81 EC ...` must stay whole.
            static constexpr std::uint8_t kProFillDmg[]{
                0x48, 0x8B, 0xC4, 0x48, 0x89, 0x50, 0x10, 0x55, 0x56, 0x57,
                0x41, 0x56, 0x48, 0x8D, 0x68, 0xA1 };
            static constexpr std::uint8_t kProFillDmgOG[]{
                0x48, 0x8B, 0xC4, 0x48, 0x89, 0x50, 0x10, 0x55, 0x56, 0x41,
                0x54, 0x41, 0x57, 0x48, 0x8D, 0x68, 0xA1 };
            if (InstallIdTap(kTapFillDmg, REL::VariantID(928518, 2225234), &HookedT32,
                    kProFillDmg, sizeof(kProFillDmg), kProFillDmgOG, sizeof(kProFillDmgOG),
                    "FillDamageTypeInfo")) {
                ++installed;
                REL::Relocation<std::uintptr_t> fd{ REL::VariantID(928518, 2225234) };
                g_fillDmgAddr = fd.address();
            }
            static constexpr std::uint8_t kProFillRes[]{
                0x48, 0x8B, 0xC4, 0xF3, 0x0F, 0x11, 0x58, 0x20, 0x56, 0x57,
                0x41, 0x56, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00 };
            static constexpr std::uint8_t kProFillResOG[]{
                0x48, 0x8B, 0xC4, 0xF3, 0x0F, 0x11, 0x58, 0x20, 0x48, 0x89,
                0x48, 0x08, 0x55, 0x41, 0x54, 0x41, 0x56 };
            if (InstallIdTap(kTapFillRes, REL::VariantID(1578434, 2225235), &HookedT33,
                    kProFillRes, sizeof(kProFillRes), kProFillResOG, sizeof(kProFillResOG),
                    "FillResistTypeInfo")) {
                ++installed;
            }
        }  // g_diagHooks

        // Round 14: CombatFormulas::GetWeaponDisplayDamage, reached from
        // FillDamageTypeInfo+0xB6 on NG984/AE221/AE240 (OG differs - no tap).
        if (g_fillDmgAddr) {
            static constexpr std::uint8_t kProDispDmg[]{
                0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18,
                0x57, 0x48, 0x83, 0xEC, 0x50 };
            const auto tgt = CallTargetAt(g_fillDmgAddr, 0xB6);
            if (tgt && VerifyBytes(tgt, kProDispDmg, sizeof(kProDispDmg))) {
                const auto stub = PatchFuncEntry(tgt, sizeof(kProDispDmg), &HookedT37,
                    "GetWeaponDisplayDamage");
                if (stub) {
                    g_tapOrig[kTapDispDmg] = stub;
                    REX::INFO("WeaponSwapLagFix DIAG: GetWeaponDisplayDamage tap @ 0x{:X} "
                              "(FillDamageTypeInfo+0xB6, {} bytes)", tgt, sizeof(kProDispDmg));
                    ++installed;
                }
            } else {
                REX::INFO("WeaponSwapLagFix DIAG: GetWeaponDisplayDamage not confirmed, skipped");
            }
        }

        // PopulateItemCardInfo has an ID of its own - the ~3.8KB card builder
        // every fresh item entry pays for. Relocation gives the address, the
        // prologue check keeps the patch honest.
        if (g_diagHooks != 0) {
            REL::Relocation<std::uintptr_t> cardAddr{ REL::VariantID(54211, 2225266) };
            const auto card = cardAddr.address();
            if (card) {
                const std::uint8_t* pro = nullptr;
                std::size_t len = 0;
                if (VerifyBytes(card, kProCardInfoNG, sizeof(kProCardInfoNG))) {
                    pro = kProCardInfoNG; len = sizeof(kProCardInfoNG);
                } else if (VerifyBytes(card, kProCardInfoOG, sizeof(kProCardInfoOG))) {
                    pro = kProCardInfoOG; len = sizeof(kProCardInfoOG);
                }
                if (pro) {
                    const auto stub = PatchFuncEntry(card, len, &HookedT27, "ItemCardInfo");
                    if (stub) {
                        g_tapOrig[kTapCardInfo] = stub;
                        REX::INFO("WeaponSwapLagFix DIAG: ItemCardInfo tap @ 0x{:X} ({} bytes)",
                            card, len);
                        ++installed;
                    }
                } else {
                    REX::INFO("WeaponSwapLagFix DIAG: ItemCardInfo prologue mismatch, skipped");
                }
            }
        }  // g_diagHooks
        return installed > 0;
    }

    // There is no ini file. Every knob is a compile-time constant next to the
    // code it governs, each with the measurement that set it; change it here
    // and rebuild rather than at runtime.
    void InitAndLogSettings()
    {
        g_perkTraceLeft.store(g_perkTraceMax > 0 ? g_perkTraceMax : 0, std::memory_order_relaxed);
        g_perkLogLeft.store(g_perkLogMax > 0 ? g_perkLogMax : 0, std::memory_order_relaxed);
        if (auto* ntdll = GetModuleHandleW(L"ntdll.dll")) {
            g_captureStack = reinterpret_cast<CaptureStack_t>(
                GetProcAddress(ntdll, "RtlCaptureStackBackTrace"));
        }
        REX::INFO("WeaponSwapLagFix: rebuild gap {}ms, throttle {}ms, loop break {}, "
                  "equip-window queue skip {}",
            static_cast<long long>(g_perkQueueGapMs), static_cast<long long>(g_throttleMs),
            g_breakLoop ? "ON" : "off", g_skipCatQueue ? "ON" : "off");
        REX::INFO("WeaponSwapLagFix: damage cache {} (ttl {}ms), card build skip {}",
            g_cacheDamage ? "ON" : "off", static_cast<long long>(g_dmgTtlUs / 1000),
            g_cardSkipMode);
        REX::INFO("WeaponSwapLagFix: traces - perk stacks {} (walk {}), perk names {}, "
                  "timing taps {}, verbose {}",
            g_perkTraceMax, g_captureStack ? "available" : "unavailable", g_perkLogMax,
            g_diagHooks ? "ON" : "off", g_verbose ? "ON" : "off");
    }

    bool InstallEquipDiag()
    {
        REL::Relocation<std::uintptr_t> addr{ REL::VariantID(988029, 2231392) };
        const auto equip = addr.address();
        if (!equip) {
            REX::ERROR("WeaponSwapLagFix DIAG: EquipObject ID unresolvable, diag NOT installed");
            return false;
        }
        // Offline-verified prologues (both end on an instruction boundary and
        // carry no rip-relative encodings).
        static constexpr std::uint8_t kProOG[]{
            0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x53, 0x10, 0x55, 0x56,
            0x41, 0x54, 0x41, 0x57, 0x49, 0x8D, 0x6B, 0xD9 };
        constexpr std::size_t kHookOG = 17;
        static constexpr std::uint8_t kProNG[]{
            0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x73, 0x20, 0x49, 0x89, 0x53, 0x10,
            0x55, 0x57, 0x41, 0x56, 0x49, 0x8D, 0x6B, 0xD9 };
        constexpr std::size_t kHookNG = 19;

        std::size_t hookSize = 0;
        const char* family = nullptr;
        if (VerifyBytes(equip, kProOG, sizeof(kProOG))) {
            hookSize = kHookOG; family = "OG";
        } else if (VerifyBytes(equip, kProNG, sizeof(kProNG))) {
            hookSize = kHookNG; family = "NG";
        } else {
            char hex[96];
            int n = std::snprintf(hex, sizeof(hex), "EquipObject @ 0x%llX prologue: ",
                static_cast<unsigned long long>(equip));
            for (int i = 0; i < 19 && n < static_cast<int>(sizeof(hex)) - 3; ++i)
                n += std::snprintf(hex + n, sizeof(hex) - n, "%02X",
                    *reinterpret_cast<const std::uint8_t*>(equip + i));
            REX::ERROR("WeaponSwapLagFix DIAG: {} - mismatch, diag NOT installed", hex);
            return false;
        }
        const auto stub = PatchFuncEntry(equip, hookSize, &HookedEquipObject, "EquipDiag");
        if (!stub) return false;
        g_origEquipObject = reinterpret_cast<EquipObjectFn>(stub);
        REX::INFO("WeaponSwapLagFix DIAG: EquipObject hooked @ 0x{:X} ({} family, {} bytes)",
            equip, family, hookSize);
        InitAndLogSettings();   // before the taps: g_diagHooks decides whether they install
        InstallEquipTaps();
        InstallPipboyTaps();
        // Resolve the pipeline spin lock from EquipObject's acquire pair,
        // then cross-verify with any lea to the same address in LoopEquip.
        const auto lockFromEquip = FindLockRef(equip, 0x400);
        const bool loopConfirms = lockFromEquip && g_loopEquipAddr &&
            ContainsLeaTo(g_loopEquipAddr, 0x200, lockFromEquip);
        if (lockFromEquip && loopConfirms) {
            g_equipLockAddr = lockFromEquip;
            REX::INFO("WeaponSwapLagFix DIAG: equip spin lock @ 0x{:X}", g_equipLockAddr);
        } else {
            REX::ERROR("WeaponSwapLagFix DIAG: spin lock resolve failed "
                       "(equip 0x{:X}, loopConfirms={}) - contention probe off",
                lockFromEquip, loopConfirms);
        }
        // Cache the AEM event source for the Notify filter.
        if (auto* mgr = RE::ActorEquipManager::GetSingleton()) {
            g_aemSource = reinterpret_cast<std::uint64_t>(mgr) + 0x08;
        }
        // Stamp menu open/close so a rebuild that lands after the perk menu
        // closes can be attributed to it.
        if (auto* ui = RE::UI::GetSingleton()) {
            ui->RegisterSink<RE::MenuOpenCloseEvent>(&g_menuWatcher);
            REX::INFO("WeaponSwapLagFix DIAG: menu watcher registered");
        }
        return true;
    }
}

F4SE_PLUGIN_QUERY(const F4SE::QueryInterface* a_f4se, F4SE::PluginInfo* a_info)
{
    if (const auto data = F4SE::PluginVersionData::GetSingleton()) {
        a_info->infoVersion = F4SE::PluginInfo::kVersion;
        a_info->name = data->GetPluginName().data();
        a_info->version = data->GetPluginVersion().pack();
    }
    const auto ver = a_f4se->RuntimeVersion();
    if (ver < REL::Version(F4SE::RUNTIME_1_10_163)) {
        REX::ERROR("WeaponSwapLagFix: unsupported runtime version {}", ver);
        return false;
    }
    return true;
}

F4SE_PLUGIN_LOAD(const F4SE::LoadInterface* a_f4se)
{
    F4SE::InitInfo initInfo{};
    initInfo.trampoline = true;
    initInfo.trampolineSize = 4096;
    F4SE::Init(a_f4se, initInfo);
    REX::INFO("WeaponSwapLagFix: loaded");

    auto* messaging = F4SE::GetMessagingInterface();
    if (messaging) {
        messaging->RegisterListener([](F4SE::MessagingInterface::Message* a_msg) {
            if (a_msg->type == F4SE::MessagingInterface::kGameDataReady) {
                InstallEquipDiag();
            }
        });
    }
    return true;
}
