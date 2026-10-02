#include "Internal.h"

namespace wslf
{
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
}
