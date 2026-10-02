#pragma once

// WeaponSwapLagFix - shared declarations.
// The plugin was split from one main.cpp into per-concern translation units
// (HookUtil / EquipPipeline / PipboyCards / PerkFlood / DamageMemo / Diag /
// main). This header carries everything they share: the common includes, the
// tap bookkeeping types, the cross-module state (declared extern, defined in
// exactly one .cpp next to the code that owns it) and the function
// declarations that cross a file boundary.

#include "F4SE/F4SE.h"
#include "RE/Fallout.h"
#include <REX/REX.h>

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>

#undef ERROR

namespace wslf
{
    // ---- hook utilities (HookUtil.cpp) --------------------------------- //

    struct SigAnchor { std::size_t off; const std::uint8_t* bytes; std::size_t len; };

    [[nodiscard]] bool IsInsideExe(std::uintptr_t a_addr);
    std::uintptr_t ScanTextSig(const std::uint8_t* a_sig, std::size_t a_len,
        const SigAnchor* a_anchors, std::size_t a_nAnchors, bool a_allowMiss,
        const char* a_tag);
    std::uintptr_t ScanTextUnique(const std::uint8_t* a_sig, std::size_t a_len,
        const char* a_tag);
    [[nodiscard]] std::uintptr_t FuncStartFromHit(std::uintptr_t a_hit, std::size_t a_back);
    bool VerifyBytes(std::uintptr_t a_addr, const std::uint8_t* a_expected, std::size_t a_len);
    std::uintptr_t PatchFuncEntry(std::uintptr_t a_addr, std::size_t a_hookSize,
        void* a_hookFn, const char* a_tag);
    [[nodiscard]] std::int64_t NowUs();
    [[nodiscard]] std::uintptr_t CallTargetAt(std::uintptr_t a_fn, std::size_t a_off);

    // ---- shared types --------------------------------------------------- //

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

    using EquipObjectFn = bool (*)(RE::ActorEquipManager*, RE::Actor*,
        const RE::BGSObjectInstance&, std::uint32_t, std::uint32_t,
        const RE::BGSEquipSlot*, bool, bool, bool, bool, bool);
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
    // (actor, entry, form) -> bool - runs once per collected item inside
    // EquipApply, each call walks the full BGSInventoryList
    using T10_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    // 11 scalar args, return ignored by the caller
    using T11_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t,
        std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t,
        std::uint64_t, std::uint64_t, std::uint64_t);
    // (actor, objInst*, count) -> void - ApplyToActor case 0x2B tail
    using T12_t = void (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    // (actor, form, flags) -> instanceData default - EquipObject head
    using T13_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    // (mgr, actor, objInst, args) -> ? - LoopEquip's main work call
    using T14_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
    // (mgr, actor, objInst*) -> slot - LoopEquip slot resolve
    using T15_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    // (actor, form) -> bool - LoopEquip equip check
    using T16_t = std::uint64_t (*)(std::uint64_t, std::uint64_t);
    // (mgr, actor, objInst*) -> slot - EquipObject wrapper slot resolve
    using T17_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    // (invChanges, actor, form, instData) -> void - equipped-array edit with
    // linear scans and per-removal memmoves inside LoopEquipMain
    using T18_t = void (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
    // source before counting anything.
    using T19_t = std::int64_t (*)(std::uint64_t, std::uint64_t);
    // (pipboyInventoryData, BGSInventoryItem*) -> void
    using T20_t = void (*)(std::uint64_t, std::uint64_t);
    // (pipboyInventoryData, ENUM_FORM_ID) -> void
    using T21_t = void (*)(std::uint64_t, std::uint64_t);
    using T22_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
    using T23_t = std::uint64_t (*)(std::uint64_t, std::uint64_t);
    using CaptureStack_t = std::uint16_t(__stdcall*)(std::uint32_t, std::uint32_t,
        void**, std::uint32_t*);
    using TPerk_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    using T24_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    using T25_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, float, std::uint64_t);
    using T26_t = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t, float);
    using T27_t = float (*)(std::uint64_t, std::uint64_t, float);

    // Declared before MenuWatcher - the class body below uses it.
    extern std::atomic<std::int64_t> g_menuCloseUs;      // PerkFlood.cpp

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

    // ---- shared state ---------------------------------------------------- //
    // Definitions live in exactly one .cpp - the module that owns the state.
    // The comment names that file.

    extern EquipObjectFn g_origEquipObject;             // EquipPipeline.cpp
    extern std::atomic<std::int32_t> g_diagDepth;       // EquipPipeline.cpp
    extern TapStats g_taps[kTapCount];                  // EquipPipeline.cpp
    extern std::uint64_t g_tapOrig[kTapCount];          // EquipPipeline.cpp
    extern std::uint64_t g_aemSource;                   // EquipPipeline.cpp
    extern std::uintptr_t g_equipLockAddr;              // EquipPipeline.cpp
    extern std::uintptr_t g_loopEquipAddr;              // EquipPipeline.cpp

    extern std::atomic<std::uint64_t> g_cmpSectionMask; // PipboyCards.cpp
    extern std::atomic<std::uint32_t> g_cardAllN;       // PipboyCards.cpp
    extern std::atomic<std::int64_t>  g_cardAllUs;      // PipboyCards.cpp
    extern std::atomic<std::uint32_t> g_secAllN;        // PipboyCards.cpp
    extern std::atomic<std::int64_t>  g_secAllUs;       // PipboyCards.cpp
    extern std::atomic<std::uint64_t> g_queueMask;      // PipboyCards.cpp
    extern int g_cardSkipMode;                          // PipboyCards.cpp
    extern std::atomic<int> g_inRepopulateItem;         // PipboyCards.cpp
    extern std::atomic<int> g_cardSkipped;              // PipboyCards.cpp
    extern std::uintptr_t g_fillDmgAddr;                // DamageMemo.cpp

    extern int g_skipCatQueue;                          // PerkFlood.cpp
    extern int g_breakLoop;                             // PerkFlood.cpp
    extern std::int64_t g_throttleMs;                   // PerkFlood.cpp
    extern std::uintptr_t g_perkSink[2];                // PerkFlood.cpp
    extern std::atomic<std::int64_t> g_lastPerkQueueUs; // PerkFlood.cpp
    extern std::int64_t g_perkQueueGapMs;               // PerkFlood.cpp
    extern std::atomic<int> g_perkDropped;              // PerkFlood.cpp
    extern std::atomic<std::uint32_t> g_equipFormType;  // PerkFlood.cpp
    extern std::atomic<int> g_catQueueSkipped;          // PerkFlood.cpp
    extern CaptureStack_t g_captureStack;               // PerkFlood.cpp
    extern int g_perkTraceMax;                          // PerkFlood.cpp
    extern int g_verbose;                               // PerkFlood.cpp
    extern int g_diagHooks;                             // PerkFlood.cpp
    extern std::atomic<int> g_perkTraceLeft;            // PerkFlood.cpp
    extern std::atomic<int> g_perkLogLeft;              // PerkFlood.cpp
    extern int g_perkLogMax;                            // PerkFlood.cpp
    extern std::atomic<std::int64_t> g_perkCalls;       // PerkFlood.cpp
    extern std::atomic<int> g_perkDistinct;             // PerkFlood.cpp
    extern std::atomic<std::int64_t> g_dmgHits;         // PerkFlood.cpp
    extern std::atomic<std::int64_t> g_dmgMisses;       // PerkFlood.cpp
    extern std::atomic<std::int64_t> g_dmgMissExpired;  // PerkFlood.cpp
    extern std::atomic<std::int64_t> g_dmgMissNewKey;   // PerkFlood.cpp
    extern std::atomic<int> g_loopSuppressed;           // PerkFlood.cpp
    extern std::atomic<int> g_throttleSuppressed;       // PerkFlood.cpp
    extern std::atomic<std::int64_t> g_perkPass;        // PerkFlood.cpp
    extern std::atomic<std::int64_t> g_perkDrop;        // PerkFlood.cpp
    extern std::atomic<std::int64_t> g_perkQueueSkipped;// PerkFlood.cpp
    extern std::atomic<int> g_epPassed[256];            // PerkFlood.cpp
    extern std::atomic<int> g_rebuildCount;             // PerkFlood.cpp
    extern std::atomic<std::int64_t> g_rebuildUs;       // PerkFlood.cpp
    extern MenuWatcher g_menuWatcher;                   // PerkFlood.cpp

    extern std::atomic<std::int64_t> g_dmgHealthOdd;    // DamageMemo.cpp
    extern std::atomic<std::uint64_t> g_dmgHealthSample;// DamageMemo.cpp
    extern int g_cacheDamage;                           // DamageMemo.cpp
    extern std::int64_t g_dmgTtlUs;                     // DamageMemo.cpp

    // ---- functions used across files ------------------------------------ //

    bool HookedEquipObject(RE::ActorEquipManager* a_mgr, RE::Actor* a_actor,
        const RE::BGSObjectInstance& a_object, std::uint32_t a_stackID,
        std::uint32_t a_number, const RE::BGSEquipSlot* a_slot, bool a_queueEquip,
        bool a_forceEquip, bool a_playSounds, bool a_applyNow, bool a_locked);  // EquipPipeline.cpp
    bool InstallEquipTaps();       // EquipPipeline.cpp
    bool InstallIdTap(TapIdx a_idx, REL::VariantID a_id, void* a_hook,
        const std::uint8_t* a_ng, std::size_t a_ngLen, const std::uint8_t* a_og,
        std::size_t a_ogLen, const char* a_tag);                       // EquipPipeline.cpp
    [[nodiscard]] std::uintptr_t FindLockRef(std::uintptr_t a_fn, std::size_t a_scanLen);      // EquipPipeline.cpp
    [[nodiscard]] bool ContainsLeaTo(std::uintptr_t a_fn, std::size_t a_scanLen,
        std::uintptr_t a_target);                                     // EquipPipeline.cpp

    bool InstallPipboyTaps();      // PipboyCards.cpp
    bool InstallPerkFloodHooks();  // PerkFlood.cpp
    bool InstallDamageMemoTap();   // DamageMemo.cpp
    void DropDamageCache();        // DamageMemo.cpp

    void DumpEquipSinks();         // Diag.cpp
    void DumpAndResetTaps(std::int64_t a_equipUs);   // Diag.cpp
}
