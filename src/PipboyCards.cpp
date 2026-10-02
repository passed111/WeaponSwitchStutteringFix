#include "Internal.h"

namespace wslf
{
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
}
