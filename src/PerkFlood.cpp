#include "Internal.h"

namespace wslf
{
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
    void DropDamageCache();   // defined in DamageMemo.cpp (declared in Internal.h)
    // 0 = keep the memo across a perk purchase (smooth; a displayed damage
    //     number can lag by up to g_dmgTtlUs)
    // 1 = drop it, so the next rebuild is exact but costs the full ~860ms
    int g_flushOnAddPerk = 0;

    // MenuWatcher itself is defined in Internal.h (the class body needs
    // g_menuCloseUs, so it lives next to that declaration).
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

    // ---- installs (moved out of InstallPipboyTaps) -------------------- //
    // The perk-sink slot swap, the AddPerk/RemovePerk trace taps and the
    // queue / section rebuild taps are all perk-flood machinery; they live
    // here with the hooks they install.
    bool InstallPerkFloodHooks()
    {
        int installed = 0;
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
        return installed > 0;
    }

}
