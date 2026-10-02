#include "Internal.h"

namespace wslf
{
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

    void DumpAndResetTaps([[maybe_unused]] std::int64_t a_equipUs)
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
}
