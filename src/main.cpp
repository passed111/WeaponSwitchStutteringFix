#include "Internal.h"

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

namespace wslf
{
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
        InstallPerkFloodHooks();
        InstallDamageMemoTap();
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
                wslf::InstallEquipDiag();
            }
        });
    }
    return true;
}