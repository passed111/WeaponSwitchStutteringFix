#include "Internal.h"

namespace wslf
{
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

        // No special case for the weapon bench any more. There was one (always
        // recompute inside the bench), added to fix "damage readout keeps the
        // pre-mod value" - but that turned out NOT to be caused by this memo:
        // it reproduces with the memo disabled entirely. So the bypass only
        // cost time for nothing and was removed.

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

    // ---- install (moved out of InstallPipboyTaps) -------------------- //
    bool InstallDamageMemoTap()
    {
        int installed = 0;
        // CombatFormulas::GetWeaponDisplayDamage has its own address-library ID,
        // which is the only reliable way in.
        //
        // Everything else was guesswork and every guess was wrong on a real
        // 1.10.984 install:
        //   - FillDamageTypeInfo+0xB6: that call reaches a "jmp [rip+0]" thunk
        //     whose destination is OUTSIDE the exe, not the game function;
        //   - scanning the caller's body: on this build none of the call targets
        //     has the prologue that was being matched.
        // The tap therefore never installed, the memo never ran, and category
        // rebuilds kept paying ~840ms - which is what made opening the favourites
        // menu stutter.
        //
        // 15 bytes are displaced: two "mov [rsp+n],reg", the push, and the
        // following "sub rsp,imm8". That is >= JMP14 and lands on an instruction
        // boundary. The prologue is intentionally NOT byte-checked - the ID is
        // authoritative, and a byte check is exactly what kept failing before.
        {
            REL::Relocation<std::uintptr_t> rel{
                REL::VariantID(1431014, 2209046) };
            const auto tgt = rel.address();
            constexpr std::size_t kDispDmgHook = 15;
            if (tgt && IsInsideExe(tgt)) {
                const auto stub = PatchFuncEntry(tgt, kDispDmgHook, &HookedT37,
                    "GetWeaponDisplayDamage");
                if (stub) {
                    g_tapOrig[kTapDispDmg] = stub;
                    REX::INFO("WeaponSwapLagFix DIAG: GetWeaponDisplayDamage tap @ 0x{:X} "
                              "(address library, {} bytes)", tgt, kDispDmgHook);
                    ++installed;
                }
            } else {
                REX::ERROR("WeaponSwapLagFix: GetWeaponDisplayDamage ID unresolvable "
                           "- damage memo OFF, category rebuilds will pay full price");
            }
        }

        return installed > 0;
    }


}
