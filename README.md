# WeaponSwapLagFix

An F4SE plugin that removes the stutter Fallout 4 pays when you swap weapons,
and the multi-second freezes it pays when mods refresh perk values.

Everything is done in memory by hooking the engine. No game files are touched.

## What it fixes

**The equip pipeline runs several times per swap.**
One hotkey swap unequips the old weapon, equips the new one, then recurses into a
second full pass for the ammo. Each pass ends with the same two expensive steps:
`CalcEquippedWeight` (walks the entire inventory item array) and
`ForceUpdateCachedMovementType` (sweeps perk entries plus two actor-value reads).
Only the last pass's result survives, so inside the player's outermost
`EquipObject` both are skipped and flushed exactly once on the way out, in
vanilla order.

**Perk events flood the Pip-Boy category-rebuild queue.**
Fallout 4 has no "change a perk value" API, so mods refresh a value by calling
`RemovePerk` then `AddPerk` - over and over. Each cycle queues a rebuild of every
item card in a category, which costs 0.8-2.3s on the game thread. The plugin lets
a queue request through only for the five entry points that can actually move a
number on an item card, and rate-limits the rest. A perk that really does change
a displayed number is never held back.

**Weapon damage is recomputed for every stack, every time.**
Each item card starts with `CombatFormulas::GetWeaponDisplayDamage`, roughly 4ms
and about 97% of a card's cost. A category rebuild walks ~200 items, so one
rebuild used to cost ~840ms. The result is memoised on the weapon, its instance
data, the ammo and the health percentage.

## Source layout

| File | Contents |
|---|---|
| `src/Internal.h` | Shared declarations: common includes, tap bookkeeping types, cross-module state (declared `extern`, defined in exactly one .cpp), and function declarations that cross a file boundary |
| `src/HookUtil.cpp` | Utilities: signature scanning, trampoline construction, byte verification, timing |
| `src/EquipPipeline.cpp` | The equip-pipeline taps, the defer fix, `EquipObject` hook and its installs |
| `src/PipboyCards.cpp` | Item-card taps: `RepopulateItem`, the rebuild path, card-field helpers |
| `src/PerkFlood.cpp` | Perk entry-point filter, the queue/section rebuild taps, rate limiting, menu watcher |
| `src/DamageMemo.cpp` | The damage memo and its tap |
| `src/Diag.cpp` | Diagnostic output |
| `src/main.cpp` | F4SE entry point and install order |

All of it lives in `namespace wslf`.

## Building

Requires [CommonLibF4](https://github.com/alandtse/CommonLibF4) and
[xmake](https://xmake.io).

```
xmake build WeaponSwapLagFix
xmake install -o <path> WeaponSwapLagFix
```

## Tuning

There is no ini file. Every knob is a compile-time constant next to the code it
governs, each with the measurement that set it - change it there and rebuild.

## Notes on locating functions

Prefer an address-library ID when one exists; fall back to signature scanning.
Do not rely on a caller's fixed offset or on a hard-coded prologue: both vary
between builds. `GetWeaponDisplayDamage` in particular has its own ID
(`1431014` / `2209046`) - chasing it through its caller's body cost three wrong
guesses on a real 1.10.984 install, because the call there reaches a `jmp` thunk
whose destination is outside the executable.

Also: a hook that fails to install logs it, but the "feature enabled" line still
prints. When judging whether an optimisation took effect, read the counters
(the damage memo's hit/miss line), not just the switch.
