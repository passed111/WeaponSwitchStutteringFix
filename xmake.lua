target("WeaponSwapLagFix")
    add_rules("commonlibf4.plugin", {
        author = "SOLO",
        description = "Remove the weapon-swap stall: deferred equip-pipeline recomputes, rate-limited Pip-Boy card rebuilds, memoised weapon damage"
    })
    add_deps("commonlibf4")
    add_files("src/**.cpp")
    add_defines("NOMINMAX", "_CRT_SECURE_NO_WARNINGS")
