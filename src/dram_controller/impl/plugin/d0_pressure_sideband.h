// D0 pressure sideband (APS): a read-only event wire from the deployed
// D0 mitigation's own per-row activation tracker to the D1 sidecar.
//
// Hardware extension request extension-request-167c1e5c1c7891fa.json
// (MIGPRESS-ROWATTRIB-LEASH-v1, run 20260901-013142-rb-kimi-k3), with two
// spec revisions from the 2026-09-04 review:
//   * attribution is EVENT-CARRIED: each event names the source core whose
//     request pushed the row across a tier, so a spread_k attack cannot
//     dilute attribution the way it dilutes per-principal statistics
//     (From-Fleet-to-Lab broke SIGRES TinyMG with exactly that dilution);
//   * the row tag shares the 16-bit mixing domain of the D1 row-reuse
//     sketch (the request spec wrote a 32-bit hash; the sketch stores
//     uint16_t tags).
//
// The wire is strictly observational: a D0 emits events, never consumes
// them, and its mitigation decisions are bit-identical with or without a
// registered sink.  With no sink registered (no D1 sidecar deployed) every
// notify below compiles to a single null check.
#pragma once
#include <cstdint>

namespace Ramulator {

// One pressure event: a row's activation count crossed a tier threshold
// inside the D0's own tracker.  Tiers are derived from the D0's own
// mitigation threshold T (for AQUA, its art_threshold):
//   tier 1 = T/32 "early", tier 2 = T/8 "elevated", tier 3 = T "committed"
// (co-timed with the D0's own action boundary).  Crossing detection IS the
// dedup: counts are monotonic inside a tracker reset epoch, so each tier
// fires at most once per row per epoch, and a row pressed again in the
// next epoch legitimately testifies again.
struct D0PressureEvent {
    uint16_t tag;    // 16-bit hash of (flat bank, row), same mixing
                     // formula as the D1 row-reuse sketch domain;
                     // diagnostic identity only -- attribution uses
                     // `source`, never tag matching
    uint8_t tier;    // 1, 2 or 3
    uint8_t bank;    // flat bank id (0..63 on the fixed 1x2x8x4 deployment)
    int32_t source;  // requesting source id (-1 if the tracker cannot see it)
};

class ID0PressureSink {
public:
    virtual ~ID0PressureSink() = default;
    virtual void d0_pressure_notify(const D0PressureEvent& event) = 0;
};

// Single-sink registry (one D1 sidecar per controller).  The sink
// registers itself at setup and clears itself in finalize().
void d0_pressure_sideband_register(ID0PressureSink* sink);
ID0PressureSink* d0_pressure_sideband_sink();

// Helper for D0 trackers: fire one event per tier threshold crossed
// between old_count and new_count (both inside the same reset epoch).
// Thresholds <= 0 disable that tier.
inline void d0_pressure_sideband_notify_tiers(
    int old_count, int new_count, int tier1, int tier2, int tier3,
    uint16_t tag, uint8_t bank, int32_t source
) {
    ID0PressureSink* sink = d0_pressure_sideband_sink();
    if (sink == nullptr) {
        return;
    }
    const int thresholds[3] = {tier1, tier2, tier3};
    for (int tier = 0; tier < 3; ++tier) {
        const int threshold = thresholds[tier];
        if (threshold > 0 && old_count < threshold && new_count >= threshold) {
            const D0PressureEvent event{
                tag, static_cast<uint8_t>(tier + 1), bank, source};
            sink->d0_pressure_notify(event);
        }
    }
}

// Same mixing formula as BlueCodegenPolicy's row-reuse sketch so sideband
// tags live in the sketch's 16-bit domain.
inline uint16_t d0_pressure_row_tag(uint32_t bank, uint32_t row) {
    const uint32_t mixed = bank * 2654435761u ^ row * 2246822519u;
    return static_cast<uint16_t>((mixed ^ (mixed >> 16)) & 0xffffu);
}

}  // namespace Ramulator
