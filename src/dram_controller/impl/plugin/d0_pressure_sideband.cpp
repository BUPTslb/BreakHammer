// Registry implementation for the D0 pressure sideband (APS).
// See d0_pressure_sideband.h for the contract.  This translation unit is
// the single definition site so every plugin (D0 emitters and the D1
// sink) shares one registry instance.
#include "dram_controller/impl/plugin/d0_pressure_sideband.h"

namespace Ramulator {

namespace {
ID0PressureSink* g_d0_pressure_sink = nullptr;
}  // namespace

void d0_pressure_sideband_register(ID0PressureSink* sink) {
    g_d0_pressure_sink = sink;
}

ID0PressureSink* d0_pressure_sideband_sink() {
    return g_d0_pressure_sink;
}

}  // namespace Ramulator
