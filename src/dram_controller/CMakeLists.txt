add_library(ramulator-controller OBJECT)

# Bind the QoS datapath reported at runtime to the exact scheduler and LLC
# sources that implement it.  A matched experiment can therefore distinguish
# a genuinely loaded one-bit QoS/aging comparator from a stale shared library.
set(HAMMEREVO_QOS_LLC_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/../frontend/impl/processor/bhO3/bhllc.cpp")
set(HAMMEREVO_QOS_LLC_HEADER
    "${CMAKE_CURRENT_SOURCE_DIR}/../frontend/impl/processor/bhO3/bhllc.h")
set(HAMMEREVO_BH_QOS_SCHEDULER_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/impl/scheduler/bh_scheduler.cpp")
set(HAMMEREVO_PRAC_QOS_SCHEDULER_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/impl/scheduler/prac_scheduler.cpp")
set_property(
  DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${HAMMEREVO_QOS_LLC_SOURCE}"
  "${HAMMEREVO_QOS_LLC_HEADER}"
  "${HAMMEREVO_BH_QOS_SCHEDULER_SOURCE}"
  "${HAMMEREVO_PRAC_QOS_SCHEDULER_SOURCE}"
)
file(SHA256 "${HAMMEREVO_QOS_LLC_SOURCE}" HAMMEREVO_QOS_LLC_SOURCE_SHA256)
file(SHA256 "${HAMMEREVO_QOS_LLC_HEADER}" HAMMEREVO_QOS_LLC_HEADER_SHA256)
file(SHA256 "${HAMMEREVO_BH_QOS_SCHEDULER_SOURCE}"
     HAMMEREVO_BH_QOS_SCHEDULER_SOURCE_SHA256)
file(SHA256 "${HAMMEREVO_PRAC_QOS_SCHEDULER_SOURCE}"
     HAMMEREVO_PRAC_QOS_SCHEDULER_SOURCE_SHA256)
string(
  SHA256 HAMMEREVO_BH_QOS_DATAPATH_SHA256
  "${HAMMEREVO_BH_QOS_SCHEDULER_SOURCE_SHA256}:${HAMMEREVO_QOS_LLC_SOURCE_SHA256}:${HAMMEREVO_QOS_LLC_HEADER_SHA256}"
)
string(
  SHA256 HAMMEREVO_PRAC_QOS_DATAPATH_SHA256
  "${HAMMEREVO_PRAC_QOS_SCHEDULER_SOURCE_SHA256}:${HAMMEREVO_QOS_LLC_SOURCE_SHA256}:${HAMMEREVO_QOS_LLC_HEADER_SHA256}"
)
target_compile_definitions(
  ramulator-controller PRIVATE
  HAMMEREVO_BH_QOS_DATAPATH_SHA256="${HAMMEREVO_BH_QOS_DATAPATH_SHA256}"
  HAMMEREVO_PRAC_QOS_DATAPATH_SHA256="${HAMMEREVO_PRAC_QOS_DATAPATH_SHA256}"
)

target_sources(
  ramulator-controller PRIVATE
  bhcontroller.h 
  bhscheduler.h 
  controller.h 
  scheduler.h 
  plugin.h
  refresh.h
  rowpolicy.h

  impl/dummy_controller.cpp
  impl/generic_dram_controller.cpp
  impl/bh_dram_controller.cpp
  impl/prac_dram_controller.cpp
  
  impl/scheduler/blocking_scheduler.cpp
  impl/scheduler/generic_scheduler.cpp
  impl/scheduler/bh_scheduler.cpp
  impl/scheduler/bliss_scheduler.cpp
  impl/scheduler/prac_scheduler.cpp

  impl/refresh/all_bank_refresh.cpp

  impl/rowpolicy/basic_rowpolicies.cpp

  impl/plugin/trace_recorder.cpp
  impl/plugin/cmd_counter.cpp
  impl/plugin/para.cpp
  impl/plugin/graphene.cpp
  impl/plugin/oracle_rh.cpp
  impl/plugin/twice.cpp
  impl/plugin/hydra.cpp
  impl/plugin/rrs.cpp
  impl/plugin/cmd_dumper.cpp
  impl/plugin/rfm_manager.cpp
  impl/plugin/mithril.cpp
  impl/plugin/mithrilplus.h
  impl/plugin/throttle_rfm.cpp
  impl/plugin/panopticon.cpp
  impl/plugin/silver_bullet.cpp
  impl/plugin/dummy_mitigation.cpp
  impl/plugin/policy_sidecar.cpp
  impl/plugin/throttle_rega.cpp
  impl/plugin/aqua.cpp

  impl/plugin/bliss.cpp
  impl/plugin/bliss.h

  impl/plugin/miss_tracker.cpp
  impl/plugin/miss_tracker.h

  impl/plugin/blockhammer.cpp
  impl/plugin/blockhammer.h
  impl/plugin/blockhammerutil.h
  impl/plugin/blockhammerthrottler.h

  impl/plugin/throttleable.cpp
  impl/plugin/throttleable.h
  
  impl/plugin/prac.cpp
  impl/plugin/prac.h

  impl/pluginutil/windowed_counter.cpp
  impl/pluginutil/windowed_counter.h
  impl/pluginutil/self_extending_counter.cpp
  impl/pluginutil/self_extending_counter.h

  impl/pluginutil/device_config.cpp
  impl/pluginutil/device_config.h

  impl/plugin/throttler.cpp
  impl/plugin/blue_codegen_d9ef2381.cpp
  impl/plugin/blue_codegen_runtime.cpp
  )

target_link_libraries(
  ramulator
  PRIVATE
  ramulator-controller
)
