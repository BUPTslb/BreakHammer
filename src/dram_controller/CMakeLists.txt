add_library(ramulator-controller OBJECT)

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
  impl/plugin/blue_codegen_d675efcd.cpp
  impl/plugin/blue_codegen_56aee84a.cpp
  impl/plugin/blue_codegen_390542a6.cpp
  impl/plugin/blue_codegen_c0e4b3e8.cpp
  impl/plugin/blue_codegen_25a70193.cpp
  impl/plugin/blue_codegen_a5afc433.cpp
  impl/plugin/blue_codegen_85ac3c8d.cpp
  impl/plugin/blue_codegen_c558d9b1.cpp
  impl/plugin/blue_codegen_2dd4e335.cpp
  impl/plugin/blue_codegen_71c5c4ff.cpp
  impl/plugin/blue_codegen_790aaec5.cpp
  impl/plugin/blue_codegen_f1d97298.cpp
  impl/plugin/blue_codegen_e3943233.cpp
  impl/plugin/blue_codegen_252c8e3d.cpp
  impl/plugin/blue_codegen_d58a5c5d.cpp
  impl/plugin/blue_codegen_f3be9e3d.cpp
  impl/plugin/blue_codegen_fc31b6b3.cpp
  impl/plugin/blue_codegen_6c2729bc.cpp
  impl/plugin/blue_codegen_760c6347.cpp
  impl/plugin/blue_codegen_a5dd520c.cpp
  impl/plugin/blue_codegen_d3733fe9.cpp
  impl/plugin/blue_codegen_898c2674.cpp
  impl/plugin/blue_codegen_00361f34.cpp
  impl/plugin/blue_codegen_4fd29245.cpp
  impl/plugin/blue_codegen_6289f4b8.cpp
  impl/plugin/blue_codegen_4ed20035.cpp
  impl/plugin/blue_codegen_8a314755.cpp
  impl/plugin/blue_codegen_44c6c29d.cpp
  impl/plugin/blue_codegen_7c92cbbf.cpp
  impl/plugin/blue_codegen_77a96662.cpp
  impl/plugin/blue_codegen_7d084d61.cpp
  impl/plugin/blue_codegen_runtime.cpp
  )

target_link_libraries(
  ramulator
  PRIVATE
  ramulator-controller
)
