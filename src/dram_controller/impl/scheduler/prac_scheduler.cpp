#include <vector>

#include "base/base.h"
#include "dram_controller/bhcontroller.h"
#include "dram_controller/bhscheduler.h"
#include "dram_controller/impl/plugin/prac.h"
#include "frontend/impl/processor/bhO3/bhO3.h"
#include "frontend/impl/processor/bhO3/bhllc.h"

#ifndef HAMMEREVO_PRAC_QOS_DATAPATH_SHA256
#define HAMMEREVO_PRAC_QOS_DATAPATH_SHA256 "unavailable"
#endif

namespace Ramulator {

class PRACScheduler : public IBHScheduler, public Implementation {
RAMULATOR_REGISTER_IMPLEMENTATION(IBHScheduler, PRACScheduler, "PRACScheduler", "PRAC Scheduler.")

private:
    IDRAM* m_dram;
    IBHDRAMController* m_ctrl;
    IPRAC* m_prac;
    BHO3LLC* m_llc = nullptr;

    std::unordered_map<int, int> lut_cycles_needed;

    Clk_t m_clk = 0;
    int m_bank_addr_idx = -1;
    int m_bank_slot_count = 0;
    uint64_t m_qos_max_starvation_cycles = 1100000;
    uint64_t s_qos_priority_decisions = 0;
    uint64_t s_qos_aged_comparisons = 0;
    uint64_t s_qos_launch_deferrals = 0;
    uint64_t s_qos_background_work_conserving_selections = 0;

    bool m_is_debug = false; 

public:
    void init() override {
      m_is_debug = param<bool>("debug").default_val(false);
      m_qos_max_starvation_cycles =
        param<uint64_t>("qos_max_starvation_cycles")
          .desc("Maximum controller cycles before a background request ages to normal priority.")
          .default_val(1100000);
      m_qos_max_starvation_cycles =
        std::max<uint64_t>(1, m_qos_max_starvation_cycles);
      register_stat(s_qos_priority_decisions)
        .name("scheduler_qos_priority_decisions");
      register_stat(s_qos_aged_comparisons)
        .name("scheduler_qos_aged_comparisons");
      register_stat(s_qos_launch_deferrals)
        .name("scheduler_qos_launch_deferrals");
      register_stat(s_qos_background_work_conserving_selections)
        .name("scheduler_qos_background_work_conserving_selections");
      std::cout << "scheduler_impl: PRACScheduler" << std::endl;
      std::cout << "scheduler_qos_datapath_sha256: "
                << HAMMEREVO_PRAC_QOS_DATAPATH_SHA256 << std::endl;
      std::cout << "scheduler_qos_max_starvation_cycles: "
                << m_qos_max_starvation_cycles << std::endl;
      std::cout << "scheduler_qos_max_priority_disadvantage_cycles: "
                << m_qos_max_starvation_cycles << std::endl;
      std::cout << "scheduler_qos_work_conserving: 0" << std::endl;
      std::cout << "scheduler_qos_same_bank_launch_guard: 1" << std::endl;
      std::cout << "scheduler_qos_cross_bank_work_conserving: 1" << std::endl;
      std::cout << "scheduler_qos_partial_request_drain_safe: 1" << std::endl;
    }

    void setup(IFrontEnd* frontend, IMemorySystem* memory_system) override {
      m_ctrl = cast_parent<IBHDRAMController>();
      m_dram = m_ctrl->m_dram;
      m_bank_addr_idx = m_dram->m_levels("bank");
      m_bank_slot_count = 1;
      for (int level = 0; level <= m_bank_addr_idx; level++) {
        m_bank_slot_count *= m_dram->m_organization.count[(size_t) level];
      }
      if (m_bank_slot_count <= 0 || m_bank_slot_count > 64) {
        throw std::runtime_error(
          "PRACScheduler same-bank launch guard supports at most 64 bank slots");
      }
      std::cout << "scheduler_qos_bank_slots: "
                << m_bank_slot_count << std::endl;
      m_llc = static_cast<BHO3*>(frontend)->get_llc();
      m_prac = m_ctrl->get_plugin<IPRAC>();

        if (!m_prac) {
            std::cout << "[RAMULATOR::PRACSched] Need PRAC plugin!" << std::endl;
            std::exit(0);
        }
    }

    ReqBuffer::iterator compare(ReqBuffer::iterator req1, ReqBuffer::iterator req2) override {
        bool fits1 = req1->scratch0;
        bool fits2 = req2->scratch0;

        if (fits1 ^ fits2) {
            if (fits1) {
                return req1;
            }
            else {
                return req2;
            }
        }

        bool ready1 = req1->scratch1;
        bool ready2 = req2->scratch1;

        if (ready1 ^ ready2) {
            if (ready1) {
                return req1;
            }
            else {
                return req2;
            }
        }

        // Within PRAC's recovery-fit class, work conservation precedes QoS:
        // a ready background command must not lose to an unready normal one.
        const int qos1 = effective_qos(*req1);
        const int qos2 = effective_qos(*req2);
        if (qos1 != qos2) {
          s_qos_priority_decisions++;
          return qos1 < qos2 ? req1 : req2;
        }

        // Fallback to FCFS
        if (req1->arrive <= req2->arrive) {
            return req1;
        }
        else {
            return req2;
        } 
    }

    ReqBuffer::iterator get_best_request(ReqBuffer& buffer) override {
        return get_best_request(buffer, false, nullptr, &buffer, nullptr);
    }

    ReqBuffer::iterator get_best_request(
        ReqBuffer& buffer,
        bool is_active_buffer,
        ReqBuffer* active_buffer,
        ReqBuffer* read_buffer,
        ReqBuffer* write_buffer
    ) override {
        if (buffer.size() == 0) {
            return buffer.end();
        }

        Clk_t next_recovery = m_prac->next_recovery_cycle();
        for (auto& req : buffer) {
            req.command = m_dram->get_preq_command(req.final_command, req.addr_vec);
            req.scratch0 = m_clk + m_prac->min_cycles_with_preall(req) < next_recovery;
            req.scratch1 = m_dram->check_ready(req.command, req.addr_vec);
        }

        auto candidate = buffer.end();
        bool guarded_ready_background = false;
        const uint64_t normal_pending_banks = is_active_buffer
            ? 0 : normal_pending_bank_mask(
                active_buffer, read_buffer, write_buffer);
        for (auto next = buffer.begin(); next != buffer.end(); next++) {
            if (!is_active_buffer
                    && launch_guard_blocks(*next, normal_pending_banks)) {
                guarded_ready_background = guarded_ready_background
                    || (static_cast<bool>(next->scratch0)
                        && static_cast<bool>(next->scratch1));
                continue;
            }
            candidate = candidate == buffer.end()
                ? next : compare(candidate, next);
        }
        if (guarded_ready_background) {
            s_qos_launch_deferrals++;
        }
        if (candidate == buffer.end()) {
            return candidate;
        }
        // The active-buffer call bypasses the launch guard, preserving PRAC's
        // recovery-fit ordering and allowing every partially issued request to
        // drain. Only untouched same-bank background launches are deferred.
        if (effective_qos(*candidate) > 0) {
            s_qos_background_work_conserving_selections++;
        }
        return candidate;
    }

    virtual void tick() override {
      m_clk++;
    }

private:
    int configured_qos(const Request& req) const {
      return m_llc == nullptr ? 0 : m_llc->get_qos_class(req.source_id);
    }

    bool is_aged_background(const Request& req) const {
      return configured_qos(req) > 0 && req.arrive >= 0
        && (uint64_t) (m_clk - req.arrive) >= m_qos_max_starvation_cycles;
    }

    int bank_slot(const Request& req) const {
      if (m_bank_addr_idx < 0
          || (size_t) m_bank_addr_idx >= req.addr_vec.size()) {
        return -1;
      }
      int slot = 0;
      for (int level = 0; level <= m_bank_addr_idx; level++) {
        const int count = m_dram->m_organization.count[(size_t) level];
        const int value = req.addr_vec[(size_t) level];
        if (count <= 0 || value < 0 || value >= count) {
          return -1;
        }
        slot = slot * count + value;
      }
      return slot >= 0 && slot < m_bank_slot_count ? slot : -1;
    }

    uint64_t normal_pending_bank_mask(
      ReqBuffer* active_buffer,
      ReqBuffer* read_buffer,
      ReqBuffer* write_buffer
    ) const {
      uint64_t mask = 0;
      ReqBuffer* buffers[] = {active_buffer, read_buffer, write_buffer};
      for (ReqBuffer* pending : buffers) {
        if (pending == nullptr) {
          continue;
        }
        for (const auto& other : pending->buffer) {
          if (configured_qos(other) != 0) {
            continue;
          }
          const int slot = bank_slot(other);
          if (slot >= 0) {
            mask |= uint64_t{1} << slot;
          }
        }
      }
      return mask;
    }

    bool launch_guard_blocks(
      const Request& req, uint64_t normal_pending_banks
    ) const {
      if (configured_qos(req) == 0 || is_aged_background(req)) {
        return false;
      }
      const int slot = bank_slot(req);
      return slot >= 0
        && (normal_pending_banks & (uint64_t{1} << slot)) != 0;
    }

    int effective_qos(const Request& req) {
      int qos = configured_qos(req);
      if (qos > 0 && req.arrive >= 0
          && (uint64_t) (m_clk - req.arrive) >= m_qos_max_starvation_cycles) {
        s_qos_aged_comparisons++;
        return 0;
      }
      return qos;
    }
};

}       // namespace Ramulator
