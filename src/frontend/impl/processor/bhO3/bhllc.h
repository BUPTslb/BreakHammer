#ifndef     RAMULATOR_FRONTEND_PROCESSOR_BH_O3_LLC_H
#define     RAMULATOR_FRONTEND_PROCESSOR_BH_O3_LLC_H

#include <vector>
#include <list>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <functional>
#include <cstdint>
#include <limits>
#include <array>

#include "base/clocked.h"
#include "base/debug.h"
#include "base/type.h"
#include "base/request.h"
#include "memory_system/bh_memory_system.h"

// BH Changes Begin
#include <unordered_set>
// BH Changes End

namespace Ramulator {

DECLARE_DEBUG_FLAG(DBHO3LLC);
// ENABLE_DEBUG_FLAG(DBHO3LLC);

class BHO3LLC : public Clocked<BHO3LLC> {
  friend class BHO3;

  struct Line {
    Addr_t addr = -1;
    Addr_t tag = -1;
    bool dirty = false;
    bool ready = false;   // Whether this line is ready (i.e., is still inflight?)
  };

  private:
    using CacheSet_t = std::list<Line>;   // LRU queue for the set. The head of the list is the least-recently-used way.
    std::unordered_map<int, CacheSet_t> m_cache_sets;
    
    using MSHREntry_t = std::pair<Addr_t, CacheSet_t::iterator>;
    using MSHR_t = std::vector<MSHREntry_t>;
    MSHR_t m_mshrs;
    std::unordered_map<Addr_t, std::vector<Request>> m_receive_requests;

    // Request that miss in the LLC with the clock cycle (current cycle + llc latency) that they 
    // should be sent to the memory system
    std::list<std::pair<Clk_t, Request>> m_miss_list;

    // Request that hit in the LLC with the clock cycle (current cycle + llc latency) that they 
    // should be sent back to the core (calls the callback)
    std::list<std::pair<Clk_t, Request>> m_hit_list;

    IMemorySystem* m_memory_system;

    Logger_t m_logger;

    // BH Changes Begin
    std::vector<int> m_allocated_mshrs;
    std::vector<int> m_blacklist_max_mshrs;
    std::vector<bool> m_blacklist_status;
    int m_num_cores = 0;

    // HammerEVO D1 admission actuator.  It limits the rate of NEW LLC misses
    // per protection-domain principal.  Cache hits and requests that merge
    // into an existing MSHR never consume a token.
    struct AdmissionBucket {
      bool enabled = false;
      uint64_t tokens = 0;
      uint64_t refill_tokens = 1;
      uint64_t refill_period_cycles = 1;
      uint64_t burst = 1;
      uint64_t max_denial_cycles = 1;
      Clk_t last_refill = 0;
      Clk_t last_admit = 0;
      Clk_t denial_begin = std::numeric_limits<Clk_t>::max();
      uint64_t admitted = 0;
      uint64_t denied = 0;
      uint64_t forced_liveness = 0;
      uint64_t refills = 0;
      uint64_t max_observed_denial_cycles = 0;
    };
    std::vector<int> m_admission_principal_by_core;
    std::vector<AdmissionBucket> m_admission_buckets;
    // Four trusted launch-entitlement classes share four aggregate buckets.
    // A bounded source-pending bitmap and round-robin pointer make grant order
    // independent of the opaque-principal partition. Source IDs are fixed
    // hardware request ports and cannot be forged by changing that partition.
    static constexpr int kAdmissionServiceClasses = 4;
    static constexpr int kAdmissionPrincipalLimit = 32;
    static constexpr int kAdmissionSourceLimit = 32;
    std::vector<int> m_admission_service_class_by_core;
    std::array<AdmissionBucket, kAdmissionServiceClasses>
      m_service_class_admission_buckets{};
    std::array<uint32_t, kAdmissionServiceClasses>
      m_service_class_pending_sources{};
    std::array<int, kAdmissionServiceClasses>
      m_service_class_rr_next_source{};
    // A bounded pre-allocation escrow for service-class burst detection.
    // Unlike the successful-new-miss observer, this gate sees a request before
    // it irreversibly allocates an MSHR.  It keeps at most four exact
    // (source, cache-line) fingerprints so retries do not inflate the burst.
    // Sparse traffic is released after a finite deadline; a threshold crossing
    // atomically starts the existing split-invariant class admission bucket
    // with zero tokens.
    static constexpr int kServiceClassProbationEntries = 4;
    enum class ServiceClassProbationMode : uint8_t {
      Disabled = 0,
      Armed = 1,
      Collecting = 2,
      Bypass = 3,
      Limited = 4,
    };
    struct ServiceClassProbationGate {
      bool enabled = false;
      ServiceClassProbationMode mode = ServiceClassProbationMode::Disabled;
      uint8_t distinct_threshold = kServiceClassProbationEntries;
      uint8_t distinct_count = 0;
      uint64_t deadline_cycles = 1;
      uint64_t principal_service_epoch_cycles = 0;
      uint64_t initial_tokens_on_limit = 0;
      uint64_t refill_tokens = 1;
      uint64_t refill_period_cycles = 1;
      uint64_t burst = 1;
      uint64_t max_denial_cycles = 1;
      Clk_t first_seen = 0;
      Clk_t first_limited = 0;
      Clk_t service_epoch_begin = 0;
      uint32_t served_principals = 0;
      bool oldest_release_pending = false;
      std::array<Addr_t, kServiceClassProbationEntries> line_addr{};
      std::array<int, kServiceClassProbationEntries> source_id{};
      uint64_t held_requests = 0;
      uint64_t duplicate_retries = 0;
      uint64_t deadline_bypasses = 0;
      uint64_t limited_transitions = 0;
      uint64_t service_epoch_resets = 0;
      uint64_t service_epoch_denials = 0;
      uint64_t oldest_release_denials = 0;
      uint64_t oldest_releases = 0;
      uint64_t max_observed_hold_cycles = 0;
    };
    std::array<ServiceClassProbationGate, kAdmissionServiceClasses>
      m_service_class_probation_gates{};
    // One scheduler QoS bit per source. Class 0 is normal service; class 1 is
    // bounded background service. Policies address opaque principals, and
    // the LLC expands that decision to member cores using the same principal
    // map as admission control.
    std::vector<int> m_qos_class_by_core;
    // Optional D1 observer: successful NEW-MSHR allocations per opaque
    // protection domain. It is disabled unless the loaded strategy declares
    // and uses the corresponding capability.
    bool m_new_miss_observer_enabled = false;
    std::vector<uint64_t> m_new_miss_allocations_principal;
    // Optional registered event path from the LLC allocation point to the
    // generated D1 FSM. The callback models a valid+source-id hardware event;
    // it is installed only when the candidate declares that capability.
    std::function<void(int)> m_new_miss_event_callback;
    // BH Changes End

  public:
    int m_latency;

    size_t m_size_bytes;
    size_t m_linesize_bytes;
    int m_associativity;
    int m_set_size;
    int m_num_mshrs;

    Addr_t m_index_mask;
    int m_index_offset;
    int m_tag_offset;


    int s_llc_read_access = 0;
    int s_llc_write_access = 0;
    int s_llc_read_misses = 0;
    int s_llc_write_misses = 0;
    int s_llc_eviction = 0;
    int s_llc_mshr_unavailable = 0;
    int s_llc_mshr_blacklisted = 0;
    uint64_t s_llc_admission_admitted = 0;
    uint64_t s_llc_admission_denied = 0;
    uint64_t s_llc_admission_forced_liveness = 0;
    uint64_t s_llc_admission_refills = 0;
    uint64_t s_llc_admission_max_denial_cycles = 0;
    std::vector<uint64_t> s_llc_admission_admitted_core;
    std::vector<uint64_t> s_llc_admission_denied_core;
    std::vector<int> s_llc_qos_class_core;
    std::vector<uint64_t> s_llc_qos_class_changes_core;
    
    // BH Changes Begin
    int m_bh_max_mshr = -1;
    int m_rank_level = -1;
    int m_bank_group_level = -1;
    int m_bank_level = -1;
    int m_row_level = -1;

    int m_num_ranks = -1;
    int m_num_banks_per_rank = -1;
    int m_num_rows_per_bank = -1;

    int m_mshr_per_core = -1;
    // BH Changes End

  public:
    BHO3LLC(int latency, int size_bytes, int linesize_bytes, int associativity, int num_mshrs, int num_cores);
    void connect_memory_system(IMemorySystem* memory_system);
    
    void tick();
    bool send(Request& req);
    void receive(Request& req);

    void serialize(std::string serialization_filename);
    void deserialize(std::string serialization_filename);
    void dump_llc();
    // BH Changes Begin
    int get_mshrs_per_core();
    int get_blacklist_max_mshrs(int source_id); 
    void set_blacklist_max_mshrs(int source_id, int max_mshr);
    // Currently not switching the following to setter for backwards portability.
    void add_blacklist(int source_id);
    void erase_blacklist(int source_id);
    void configure_admission_principals(const std::vector<int>& principal_by_core);
    void configure_admission_service_classes(
      const std::vector<int>& service_class_by_core
    );
    void configure_new_miss_observer(bool enabled);
    void configure_new_miss_event_callback(std::function<void(int)> callback);
    void set_admission_budget(
      int principal,
      uint64_t refill_tokens,
      uint64_t refill_period_cycles,
      uint64_t burst,
      uint64_t max_denial_cycles
    );
    void clear_admission_budget(int principal);
    void set_admission_tokens(int principal, uint64_t tokens);
    uint64_t get_admission_tokens(int principal);
    uint64_t get_admission_admitted(int principal) const;
    uint64_t get_admission_denied(int principal) const;
    uint64_t get_admission_forced_liveness(int principal) const;
    uint64_t get_admission_refills(int principal) const;
    uint64_t get_admission_max_denial_cycles(int principal) const;
    void set_service_class_admission_budget(
      int service_class,
      uint64_t refill_tokens,
      uint64_t refill_period_cycles,
      uint64_t burst,
      uint64_t max_denial_cycles
    );
    void clear_service_class_admission_budget(int service_class);
    void set_service_class_admission_tokens(
      int service_class, uint64_t tokens
    );
    uint64_t get_service_class_admission_tokens(int service_class);
    uint64_t get_service_class_admission_admitted(int service_class) const;
    uint64_t get_service_class_admission_denied(int service_class) const;
    uint64_t get_service_class_admission_forced_liveness(
      int service_class
    ) const;
    uint64_t get_service_class_admission_refills(int service_class) const;
    uint64_t get_service_class_admission_max_denial_cycles(
      int service_class
    ) const;
    void arm_service_class_probation_gate(
      int service_class,
      uint64_t distinct_threshold,
      uint64_t deadline_cycles,
      uint64_t principal_service_epoch_cycles,
      uint64_t initial_tokens_on_limit,
      uint64_t refill_tokens,
      uint64_t refill_period_cycles,
      uint64_t burst,
      uint64_t max_denial_cycles
    );
    void clear_service_class_probation_gate(int service_class);
    uint64_t get_service_class_probation_mode(int service_class) const;
    uint64_t get_service_class_probation_distinct_count(
      int service_class
    ) const;
    uint64_t get_service_class_probation_distinct_threshold(
      int service_class
    ) const;
    uint64_t get_service_class_probation_deadline_cycles(
      int service_class
    ) const;
    uint64_t get_service_class_probation_refill_period_cycles(
      int service_class
    ) const;
    uint64_t get_service_class_probation_service_epoch_cycles(
      int service_class
    ) const;
    uint64_t get_service_class_probation_initial_tokens(
      int service_class
    ) const;
    uint64_t get_service_class_probation_held(int service_class) const;
    uint64_t get_service_class_probation_duplicate_retries(
      int service_class
    ) const;
    uint64_t get_service_class_probation_deadline_bypasses(
      int service_class
    ) const;
    uint64_t get_service_class_probation_limited_transitions(
      int service_class
    ) const;
    uint64_t get_service_class_probation_service_epoch_resets(
      int service_class
    ) const;
    uint64_t get_service_class_probation_service_epoch_denials(
      int service_class
    ) const;
    uint64_t get_service_class_probation_oldest_release_denials(
      int service_class
    ) const;
    uint64_t get_service_class_probation_oldest_releases(
      int service_class
    ) const;
    uint64_t get_service_class_probation_max_hold_cycles(
      int service_class
    ) const;
    uint64_t get_service_class_probation_first_limited_cycle(
      int service_class
    ) const;
    uint64_t get_new_miss_allocations(int principal) const;
    void set_principal_qos_class(int principal, int qos_class);
    int get_qos_class(int source_id) const;
    bool clflush(Addr_t addr);
    // BH Changes End
  private:
    int get_index(Addr_t addr)  { return (addr >> m_index_offset) & m_index_mask; }
    Addr_t get_tag(Addr_t addr) { return (addr >> m_tag_offset); }
    Addr_t align(Addr_t addr)   { return (addr & ~(m_linesize_bytes-1l)); }

    CacheSet_t& get_set(Addr_t addr);
    CacheSet_t::iterator allocate_line(CacheSet_t& set, Addr_t addr);
    bool need_eviction(const CacheSet_t& set, Addr_t addr);
    void evict_line(CacheSet_t& set, CacheSet_t::iterator victim_it);

    CacheSet_t::iterator check_set_hit(CacheSet_t& set, Addr_t addr);
    MSHR_t::iterator check_mshr_hit(Addr_t addr);
    std::unordered_set<uint32_t>& get_bank_blacklist(Request& req);
    void refill_admission_bucket(AdmissionBucket& bucket);
    bool admit_new_miss(const Request& req);
    void record_new_miss_allocation(int source_id);
};

}        // namespace Ramulator


#endif   // RAMULATOR_FRONTEND_PROCESSOR_BH_O3_LLC_H
