#include <algorithm>
#include <iostream>
#include "frontend/impl/processor/bhO3/bhllc.h"
#include "dram/dram.h"

namespace Ramulator {

BHO3LLC::BHO3LLC(int latency, int size_bytes, int linesize_bytes, int associativity, int num_mshrs, int num_cores):
m_latency(latency), m_size_bytes(size_bytes), m_linesize_bytes(linesize_bytes), m_associativity(associativity), m_num_mshrs(num_mshrs), m_num_cores(num_cores) {
  m_logger = Logging::create_logger("BHO3LLC");

  m_set_size = m_size_bytes / (m_linesize_bytes * m_associativity);
  m_index_mask = m_set_size - 1;
  m_index_offset = calc_log2(m_linesize_bytes);
  m_tag_offset = calc_log2(m_set_size) + m_index_offset;
  // BH Changes Begin
  m_mshr_per_core = num_mshrs / num_cores;
  m_blacklist_max_mshrs.resize(num_cores);
  m_blacklist_status.resize(num_cores);
  m_allocated_mshrs.resize(num_cores);
  m_admission_principal_by_core.resize(num_cores);
  m_admission_service_class_by_core.assign(num_cores, -1);
  m_qos_class_by_core.assign(num_cores, 0);
  s_llc_admission_admitted_core.resize(num_cores);
  s_llc_admission_denied_core.resize(num_cores);
  s_llc_qos_class_core.assign(num_cores, 0);
  s_llc_qos_class_changes_core.assign(num_cores, 0);
  for (int core = 0; core < num_cores; core++) {
    m_admission_principal_by_core[core] = core;
  }
  // BH Changes End

  DEBUG_LOG(DBHO3LLC, m_logger, "Index mask: {0:x}", m_index_mask);
  DEBUG_LOG(DBHO3LLC, m_logger, "Index offset: {}",  m_index_offset);
  DEBUG_LOG(DBHO3LLC, m_logger, "Tag offset: {}",    m_tag_offset);
}

void BHO3LLC::tick() {
  m_clk++;

  // Keep the liveness evidence current even when the denied request has not
  // yet reached its forced-admission deadline.
  for (auto& bucket : m_admission_buckets) {
    if (bucket.enabled
        && bucket.denial_begin != std::numeric_limits<Clk_t>::max()) {
      uint64_t denied_for = (uint64_t) (m_clk - bucket.denial_begin);
      bucket.max_observed_denial_cycles = std::max(
        bucket.max_observed_denial_cycles, denied_for
      );
      s_llc_admission_max_denial_cycles = std::max(
        s_llc_admission_max_denial_cycles, denied_for
      );
    }
  }
  for (auto& bucket : m_service_class_admission_buckets) {
    if (bucket.enabled
        && bucket.denial_begin != std::numeric_limits<Clk_t>::max()) {
      uint64_t denied_for = (uint64_t) (m_clk - bucket.denial_begin);
      bucket.max_observed_denial_cycles = std::max(
        bucket.max_observed_denial_cycles, denied_for
      );
      s_llc_admission_max_denial_cycles = std::max(
        s_llc_admission_max_denial_cycles, denied_for
      );
    }
  }
  for (auto& gate : m_service_class_probation_gates) {
    if (gate.enabled
        && gate.mode == ServiceClassProbationMode::Collecting) {
      uint64_t held_for = (uint64_t) (m_clk - gate.first_seen);
      gate.max_observed_hold_cycles = std::max(
        gate.max_observed_hold_cycles,
        std::min(held_for, gate.deadline_cycles)
      );
    }
  }

  // Send miss requests to the memory system when LLC latency is met
  // TODO: Optimization by assuming in-order issue?
  auto it = m_miss_list.begin(); 
  while (it != m_miss_list.end()) {
    if (m_clk >= it->first) {
      if (!m_memory_system->send(it->second)) {
        it++;
      }
      else {
        it = m_miss_list.erase(it);
      }
    } else {
      it++;
    }
  }

  // call hit request callback when LLC latency is met
  it = m_hit_list.begin();
  while (it != m_hit_list.end()) {
    if (m_clk >= it->first) {
      std::vector<Request> _req_v{it->second};
      m_receive_requests[it->second.addr] = _req_v;

      it->second.callback(it->second);
      it = m_hit_list.erase(it);
    } 
    else {
      it++;
    }
  }
}

bool BHO3LLC::send(Request& req) {
  CacheSet_t& set = get_set(req.addr);

  if (req.type_id == Request::Type::Read) {
    s_llc_read_access++;
  } else if (req.type_id == Request::Type::Write) {
    s_llc_write_access++;
  }

  if (auto line_it = check_set_hit(set, req.addr); line_it != set.end()) {
    // Hit in the set
    DEBUG_LOG(DBHO3LLC, m_logger, 
    "[Clk={}] Request Source: {}, Type: {}, Addr: {}, Index: {}, Tag: {}. Hit, will finish at Clk={}", 
    m_clk, req.source_id, req.type_id, req.addr, get_index(req.addr), get_tag(req.addr), m_clk, m_clk + m_latency
    );

    // Update the LRU status
    set.push_back({req.addr, get_tag(req.addr), line_it->dirty || (req.type_id == Request::Type::Write), true});
    set.erase(line_it);

    // Add to the hit list to callback when finished
    m_hit_list.push_back(std::make_pair(m_clk + m_latency, req));
    return true;
  } else {
    // Miss in the set
    DEBUG_LOG(DBHO3LLC, m_logger, 
    "[Clk={}] Request Source: {}, Type: {}, Addr: {}, Index: {}, Tag: {}. Miss.", 
    m_clk, req.source_id, req.type_id, req.addr, get_index(req.addr), get_tag(req.addr), m_clk, m_clk + m_latency
    );

    if (req.type_id == Request::Type::Read) {
      s_llc_read_misses++;
    } else if (req.type_id == Request::Type::Write) {
      s_llc_write_misses++;
    }

    bool dirty = (req.type_id == Request::Type::Write);
    if (req.type_id == Request::Type::Write) {
      req.type_id = Request::Type::Read;
    }

    // MSHR lookup
    auto mshr_it = check_mshr_hit(req.addr);
    if (mshr_it != m_mshrs.end()) {
      DEBUG_LOG(DBHO3LLC, m_logger,  "MSHR Hit.", m_clk);
      // Add new req to MSHR_requests
      m_receive_requests[mshr_it->first].push_back(req);

      mshr_it->second->dirty = dirty || mshr_it->second->dirty;
      return true;
    }

    // BH Changes Begin
    // First request of this core (we don't have application/thread ids)
    // Blacklisted core 
    if (req.source_id >= 0 && m_blacklist_status[req.source_id]
    &&  m_allocated_mshrs[req.source_id] >= m_blacklist_max_mshrs[req.source_id]) {
      s_llc_mshr_blacklisted++;
      return false;
    }
    // BH Changes End
    
    // MSHR miss
    // Check if there is available MSHR entry
    if (m_mshrs.size() == m_num_mshrs) {
      DEBUG_LOG(DBHO3LLC, m_logger,  "No MSHR entry available.", m_clk);
      s_llc_mshr_unavailable++;
      return false;
    }

    // Check if there is available cache line in the set
    bool line_available = false;
    if (set.size() < m_associativity) {
      line_available = true;
    } else {
      for (const auto& line : set) {
        if (line.ready) {
          line_available = true;
        }
      }
    }
    if (!line_available) {
      DEBUG_LOG(DBHO3LLC, m_logger,  "No cache line available in the set.", m_clk);
      return false;
    }

    // True rate actuation belongs after cache/MSHR coalescing and ordinary
    // allocation feasibility checks, immediately before a NEW MSHR is
    // allocated.  This avoids charging hits, merged misses, or requests that
    // could not have entered the memory system anyway.
    if (!admit_new_miss(req)) {
      return false;
    }

    // Allocate a new cache line
    auto newline_it = allocate_line(set, req.addr);
    if (newline_it == set.end()) {
      // Should this happen?
      throw std::runtime_error("Failed to allocate new line when there is available entry.");
      return false;
    }
    newline_it->dirty = dirty;
    record_new_miss_allocation(req.source_id);
    
    // Add to MSHR entries
    m_mshrs.push_back(std::make_pair(req.addr, newline_it));
    // Add Request to MSHR_requests
    std::vector<Request> _req_v{req};
    m_receive_requests[req.addr] = _req_v;

    // Add to the miss request list
    m_miss_list.push_back(std::make_pair(m_clk + m_latency, req));

    // BH Changes Begin
    if (req.source_id >= 0) {
      m_allocated_mshrs[req.source_id]++;
    }
    // BH Changes End
    return true;
  }
}

void BHO3LLC::receive(Request& req) {
  auto it = std::find_if(
    m_mshrs.begin(), m_mshrs.end(),
    [&req, this](MSHREntry_t mshr_entry) { return (align(mshr_entry.first) == align(req.addr)); }
  );

  DEBUG_LOG(DBHO3LLC, m_logger, "[Clk={}] Request {} received.", m_clk, req.addr);

  if (it != m_mshrs.end()) {
    it->second->ready = true;
    m_mshrs.erase(it);
    // BH Changes Begin
    if (req.source_id >= 0) {
      m_allocated_mshrs[req.source_id]--;
    }
    // BH Changes End
  }
}

BHO3LLC::CacheSet_t& BHO3LLC::get_set(Addr_t addr) {
  int set_index = get_index(addr);
  if (m_cache_sets.find(set_index) == m_cache_sets.end()) {
    m_cache_sets.insert(make_pair(set_index, std::list<Line>()));
  }
  return m_cache_sets[set_index];
}

BHO3LLC::CacheSet_t::iterator BHO3LLC::allocate_line(CacheSet_t& set, Addr_t addr) {
  // Check if we need to evict any line
  if (need_eviction(set, addr)) {
    // Get a victim to evict
    auto victim = std::find_if(set.begin(), set.end(), [this](Line line) { return line.ready; });
    if (victim == set.end())
      return victim;  // doesn't exist a line that's already unlocked in each level
    evict_line(set, victim);
  }

  // Allocate new cache line and return an iterator to it
  set.push_back({addr, get_tag(addr)});
  return --set.end();
}

bool BHO3LLC::need_eviction(const CacheSet_t& set, Addr_t addr) {
  if (std::find_if(set.begin(), set.end(), 
            [addr, this](Line l) { return (get_tag(addr) == l.tag); }) 
      != set.end()) {
    // Due to MSHR, the program can't reach here. Just for checking
    assert(false);
    return false;
  } 
  else {
    if (set.size() < m_associativity) {
      return false;
    } else {
      return true;
    }
  }
}

void BHO3LLC::evict_line(CacheSet_t& set, CacheSet_t::iterator victim_it) {
  DEBUG_LOG(DBHO3LLC, m_logger,  "Evicting {}.", victim_it->addr);
  s_llc_eviction++;

  // Generate writeback request if victim line is dirty
  if (victim_it->dirty) {
    Request writeback_req(victim_it->addr, Request::Type::Write);
    m_miss_list.push_back(std::make_pair(m_clk + m_latency, writeback_req));

    DEBUG_LOG(DBHO3LLC, m_logger,  "Writeback Request will be issued at Clk={}.", m_clk + m_latency);
  }

  set.erase(victim_it);
}

BHO3LLC::CacheSet_t::iterator BHO3LLC::check_set_hit(CacheSet_t& set, Addr_t addr) {
  auto line_it = std::find_if(set.begin(), set.end(), [addr, this](Line l){return (l.tag == get_tag(addr));});
  if (line_it == set.end() || !line_it->ready) {
    return set.end();
  } else {
    return line_it;
  }
}

BHO3LLC::MSHR_t::iterator BHO3LLC::check_mshr_hit(Addr_t addr) {
  auto mshr_it =
    std::find_if(
      m_mshrs.begin(), m_mshrs.end(),
      [addr, this](MSHREntry_t mshr_entry) { return (align(mshr_entry.first) == align(addr)); }
    );
  return mshr_it;
}

void BHO3LLC::serialize(std::string serialization_filename) {
  std::ofstream serialization_file;
  serialization_file.open(serialization_filename, std::ios::out);

  serialization_file << "index,addr,tag,dirty" << std::endl;
  for (auto it1 = m_cache_sets.begin(); it1 != m_cache_sets.end(); it1++) {
    for (auto it2 = it1->second.begin(); it2 != it1->second.end(); it2++) {
      serialization_file << it1->first << "," << it2->addr << "," << it2->tag << "," << it2->dirty << std::endl;
    }
  }
  serialization_file.close();
}

void BHO3LLC::deserialize(std::string serialization_filename) {
  std::ifstream serialization_file;
  serialization_file.open(serialization_filename, std::ios::out);

  std::string file_line;
  std::getline(serialization_file, file_line); // Skip the first line, which is the header
  while (std::getline(serialization_file, file_line)) {
    std::string index_str = file_line.substr(0, file_line.find(","));
    file_line = file_line.substr(file_line.find(",") + 1);
    std::string addr_str = file_line.substr(0, file_line.find(","));
    file_line = file_line.substr(file_line.find(",") + 1);
    std::string tag_str = file_line.substr(0, file_line.find(","));
    file_line = file_line.substr(file_line.find(",") + 1);
    std::string dirty_str = file_line.substr(0, file_line.find(","));
    
    int index = std::stoi(index_str);
    Addr_t addr = std::stoll(addr_str);
    Addr_t tag = std::stoll(tag_str);
    bool dirty = std::stoi(dirty_str);
    if(m_cache_sets.find(index) == m_cache_sets.end()){
      m_cache_sets.insert({index, std::list<BHO3LLC::Line>()});
    }
    m_cache_sets[index].push_back({addr, tag, dirty, 1});
  }
  serialization_file.close();
}

void BHO3LLC::dump_llc() {
  /**
   * @brief dumps the LLC cache to the console
   * 
   */
  std::cout << "Dumping LLC" << std::endl;
  std::cout << "index,addr,tag,dirty,ready" << std::endl;
  for (auto it1 = m_cache_sets.begin(); it1 != m_cache_sets.end(); it1++) {
    for (auto it2 = it1->second.begin(); it2 != it1->second.end(); it2++) {
      std::cout << it1->first << "," << it2->addr << "," << it2->tag << "," << it2->dirty << "," << it2->ready << std::endl;
    }
  }
}

// BH Changes
void BHO3LLC::connect_memory_system(IMemorySystem* memory_system) {
  m_memory_system = memory_system;
  IDRAM* dram = static_cast<IBHMemorySystem*>(memory_system)->get_dram();

  m_rank_level = dram->m_levels("rank");
  m_bank_group_level = dram->m_levels("bankgroup");
  m_bank_level = dram->m_levels("bank");
  m_row_level = dram->m_levels("row");

  m_num_ranks = dram->get_level_size("rank");
  m_num_banks_per_rank = dram->get_level_size("bankgroup") == -1 ? 
                          dram->get_level_size("bank") : 
                          dram->get_level_size("bankgroup") * dram->get_level_size("bank");
  m_num_rows_per_bank = dram->get_level_size("row");
}

// Not safeguarding these on purpose. If you try to get/set
// anything non existent then your implementation is flawed.
int BHO3LLC::get_mshrs_per_core() {
  return m_mshr_per_core;
}

int BHO3LLC::get_blacklist_max_mshrs(int source_id) {
  return m_blacklist_max_mshrs[source_id];
}

void BHO3LLC::set_blacklist_max_mshrs(int source_id, int max_mshr) {
  m_blacklist_max_mshrs[source_id] = max_mshr;
}

void BHO3LLC::add_blacklist(int source_id) {
  m_blacklist_status[source_id] = true;
}

void BHO3LLC::erase_blacklist(int source_id) {
  m_blacklist_status[source_id] = false;
}

void BHO3LLC::configure_admission_principals(
  const std::vector<int>& principal_by_core
) {
  m_admission_principal_by_core.assign(m_num_cores, -1);
  int max_principal = -1;
  for (int core = 0; core < m_num_cores; core++) {
    int principal = (
      core < (int) principal_by_core.size()
      ? principal_by_core[(size_t) core]
      : core
    );
    if (principal < 0) {
      principal = core;
    }
    m_admission_principal_by_core[(size_t) core] = principal;
    max_principal = std::max(max_principal, principal);
  }
  m_admission_buckets.assign(
    (size_t) std::max(0, max_principal + 1), AdmissionBucket{}
  );
  m_new_miss_allocations_principal.assign(
    (size_t) std::max(0, max_principal + 1), 0
  );
}

void BHO3LLC::configure_admission_service_classes(
  const std::vector<int>& service_class_by_core
) {
  m_admission_service_class_by_core.assign(m_num_cores, -1);
  for (int core = 0; core < m_num_cores; core++) {
    int service_class = (
      core < (int) service_class_by_core.size()
      ? service_class_by_core[(size_t) core]
      : -1
    );
    if (service_class >= 0 && service_class < kAdmissionServiceClasses) {
      m_admission_service_class_by_core[(size_t) core] = service_class;
    }
  }
  m_service_class_admission_buckets = {};
  m_service_class_pending_sources = {};
  m_service_class_rr_next_source = {};
  m_service_class_probation_gates = {};
}

void BHO3LLC::configure_new_miss_observer(bool enabled) {
  m_new_miss_observer_enabled = enabled;
  std::fill(
    m_new_miss_allocations_principal.begin(),
    m_new_miss_allocations_principal.end(),
    0
  );
}

void BHO3LLC::configure_new_miss_event_callback(
  std::function<void(int)> callback
) {
  m_new_miss_event_callback = callback;
}

void BHO3LLC::set_admission_budget(
  int principal,
  uint64_t refill_tokens,
  uint64_t refill_period_cycles,
  uint64_t burst,
  uint64_t max_denial_cycles
) {
  if (principal < 0 || principal >= (int) m_admission_buckets.size()) {
    return;
  }
  auto& bucket = m_admission_buckets[(size_t) principal];
  const bool was_enabled = bucket.enabled;
  bucket.enabled = true;
  bucket.refill_tokens = std::max<uint64_t>(1, refill_tokens);
  bucket.refill_period_cycles = std::max<uint64_t>(1, refill_period_cycles);
  bucket.burst = std::max<uint64_t>(1, burst);
  bucket.max_denial_cycles = std::max<uint64_t>(1, max_denial_cycles);
  if (!was_enabled) {
    bucket.tokens = bucket.burst;
    bucket.last_refill = m_clk;
    bucket.last_admit = m_clk;
    bucket.denial_begin = std::numeric_limits<Clk_t>::max();
  } else {
    bucket.tokens = std::min(bucket.tokens, bucket.burst);
  }
}

void BHO3LLC::clear_admission_budget(int principal) {
  if (principal < 0 || principal >= (int) m_admission_buckets.size()) {
    return;
  }
  auto& bucket = m_admission_buckets[(size_t) principal];
  bucket.enabled = false;
  bucket.denial_begin = std::numeric_limits<Clk_t>::max();
}

void BHO3LLC::set_admission_tokens(int principal, uint64_t tokens) {
  if (principal < 0 || principal >= (int) m_admission_buckets.size()) {
    return;
  }
  auto& bucket = m_admission_buckets[(size_t) principal];
  if (!bucket.enabled) {
    return;
  }
  bucket.tokens = std::min(tokens, bucket.burst);
  // Re-anchor both refill and forced-progress clocks.  At the pre-request
  // initialization event this creates a cold-start guard with an explicit,
  // finite deadline instead of silently dropping the first request.
  bucket.last_refill = m_clk;
  bucket.last_admit = m_clk;
  bucket.denial_begin = std::numeric_limits<Clk_t>::max();
}

void BHO3LLC::refill_admission_bucket(AdmissionBucket& bucket) {
  if (!bucket.enabled || m_clk <= bucket.last_refill) {
    return;
  }
  uint64_t elapsed = (uint64_t) (m_clk - bucket.last_refill);
  uint64_t periods = elapsed / bucket.refill_period_cycles;
  if (periods == 0) {
    return;
  }
  uint64_t capacity = bucket.burst - std::min(bucket.tokens, bucket.burst);
  uint64_t added = periods > capacity / bucket.refill_tokens
    ? capacity
    : periods * bucket.refill_tokens;
  bucket.tokens = std::min(bucket.burst, bucket.tokens + added);
  bucket.last_refill += (Clk_t) (periods * bucket.refill_period_cycles);
  bucket.refills += periods;
  s_llc_admission_refills += periods;
}

bool BHO3LLC::admit_new_miss(const Request& req) {
  const int source_id = req.source_id;
  if (source_id < 0 || source_id >= m_num_cores) {
    return true;
  }
  int principal = m_admission_principal_by_core[(size_t) source_id];
  AdmissionBucket* principal_bucket = (
    principal >= 0 && principal < (int) m_admission_buckets.size()
    ? &m_admission_buckets[(size_t) principal]
    : nullptr
  );
  int service_class = m_admission_service_class_by_core[(size_t) source_id];
  if (service_class >= 0 && service_class < kAdmissionServiceClasses) {
    auto& gate = m_service_class_probation_gates[(size_t) service_class];
    if (gate.enabled
        && gate.mode != ServiceClassProbationMode::Bypass
        && gate.mode != ServiceClassProbationMode::Limited) {
      if (gate.mode == ServiceClassProbationMode::Armed) {
        gate.mode = ServiceClassProbationMode::Collecting;
        gate.first_seen = m_clk;
        gate.distinct_count = 0;
      }

      uint64_t held_for = (uint64_t) (m_clk - gate.first_seen);
      if (held_for >= gate.deadline_cycles) {
        gate.max_observed_hold_cycles = std::max(
          gate.max_observed_hold_cycles, gate.deadline_cycles
        );
        gate.mode = ServiceClassProbationMode::Bypass;
        gate.deadline_bypasses++;
      } else {
        const Addr_t line = align(req.addr);
        bool duplicate = false;
        for (int entry = 0; entry < (int) gate.distinct_count; entry++) {
          if (gate.line_addr[(size_t) entry] == line
              && gate.source_id[(size_t) entry] == source_id) {
            duplicate = true;
            break;
          }
        }
        if (duplicate) {
          gate.duplicate_retries++;
        } else if (gate.distinct_count < gate.distinct_threshold) {
          const size_t entry = (size_t) gate.distinct_count;
          gate.line_addr[entry] = line;
          gate.source_id[entry] = source_id;
          gate.distinct_count++;
        }

        if (gate.distinct_count >= gate.distinct_threshold) {
          gate.mode = ServiceClassProbationMode::Limited;
          gate.first_limited = m_clk;
          gate.service_epoch_begin = m_clk;
          gate.served_principals = 0;
          gate.limited_transitions++;
          set_service_class_admission_budget(
            service_class,
            gate.refill_tokens,
            gate.refill_period_cycles,
            gate.burst,
            gate.max_denial_cycles
          );
          set_service_class_admission_tokens(
            service_class, gate.initial_tokens_on_limit
          );
          gate.oldest_release_pending = gate.initial_tokens_on_limit > 0;
        } else {
          gate.held_requests++;
          gate.max_observed_hold_cycles = std::max(
            gate.max_observed_hold_cycles, held_for
          );
          s_llc_admission_denied++;
          s_llc_admission_denied_core[(size_t) source_id]++;
          return false;
        }
      }
    }
    if (gate.enabled
        && gate.mode == ServiceClassProbationMode::Limited
        && gate.oldest_release_pending
        && (source_id != gate.source_id[0]
            || align(req.addr) != gate.line_addr[0])) {
      gate.held_requests++;
      gate.oldest_release_denials++;
      s_llc_admission_denied++;
      s_llc_admission_denied_core[(size_t) source_id]++;
      return false;
    }
  }
  AdmissionBucket* class_bucket = (
    service_class >= 0 && service_class < kAdmissionServiceClasses
    ? &m_service_class_admission_buckets[(size_t) service_class]
    : nullptr
  );
  ServiceClassProbationGate* limited_gate = (
    service_class >= 0 && service_class < kAdmissionServiceClasses
        && m_service_class_probation_gates[(size_t) service_class].enabled
        && m_service_class_probation_gates[(size_t) service_class].mode
          == ServiceClassProbationMode::Limited
    ? &m_service_class_probation_gates[(size_t) service_class]
    : nullptr
  );
  if (limited_gate != nullptr
      && limited_gate->principal_service_epoch_cycles > 0
      && m_clk >= limited_gate->service_epoch_begin) {
    uint64_t elapsed = (uint64_t) (
      m_clk - limited_gate->service_epoch_begin
    );
    uint64_t epochs = elapsed /
      limited_gate->principal_service_epoch_cycles;
    if (epochs > 0) {
      limited_gate->service_epoch_begin += (Clk_t) (
        epochs * limited_gate->principal_service_epoch_cycles
      );
      limited_gate->served_principals = 0;
      limited_gate->service_epoch_resets += epochs;
    }
  }
  if ((principal_bucket == nullptr || !principal_bucket->enabled)
      && (class_bucket == nullptr || !class_bucket->enabled)) {
    return true;
  }

  auto bucket_ready = [this](AdmissionBucket* bucket, bool& forced) {
    forced = false;
    if (bucket == nullptr || !bucket->enabled) {
      return true;
    }
    refill_admission_bucket(*bucket);
    if (bucket->tokens == 0) {
      uint64_t since_admit = (uint64_t) (m_clk - bucket->last_admit);
      forced = since_admit >= bucket->max_denial_cycles;
    }
    return bucket->tokens > 0 || forced;
  };

  bool principal_forced = false;
  bool class_forced = false;
  bool principal_ready = bucket_ready(principal_bucket, principal_forced);
  bool class_ready = bucket_ready(class_bucket, class_forced);

  // A class token is distributed across fixed hardware request sources by a
  // bounded sticky-pending bitmap and round-robin pointer. Principal IDs are
  // deliberately absent from the tie break, so repartitioning the same source
  // traffic cannot change which request receives the next aggregate grant.
  const bool class_resource_ready = class_ready;
  if (class_bucket != nullptr && class_bucket->enabled
      && source_id >= 0 && source_id < kAdmissionSourceLimit) {
    uint32_t source_bit = uint32_t{1} << (uint32_t) source_id;
    m_service_class_pending_sources[(size_t) service_class] |= source_bit;
    if (class_ready) {
      uint32_t pending =
        m_service_class_pending_sources[(size_t) service_class];
      int start =
        m_service_class_rr_next_source[(size_t) service_class];
      int selected_source = -1;
      for (int offset = 0; offset < kAdmissionSourceLimit; offset++) {
        int candidate_source = (start + offset) % kAdmissionSourceLimit;
        uint32_t candidate_source_bit =
          uint32_t{1} << (uint32_t) candidate_source;
        int candidate_principal = (
          candidate_source >= 0
              && candidate_source < (int) m_admission_principal_by_core.size()
          ? m_admission_principal_by_core[(size_t) candidate_source]
          : -1
        );
        uint32_t candidate_principal_bit = (
          candidate_principal >= 0
              && candidate_principal < kAdmissionPrincipalLimit
          ? uint32_t{1} << (uint32_t) candidate_principal
          : 0
        );
        bool already_served = limited_gate != nullptr
          && limited_gate->principal_service_epoch_cycles > 0
          && candidate_principal_bit != 0
          && (limited_gate->served_principals
              & candidate_principal_bit) != 0;
        if ((pending & candidate_source_bit) != 0 && !already_served) {
          selected_source = candidate_source;
          break;
        }
      }
      class_ready = selected_source == source_id;
      if (!class_ready && class_resource_ready && limited_gate != nullptr
          && limited_gate->principal_service_epoch_cycles > 0
          && principal >= 0 && principal < kAdmissionPrincipalLimit
          && (limited_gate->served_principals
              & (uint32_t{1} << (uint32_t) principal)) != 0) {
        limited_gate->service_epoch_denials++;
      }
    }
  }

  auto record_denial = [this](AdmissionBucket* bucket) {
    if (bucket == nullptr || !bucket->enabled) {
      return;
    }
    bucket->denied++;
    if (bucket->denial_begin == std::numeric_limits<Clk_t>::max()) {
      bucket->denial_begin = m_clk;
    }
  };
  if (!principal_ready || !class_ready) {
    if (!principal_ready) {
      record_denial(principal_bucket);
    }
    if (!class_ready) {
      record_denial(class_bucket);
    }
    s_llc_admission_denied++;
    s_llc_admission_denied_core[(size_t) source_id]++;
    return false;
  }

  auto record_admission = [this](AdmissionBucket* bucket, bool forced) {
    if (bucket == nullptr || !bucket->enabled) {
      return;
    }
    if (!forced) {
      bucket->tokens--;
    } else {
      bucket->forced_liveness++;
    }
    if (bucket->denial_begin != std::numeric_limits<Clk_t>::max()) {
      uint64_t denied_for = (uint64_t) (m_clk - bucket->denial_begin);
      bucket->max_observed_denial_cycles = std::max(
        bucket->max_observed_denial_cycles, denied_for
      );
      s_llc_admission_max_denial_cycles = std::max(
        s_llc_admission_max_denial_cycles, denied_for
      );
      bucket->denial_begin = std::numeric_limits<Clk_t>::max();
    }
    bucket->last_admit = m_clk;
    bucket->admitted++;
  };
  record_admission(principal_bucket, principal_forced);
  record_admission(class_bucket, class_forced);
  if (principal_forced || class_forced) {
    s_llc_admission_forced_liveness++;
  }
  if (class_bucket != nullptr && class_bucket->enabled
      && source_id >= 0 && source_id < kAdmissionSourceLimit) {
    m_service_class_pending_sources[(size_t) service_class] &=
      ~(uint32_t{1} << (uint32_t) source_id);
    m_service_class_rr_next_source[(size_t) service_class] =
      (source_id + 1) % kAdmissionSourceLimit;
    if (limited_gate != nullptr
        && limited_gate->principal_service_epoch_cycles > 0
        && principal >= 0 && principal < kAdmissionPrincipalLimit) {
      limited_gate->served_principals |=
        uint32_t{1} << (uint32_t) principal;
    }
    if (limited_gate != nullptr
        && limited_gate->oldest_release_pending
        && source_id == limited_gate->source_id[0]
        && align(req.addr) == limited_gate->line_addr[0]) {
      limited_gate->oldest_release_pending = false;
      limited_gate->oldest_releases++;
    }
  }
  s_llc_admission_admitted++;
  s_llc_admission_admitted_core[(size_t) source_id]++;
  return true;
}

uint64_t BHO3LLC::get_admission_tokens(int principal) {
  if (principal < 0 || principal >= (int) m_admission_buckets.size()) {
    return 0;
  }
  auto& bucket = m_admission_buckets[(size_t) principal];
  refill_admission_bucket(bucket);
  return bucket.tokens;
}

uint64_t BHO3LLC::get_admission_admitted(int principal) const {
  return principal >= 0 && principal < (int) m_admission_buckets.size()
    ? m_admission_buckets[(size_t) principal].admitted : 0;
}

uint64_t BHO3LLC::get_admission_denied(int principal) const {
  return principal >= 0 && principal < (int) m_admission_buckets.size()
    ? m_admission_buckets[(size_t) principal].denied : 0;
}

uint64_t BHO3LLC::get_admission_forced_liveness(int principal) const {
  return principal >= 0 && principal < (int) m_admission_buckets.size()
    ? m_admission_buckets[(size_t) principal].forced_liveness : 0;
}

uint64_t BHO3LLC::get_admission_refills(int principal) const {
  return principal >= 0 && principal < (int) m_admission_buckets.size()
    ? m_admission_buckets[(size_t) principal].refills : 0;
}

uint64_t BHO3LLC::get_admission_max_denial_cycles(int principal) const {
  return principal >= 0 && principal < (int) m_admission_buckets.size()
    ? m_admission_buckets[(size_t) principal].max_observed_denial_cycles : 0;
}

void BHO3LLC::set_service_class_admission_budget(
  int service_class,
  uint64_t refill_tokens,
  uint64_t refill_period_cycles,
  uint64_t burst,
  uint64_t max_denial_cycles
) {
  if (service_class < 0 || service_class >= kAdmissionServiceClasses) {
    return;
  }
  auto& bucket =
    m_service_class_admission_buckets[(size_t) service_class];
  const bool was_enabled = bucket.enabled;
  bucket.enabled = true;
  bucket.refill_tokens = std::max<uint64_t>(1, refill_tokens);
  bucket.refill_period_cycles = std::max<uint64_t>(1, refill_period_cycles);
  bucket.burst = std::max<uint64_t>(1, burst);
  bucket.max_denial_cycles = std::max<uint64_t>(1, max_denial_cycles);
  if (!was_enabled) {
    bucket.tokens = bucket.burst;
    bucket.last_refill = m_clk;
    bucket.last_admit = m_clk;
    bucket.denial_begin = std::numeric_limits<Clk_t>::max();
    m_service_class_pending_sources[(size_t) service_class] = 0;
    m_service_class_rr_next_source[(size_t) service_class] = 0;
  } else {
    bucket.tokens = std::min(bucket.tokens, bucket.burst);
  }
}

void BHO3LLC::clear_service_class_admission_budget(int service_class) {
  if (service_class < 0 || service_class >= kAdmissionServiceClasses) {
    return;
  }
  auto& bucket =
    m_service_class_admission_buckets[(size_t) service_class];
  bucket.enabled = false;
  bucket.denial_begin = std::numeric_limits<Clk_t>::max();
  m_service_class_pending_sources[(size_t) service_class] = 0;
}

void BHO3LLC::set_service_class_admission_tokens(
  int service_class, uint64_t tokens
) {
  if (service_class < 0 || service_class >= kAdmissionServiceClasses) {
    return;
  }
  auto& bucket =
    m_service_class_admission_buckets[(size_t) service_class];
  if (!bucket.enabled) {
    return;
  }
  bucket.tokens = std::min(tokens, bucket.burst);
  bucket.last_refill = m_clk;
  bucket.last_admit = m_clk;
  bucket.denial_begin = std::numeric_limits<Clk_t>::max();
}

uint64_t BHO3LLC::get_service_class_admission_tokens(int service_class) {
  if (service_class < 0 || service_class >= kAdmissionServiceClasses) {
    return 0;
  }
  auto& bucket =
    m_service_class_admission_buckets[(size_t) service_class];
  refill_admission_bucket(bucket);
  return bucket.tokens;
}

uint64_t BHO3LLC::get_service_class_admission_admitted(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_admission_buckets[(size_t) service_class].admitted : 0;
}

uint64_t BHO3LLC::get_service_class_admission_denied(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_admission_buckets[(size_t) service_class].denied : 0;
}

uint64_t BHO3LLC::get_service_class_admission_forced_liveness(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_admission_buckets[(size_t) service_class].forced_liveness
    : 0;
}

uint64_t BHO3LLC::get_service_class_admission_refills(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_admission_buckets[(size_t) service_class].refills : 0;
}

uint64_t BHO3LLC::get_service_class_admission_max_denial_cycles(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_admission_buckets[(size_t) service_class]
        .max_observed_denial_cycles
    : 0;
}

void BHO3LLC::arm_service_class_probation_gate(
  int service_class,
  uint64_t distinct_threshold,
  uint64_t deadline_cycles,
  uint64_t principal_service_epoch_cycles,
  uint64_t initial_tokens_on_limit,
  uint64_t refill_tokens,
  uint64_t refill_period_cycles,
  uint64_t burst,
  uint64_t max_denial_cycles
) {
  if (service_class < 0 || service_class >= kAdmissionServiceClasses) {
    return;
  }
  auto& gate = m_service_class_probation_gates[(size_t) service_class];
  gate = ServiceClassProbationGate{};
  gate.enabled = true;
  gate.mode = ServiceClassProbationMode::Armed;
  gate.distinct_threshold = (uint8_t) std::max<uint64_t>(
    1,
    std::min<uint64_t>(kServiceClassProbationEntries, distinct_threshold)
  );
  gate.deadline_cycles = std::max<uint64_t>(1, deadline_cycles);
  gate.principal_service_epoch_cycles = principal_service_epoch_cycles;
  gate.initial_tokens_on_limit = std::min<uint64_t>(
    initial_tokens_on_limit, std::max<uint64_t>(1, burst)
  );
  gate.refill_tokens = std::max<uint64_t>(1, refill_tokens);
  gate.refill_period_cycles = std::max<uint64_t>(1, refill_period_cycles);
  gate.burst = std::max<uint64_t>(1, burst);
  gate.max_denial_cycles = std::max<uint64_t>(1, max_denial_cycles);
}

void BHO3LLC::clear_service_class_probation_gate(int service_class) {
  if (service_class < 0 || service_class >= kAdmissionServiceClasses) {
    return;
  }
  auto& gate = m_service_class_probation_gates[(size_t) service_class];
  gate.enabled = false;
  gate.mode = ServiceClassProbationMode::Disabled;
}

uint64_t BHO3LLC::get_service_class_probation_mode(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? (uint64_t) m_service_class_probation_gates[(size_t) service_class].mode
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_distinct_count(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class].distinct_count
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_distinct_threshold(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class]
        .distinct_threshold
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_deadline_cycles(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class].deadline_cycles
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_refill_period_cycles(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class]
        .refill_period_cycles
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_service_epoch_cycles(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class]
        .principal_service_epoch_cycles
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_initial_tokens(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class]
        .initial_tokens_on_limit
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_held(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class].held_requests
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_duplicate_retries(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class].duplicate_retries
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_deadline_bypasses(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class].deadline_bypasses
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_limited_transitions(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class].limited_transitions
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_service_epoch_resets(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class]
        .service_epoch_resets
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_service_epoch_denials(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class]
        .service_epoch_denials
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_oldest_release_denials(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class]
        .oldest_release_denials
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_oldest_releases(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class].oldest_releases
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_max_hold_cycles(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? m_service_class_probation_gates[(size_t) service_class]
        .max_observed_hold_cycles
    : 0;
}

uint64_t BHO3LLC::get_service_class_probation_first_limited_cycle(
  int service_class
) const {
  return service_class >= 0 && service_class < kAdmissionServiceClasses
    ? (uint64_t) m_service_class_probation_gates[(size_t) service_class]
        .first_limited
    : 0;
}

void BHO3LLC::record_new_miss_allocation(int source_id) {
  if (source_id < 0 || source_id >= m_num_cores) {
    return;
  }
  if (m_new_miss_observer_enabled) {
    int principal = m_admission_principal_by_core[(size_t) source_id];
    if (principal < 0
        || principal >= (int) m_new_miss_allocations_principal.size()) {
      return;
    }
    m_new_miss_allocations_principal[(size_t) principal]++;
  }
  if (m_new_miss_event_callback) {
    m_new_miss_event_callback(source_id);
  }
}

uint64_t BHO3LLC::get_new_miss_allocations(int principal) const {
  return m_new_miss_observer_enabled
      && principal >= 0
      && principal < (int) m_new_miss_allocations_principal.size()
    ? m_new_miss_allocations_principal[(size_t) principal] : 0;
}

void BHO3LLC::set_principal_qos_class(int principal, int qos_class) {
  const int clamped = std::max(0, std::min(1, qos_class));
  for (int core = 0; core < m_num_cores; core++) {
    if (m_admission_principal_by_core[(size_t) core] != principal) {
      continue;
    }
    if (m_qos_class_by_core[(size_t) core] != clamped) {
      m_qos_class_by_core[(size_t) core] = clamped;
      s_llc_qos_class_core[(size_t) core] = clamped;
      s_llc_qos_class_changes_core[(size_t) core]++;
    }
  }
}

int BHO3LLC::get_qos_class(int source_id) const {
  if (source_id < 0 || source_id >= m_num_cores) {
    return 0;
  }
  return m_qos_class_by_core[(size_t) source_id];
}

// TODO: I'll do some stuff to limit number of clflushes issable in a window (@Oguzhan)
// Currently everything returns true
bool BHO3LLC::clflush(Addr_t addr) {
  CacheSet_t& set = get_set(addr);
  auto line_it = check_set_hit(set, addr);
  if (line_it != set.end()) {
    evict_line(set, line_it);
  }
  return true;
}

}        // namespace Ramulator
