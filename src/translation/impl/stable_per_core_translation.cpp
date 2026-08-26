#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "base/base.h"
#include "frontend/frontend.h"
#include "translation/translation.h"

#ifndef STABLE_PER_CORE_TRANSLATION_SOURCE_SHA256
#error "StablePerCoreTranslation requires an embedded source SHA-256"
#endif

namespace Ramulator {

class StablePerCoreTranslation : public ITranslation, public Implementation {
  RAMULATOR_REGISTER_IMPLEMENTATION(
    ITranslation,
    StablePerCoreTranslation,
    "StablePerCoreTranslation",
    "Order-independent random page allocation in disjoint per-core partitions."
  );

  IFrontEnd* m_frontend = nullptr;
  Addr_t m_max_paddr = 0;
  Addr_t m_pagesize = 0;
  int m_offsetbits = 0;
  size_t m_num_pages = 0;
  int m_num_partitions = 1;
  int m_seed = 123;
  size_t m_audit_prefix_pages = 64;

  using CoreTranslation = std::unordered_map<Addr_t, Addr_t>;
  std::vector<CoreTranslation> m_translation;
  std::vector<std::mt19937_64> m_allocator_rng;
  std::vector<size_t> m_partition_begin;
  std::vector<size_t> m_partition_end;
  std::vector<size_t> m_partition_free;
  std::vector<bool> m_free_physical_pages;
  std::unordered_set<Addr_t> m_reserved_pages;
  std::vector<std::unordered_set<Addr_t>> m_registered_vpns;
  bool m_mapping_finalized = false;

  // Runtime evidence for the matched-deployment gate.  The rolling digest is
  // deliberately limited to the first N VPN-sorted mappings of each core.
  // It therefore certifies the mapping function and is independent of dynamic
  // cache hits, stalls, and first-touch order.
  std::vector<uint64_t> s_mapping_count_core;
  std::vector<uint64_t> s_mapping_prefix_count_core;
  std::vector<uint64_t> s_mapping_prefix_digest_core;

  static uint64_t mix_seed(uint64_t value) {
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
  }

  static uint64_t extend_digest(uint64_t digest, uint64_t value) {
    digest ^= mix_seed(value);
    digest *= 1099511628211ULL;
    return digest;
  }

  Addr_t choose_page(int partition) {
    const size_t begin = m_partition_begin[(size_t) partition];
    const size_t end = m_partition_end[(size_t) partition];
    const size_t span = end - begin;
    if (span == 0) {
      throw std::runtime_error("StablePerCoreTranslation has an empty partition");
    }
    const size_t start =
      begin + (size_t) (m_allocator_rng[(size_t) partition]() % span);
    for (size_t offset = 0; offset < span; offset++) {
      const size_t candidate = begin + ((start - begin + offset) % span);
      if (m_reserved_pages.find((Addr_t) candidate) != m_reserved_pages.end()) {
        continue;
      }
      if (m_free_physical_pages[candidate]) {
        return (Addr_t) candidate;
      }
    }
    throw std::runtime_error(
      "StablePerCoreTranslation has no allocatable page in partition"
    );
  }

  void finalize_registered_mappings() {
    if (m_mapping_finalized) {
      return;
    }

    for (size_t core = 0; core < m_translation.size(); core++) {
      std::vector<Addr_t> vpns(
        m_registered_vpns[core].begin(),
        m_registered_vpns[core].end()
      );
      std::sort(vpns.begin(), vpns.end());
      if (vpns.size() > m_partition_free[core]) {
        throw std::runtime_error(
          "StablePerCoreTranslation registered working set exceeds its "
          "per-core physical-page partition"
        );
      }

      auto& core_translation = m_translation[core];
      for (const Addr_t vpn : vpns) {
        const Addr_t ppn = choose_page((int) core);
        core_translation.emplace(vpn, ppn);
        m_free_physical_pages[(size_t) ppn] = false;
        m_partition_free[core]--;

        s_mapping_count_core[core]++;
        if (s_mapping_prefix_count_core[core] < m_audit_prefix_pages) {
          uint64_t digest = s_mapping_prefix_digest_core[core];
          digest = extend_digest(digest, (uint64_t) vpn);
          digest = extend_digest(digest, (uint64_t) ppn);
          s_mapping_prefix_digest_core[core] = digest;
          s_mapping_prefix_count_core[core]++;
        }
      }
    }
    m_mapping_finalized = true;
  }

public:
  void init() override {
    m_seed = param<int>("seed")
      .desc("Base seed for deterministic per-core page allocation.")
      .default_val(123);
    m_max_paddr = param<Addr_t>("max_addr")
      .desc("Max physical address of the memory system.")
      .required();
    m_pagesize = param<Addr_t>("pagesize_KB")
      .desc("Page size in KB.")
      .default_val(4) << 10;
    m_offsetbits = calc_log2(m_pagesize);
    m_num_pages = (size_t) (m_max_paddr / m_pagesize);

    m_frontend = cast_parent<IFrontEnd>();
    const int num_cores = m_frontend->get_num_cores();
    m_num_partitions = param<int>("num_partitions")
      .desc("Fixed host partition count shared by matched deployments.")
      .default_val(num_cores);
    m_audit_prefix_pages = param<size_t>("audit_prefix_pages")
      .desc("Number of VPN-sorted per-core mappings hashed for audit.")
      .default_val(64);
    if (m_num_partitions < num_cores || m_num_partitions <= 0
        || (size_t) m_num_partitions > m_num_pages) {
      throw ConfigurationError(
        "StablePerCoreTranslation requires num_cores <= num_partitions <= num_pages"
      );
    }

    m_translation.resize((size_t) num_cores);
    m_registered_vpns.resize((size_t) num_cores);
    m_allocator_rng.resize((size_t) m_num_partitions);
    m_partition_begin.resize((size_t) m_num_partitions);
    m_partition_end.resize((size_t) m_num_partitions);
    m_partition_free.resize((size_t) m_num_partitions);
    m_free_physical_pages.assign(m_num_pages, true);
    for (int partition = 0; partition < m_num_partitions; partition++) {
      const size_t begin =
        (m_num_pages * (size_t) partition) / (size_t) m_num_partitions;
      const size_t end =
        (m_num_pages * (size_t) (partition + 1)) / (size_t) m_num_partitions;
      m_partition_begin[(size_t) partition] = begin;
      m_partition_end[(size_t) partition] = end;
      m_partition_free[(size_t) partition] = end - begin;
      m_allocator_rng[(size_t) partition].seed(
        mix_seed((uint64_t) (uint32_t) m_seed ^ (uint64_t) partition)
      );
    }

    s_mapping_count_core.assign((size_t) num_cores, 0);
    s_mapping_prefix_count_core.assign((size_t) num_cores, 0);
    s_mapping_prefix_digest_core.assign(
      (size_t) num_cores,
      1469598103934665603ULL
    );
    register_stat(m_seed).name("translation_seed");
    register_stat(m_num_partitions).name("translation_num_partitions");
    register_stat(m_audit_prefix_pages).name("translation_audit_prefix_pages");
    register_stat(s_mapping_count_core).name("translation_mapping_count_core");
    register_stat(s_mapping_prefix_count_core)
      .name("translation_mapping_prefix_count_core");
    register_stat(s_mapping_prefix_digest_core)
      .name("translation_mapping_prefix_digest_core");
    std::cout << "translation_impl: StablePerCoreTranslation" << std::endl;
    std::cout << "translation_source_sha256: "
              << STABLE_PER_CORE_TRANSLATION_SOURCE_SHA256 << std::endl;
    m_logger = Logging::create_logger("StablePerCoreTranslation");
  }

  void register_address(int source_id, Addr_t addr) override {
    if (m_mapping_finalized) {
      throw std::runtime_error(
        "StablePerCoreTranslation cannot register an address after translation starts"
      );
    }
    if (source_id < 0 || source_id >= (int) m_registered_vpns.size()) {
      throw std::runtime_error(
        "StablePerCoreTranslation received an invalid preload source id"
      );
    }
    m_registered_vpns[(size_t) source_id].insert(addr >> m_offsetbits);
  }

  bool translate(Request& req) override {
    if (req.source_id < 0 || req.source_id >= (int) m_translation.size()) {
      return false;
    }
    finalize_registered_mappings();
    const Addr_t vpn = req.addr >> m_offsetbits;
    auto& core_translation = m_translation[(size_t) req.source_id];
    auto target = core_translation.find(vpn);
    if (target == core_translation.end()) {
      throw std::runtime_error(
        "StablePerCoreTranslation encountered an unregistered runtime VPN"
      );
    }

    const Addr_t offset_mask = ((Addr_t) 1 << m_offsetbits) - 1;
    req.addr = (target->second << m_offsetbits) | (req.addr & offset_mask);
    return true;
  }

  bool reserve(const std::string& type, Addr_t addr) override {
    (void) type;
    if (m_mapping_finalized) {
      throw std::runtime_error(
        "StablePerCoreTranslation cannot reserve a page after translation starts"
      );
    }
    const Addr_t ppn = addr >> m_offsetbits;
    if (ppn < 0 || (size_t) ppn >= m_num_pages) {
      return false;
    }
    const auto [_, inserted] = m_reserved_pages.insert(ppn);
    if (inserted && m_free_physical_pages[(size_t) ppn]) {
      m_free_physical_pages[(size_t) ppn] = false;
      const size_t partition = std::min(
        (size_t) m_num_partitions - 1,
        ((size_t) ppn * (size_t) m_num_partitions) / m_num_pages
      );
      if (m_partition_free[partition] > 0) {
        m_partition_free[partition]--;
      }
    }
    return true;
  }

  Addr_t get_max_addr() override {
    return m_max_paddr;
  }
};

}  // namespace Ramulator
