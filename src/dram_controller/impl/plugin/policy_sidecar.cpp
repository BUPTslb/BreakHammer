#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#include "base/base.h"
#include "dram_controller/bhcontroller.h"
#include "dram_controller/plugin.h"
#include "dram_controller/impl/pluginutil/device_config.h"
#include "frontend/impl/processor/bhO3/bhO3.h"
#include "frontend/impl/processor/bhO3/bhllc.h"

namespace Ramulator {

class PolicySidecar : public IControllerPlugin, public Implementation {
    RAMULATOR_REGISTER_IMPLEMENTATION(
        IControllerPlugin,
        PolicySidecar,
        "PolicySidecar",
        "HammerEVO bounded policy sidecar."
    )

private:
    struct Rule {
        int feature_id = 0;
        int operator_id = 0;
        int threshold = 0;
        int action_type = 0;
        int action_value = 0;
    };

    static constexpr int kMaxRules = 16;
    static constexpr int kIRV1MaxRules = 1;
    static constexpr int kFeatureActivationFast = 1;
    static constexpr int kFeatureActivationSlow = 2;
    static constexpr int kOpGte = 1;
    static constexpr int kOpGt = 2;
    static constexpr int kOpLte = 3;
    static constexpr int kOpLt = 4;
    static constexpr int kActionSetQuota = 1;
    static constexpr int kActionDecreaseQuota = 2;

    DeviceConfig m_cfg;
    BHO3* m_frontend = nullptr;
    BHO3LLC* m_llc = nullptr;

    Clk_t m_clk = 0;
    int m_num_cores = 0;
    int m_window_period_ns = 64000000;
    int m_window_period_clk = 1;
    int m_quota_min = 1;
    int m_quota_max = 1;
    bool m_enabled = true;
    std::string m_schema_version = "";
    std::string m_policy_ir_sha256 = "";

    std::vector<Rule> m_rules;
    std::vector<int> m_window_refs;
    std::vector<int> m_prev_window_refs;
    std::vector<bool> m_throttled;
    std::vector<Clk_t> m_throttle_begin_clk;

    uint64_t s_policy_sidecar_actions_applied = 0;
    uint64_t s_policy_sidecar_windows = 0;
    uint64_t s_policy_sidecar_opening_requests = 0;
    uint64_t s_policy_sidecar_invalid_source_id = 0;
    uint64_t s_policy_sidecar_throttle_entered = 0;
    uint64_t s_policy_sidecar_blacklist_success = 0;
    int s_policy_sidecar_loaded_window_period_ns = 0;
    int s_policy_sidecar_loaded_window_period_clk = 0;
    int s_policy_sidecar_last_mshr_before = -1;
    int s_policy_sidecar_last_mshr_after = -1;
    int s_policy_sidecar_min_mshr_after = -1;
    int s_policy_sidecar_max_mshr_before = -1;
    int s_policy_sidecar_policy_loaded = 0;
    int s_policy_sidecar_rule_count = 0;
    int s_policy_sidecar_loaded_quota_min = 0;
    int s_policy_sidecar_loaded_quota_max = 0;
    int s_policy_sidecar_setup_mshr_limit_before = -1;
    int s_policy_sidecar_setup_mshr_limit_after = -1;
    int s_policy_sidecar_finalize_mshr_limit = -1;
    uint64_t s_policy_sidecar_action_set_quota_count = 0;
    uint64_t s_policy_sidecar_action_decrease_quota_count = 0;
    int s_policy_sidecar_action_value_last = -1;
    int s_policy_sidecar_quota_before_last = -1;
    int s_policy_sidecar_quota_after_last = -1;
    uint64_t s_policy_sidecar_unsupported_feature_count = 0;
    uint64_t s_policy_sidecar_policy_runtime_error_count = 0;
    std::vector<uint64_t> s_policy_sidecar_rule_evaluation_count;
    std::vector<uint64_t> s_policy_sidecar_rule_hit_count;
    std::vector<int> s_policy_sidecar_loaded_rule_feature_id;
    std::vector<int> s_policy_sidecar_loaded_rule_operator_id;
    std::vector<int> s_policy_sidecar_loaded_rule_threshold;
    std::vector<int> s_policy_sidecar_loaded_rule_action_type;
    std::vector<int> s_policy_sidecar_loaded_rule_action_value;
    std::vector<uint64_t> s_policy_sidecar_actions_core;
    std::vector<uint64_t> s_policy_sidecar_duration_core;
    std::vector<uint64_t> s_policy_sidecar_max_window_refs_core;
    std::vector<int> s_policy_sidecar_setup_mshr_limit_before_core;
    std::vector<int> s_policy_sidecar_setup_mshr_limit_after_core;
    std::vector<int> s_policy_sidecar_finalize_mshr_limit_core;
    std::vector<uint64_t> s_policy_sidecar_feature_samples;
    std::vector<int64_t> s_policy_sidecar_feature_min;
    std::vector<int64_t> s_policy_sidecar_feature_max;
    std::vector<int64_t> s_policy_sidecar_feature_sum;

public:
    void init() override {
        m_enabled = param<bool>("enabled").default_val(true);
        m_window_period_ns = param<int>("window_period_ns").default_val(64000000);
        int quota_min = param<int>("quota_min").default_val(1);
        int quota_max = param<int>("quota_max").default_val(1);
        m_schema_version = param<std::string>("policy_ir_schema_version").default_val("");
        m_policy_ir_sha256 = param<std::string>("policy_ir_sha256").default_val("");
        int rule_count = param<int>("policy_ir_rule_count").default_val(0);
        std::vector<Rule> loaded_rules;
        bool valid = true;
        if (m_schema_version != "policy_sidecar_ir_v1") {
            valid = false;
        }
        if (m_window_period_ns <= 0) {
            valid = false;
        }
        if (quota_min < 1 || quota_max < 1 || quota_min > quota_max || quota_max > 128) {
            valid = false;
        }
        if (rule_count < 0 || rule_count > kMaxRules || rule_count > kIRV1MaxRules) {
            valid = false;
        }
        if (!valid) {
            s_policy_sidecar_policy_runtime_error_count++;
            rule_count = 0;
        }
        for (int i = 0; i < rule_count; i++) {
            Rule rule;
            rule.feature_id = param<int>("policy_ir_rule_" + std::to_string(i) + "_feature_id").default_val(-1);
            rule.operator_id = param<int>("policy_ir_rule_" + std::to_string(i) + "_operator_id").default_val(-1);
            rule.threshold = param<int>("policy_ir_rule_" + std::to_string(i) + "_threshold").default_val(-1);
            rule.action_type = param<int>("policy_ir_rule_" + std::to_string(i) + "_action_type").default_val(-1);
            rule.action_value = param<int>("policy_ir_rule_" + std::to_string(i) + "_action_value").default_val(-1);
            if (!is_supported_feature(rule.feature_id)) {
                s_policy_sidecar_unsupported_feature_count++;
                valid = false;
            }
            if (!is_supported_operator(rule.operator_id) || !is_supported_action(rule.action_type) ||
                rule.threshold < 0 || rule.action_value < 0) {
                valid = false;
            }
            if (rule.action_type == kActionSetQuota &&
                (rule.action_value < quota_min || rule.action_value > quota_max)) {
                valid = false;
            }
            if (rule.action_type == kActionDecreaseQuota &&
                (rule.action_value < 0 || rule.action_value > quota_max)) {
                valid = false;
            }
            loaded_rules.push_back(rule);
        }
        if (!valid) {
            s_policy_sidecar_policy_runtime_error_count++;
            m_enabled = false;
            m_rules.clear();
            s_policy_sidecar_policy_loaded = 0;
            s_policy_sidecar_rule_count = 0;
            return;
        }
        m_quota_min = quota_min;
        m_quota_max = quota_max;
        m_rules = loaded_rules;
        s_policy_sidecar_rule_count = (int) m_rules.size();
        s_policy_sidecar_loaded_quota_min = m_quota_min;
        s_policy_sidecar_loaded_quota_max = m_quota_max;
        s_policy_sidecar_policy_loaded = 1;
    }

    void setup(IFrontEnd* frontend, IMemorySystem* memory_system) override {
        (void) memory_system;
        m_frontend = static_cast<BHO3*>(frontend);
        m_llc = m_frontend->get_llc();
        m_cfg.set_device(cast_parent<IDRAMController>());
        m_num_cores = frontend->get_num_cores();

        float tck_ns = ((float) m_cfg.m_dram->m_timing_vals("tCK_ps") / 1000.0f);
        double window_clk = std::numeric_limits<double>::quiet_NaN();
        if (std::isfinite(tck_ns) && tck_ns > 0.0f) {
            window_clk = ((double) m_window_period_ns / (double) tck_ns);
        }
        if (
            !std::isfinite(window_clk)
            || window_clk < 1.0
            || window_clk > (double) std::numeric_limits<int>::max()
        ) {
            s_policy_sidecar_policy_runtime_error_count++;
            s_policy_sidecar_policy_loaded = 0;
            m_enabled = false;
            m_rules.clear();
            s_policy_sidecar_rule_count = 0;
            m_window_period_clk = 1;
        } else {
            m_window_period_clk = (int) window_clk;
        }
        s_policy_sidecar_loaded_window_period_ns = m_window_period_ns;
        s_policy_sidecar_loaded_window_period_clk = m_window_period_clk;

        m_window_refs.assign(m_num_cores, 0);
        m_prev_window_refs.assign(m_num_cores, 0);
        m_throttled.assign(m_num_cores, false);
        m_throttle_begin_clk.assign(m_num_cores, 0);
        s_policy_sidecar_actions_core.assign(m_num_cores, 0);
        s_policy_sidecar_duration_core.assign(m_num_cores, 0);
        s_policy_sidecar_max_window_refs_core.assign(m_num_cores, 0);
        s_policy_sidecar_setup_mshr_limit_before_core.assign(m_num_cores, -1);
        s_policy_sidecar_setup_mshr_limit_after_core.assign(m_num_cores, -1);
        s_policy_sidecar_finalize_mshr_limit_core.assign(m_num_cores, -1);
        s_policy_sidecar_rule_evaluation_count.assign(m_rules.size(), 0);
        s_policy_sidecar_rule_hit_count.assign(m_rules.size(), 0);
        s_policy_sidecar_loaded_rule_feature_id.assign(m_rules.size(), 0);
        s_policy_sidecar_loaded_rule_operator_id.assign(m_rules.size(), 0);
        s_policy_sidecar_loaded_rule_threshold.assign(m_rules.size(), 0);
        s_policy_sidecar_loaded_rule_action_type.assign(m_rules.size(), 0);
        s_policy_sidecar_loaded_rule_action_value.assign(m_rules.size(), 0);
        s_policy_sidecar_feature_samples.assign(3, 0);
        s_policy_sidecar_feature_min.assign(3, std::numeric_limits<int64_t>::max());
        s_policy_sidecar_feature_max.assign(3, std::numeric_limits<int64_t>::min());
        s_policy_sidecar_feature_sum.assign(3, 0);

        for (int i = 0; i < m_num_cores; i++) {
            int before = m_llc->get_blacklist_max_mshrs(i);
            s_policy_sidecar_setup_mshr_limit_before_core[i] = before;
            if (s_policy_sidecar_setup_mshr_limit_before < 0) {
                s_policy_sidecar_setup_mshr_limit_before = before;
            }
            if (m_enabled && s_policy_sidecar_policy_loaded == 1 && !m_rules.empty()) {
                m_llc->set_blacklist_max_mshrs(i, m_quota_max + 1);
            }
            int after = m_llc->get_blacklist_max_mshrs(i);
            s_policy_sidecar_setup_mshr_limit_after_core[i] = after;
            if (s_policy_sidecar_setup_mshr_limit_after < 0) {
                s_policy_sidecar_setup_mshr_limit_after = after;
            }
            register_stat(s_policy_sidecar_actions_core[i]).name("policy_sidecar_actions_core_{}", i);
            register_stat(s_policy_sidecar_duration_core[i]).name("policy_sidecar_duration_core_{}", i);
            register_stat(s_policy_sidecar_max_window_refs_core[i]).name("policy_sidecar_max_window_refs_core_{}", i);
            register_stat(s_policy_sidecar_setup_mshr_limit_before_core[i]).name("policy_sidecar_setup_mshr_limit_before_core_{}", i);
            register_stat(s_policy_sidecar_setup_mshr_limit_after_core[i]).name("policy_sidecar_setup_mshr_limit_after_core_{}", i);
            register_stat(s_policy_sidecar_finalize_mshr_limit_core[i]).name("policy_sidecar_finalize_mshr_limit_core_{}", i);
        }
        for (int i = 0; i < (int) m_rules.size(); i++) {
            s_policy_sidecar_loaded_rule_feature_id[i] = m_rules[i].feature_id;
            s_policy_sidecar_loaded_rule_operator_id[i] = m_rules[i].operator_id;
            s_policy_sidecar_loaded_rule_threshold[i] = m_rules[i].threshold;
            s_policy_sidecar_loaded_rule_action_type[i] = m_rules[i].action_type;
            s_policy_sidecar_loaded_rule_action_value[i] = m_rules[i].action_value;
            register_stat(s_policy_sidecar_rule_evaluation_count[i]).name("policy_sidecar_rule_{}_evaluation_count", i);
            register_stat(s_policy_sidecar_rule_hit_count[i]).name("policy_sidecar_rule_{}_hit_count", i);
            register_stat(s_policy_sidecar_loaded_rule_feature_id[i]).name("policy_sidecar_loaded_rule_{}_feature_id", i);
            register_stat(s_policy_sidecar_loaded_rule_operator_id[i]).name("policy_sidecar_loaded_rule_{}_operator_id", i);
            register_stat(s_policy_sidecar_loaded_rule_threshold[i]).name("policy_sidecar_loaded_rule_{}_threshold", i);
            register_stat(s_policy_sidecar_loaded_rule_action_type[i]).name("policy_sidecar_loaded_rule_{}_action_type", i);
            register_stat(s_policy_sidecar_loaded_rule_action_value[i]).name("policy_sidecar_loaded_rule_{}_action_value", i);
        }
        register_stat(s_policy_sidecar_actions_applied).name("policy_sidecar_actions_applied");
        register_stat(s_policy_sidecar_windows).name("policy_sidecar_windows");
        register_stat(s_policy_sidecar_opening_requests).name("policy_sidecar_opening_requests");
        register_stat(s_policy_sidecar_invalid_source_id).name("policy_sidecar_invalid_source_id");
        register_stat(s_policy_sidecar_throttle_entered).name("policy_sidecar_throttle_entered");
        register_stat(s_policy_sidecar_blacklist_success).name("policy_sidecar_blacklist_success");
        register_stat(s_policy_sidecar_loaded_window_period_ns).name("policy_sidecar_loaded_window_period_ns");
        register_stat(s_policy_sidecar_loaded_window_period_clk).name("policy_sidecar_loaded_window_period_clk");
        register_stat(s_policy_sidecar_last_mshr_before).name("policy_sidecar_last_mshr_before");
        register_stat(s_policy_sidecar_last_mshr_after).name("policy_sidecar_last_mshr_after");
        register_stat(s_policy_sidecar_min_mshr_after).name("policy_sidecar_min_mshr_after");
        register_stat(s_policy_sidecar_max_mshr_before).name("policy_sidecar_max_mshr_before");
        register_stat(s_policy_sidecar_policy_loaded).name("policy_sidecar_policy_loaded");
        register_stat(s_policy_sidecar_rule_count).name("policy_sidecar_rule_count");
        register_stat(s_policy_sidecar_loaded_quota_min).name("policy_sidecar_loaded_quota_min");
        register_stat(s_policy_sidecar_loaded_quota_max).name("policy_sidecar_loaded_quota_max");
        register_stat(s_policy_sidecar_setup_mshr_limit_before).name("policy_sidecar_setup_mshr_limit_before");
        register_stat(s_policy_sidecar_setup_mshr_limit_after).name("policy_sidecar_setup_mshr_limit_after");
        register_stat(s_policy_sidecar_finalize_mshr_limit).name("policy_sidecar_finalize_mshr_limit");
        register_stat(s_policy_sidecar_action_set_quota_count).name("policy_sidecar_action_set_quota_count");
        register_stat(s_policy_sidecar_action_decrease_quota_count).name("policy_sidecar_action_decrease_quota_count");
        register_stat(s_policy_sidecar_action_value_last).name("policy_sidecar_action_value_last");
        register_stat(s_policy_sidecar_quota_before_last).name("policy_sidecar_quota_before_last");
        register_stat(s_policy_sidecar_quota_after_last).name("policy_sidecar_quota_after_last");
        register_stat(s_policy_sidecar_unsupported_feature_count).name("policy_sidecar_unsupported_feature_count");
        register_stat(s_policy_sidecar_policy_runtime_error_count).name("policy_sidecar_policy_runtime_error_count");
        for (int feature_id = 1; feature_id <= 2; feature_id++) {
            register_stat(s_policy_sidecar_feature_samples[feature_id]).name("policy_sidecar_feature_{}_samples", feature_id);
            register_stat(s_policy_sidecar_feature_min[feature_id]).name("policy_sidecar_feature_{}_min", feature_id);
            register_stat(s_policy_sidecar_feature_max[feature_id]).name("policy_sidecar_feature_{}_max", feature_id);
            register_stat(s_policy_sidecar_feature_sum[feature_id]).name("policy_sidecar_feature_{}_sum", feature_id);
        }
        std::cout << "policy_sidecar_declared_policy_ir_sha256: " << m_policy_ir_sha256 << std::endl;
        std::cout << "policy_sidecar_loaded_schema_version: " << m_schema_version << std::endl;
    }

    void update(bool request_found, ReqBuffer::iterator& req_it) override {
        m_clk++;
        if (!m_enabled) {
            return;
        }

        if (!request_found) {
            if (m_clk % m_window_period_clk == 0) {
                close_window();
            }
            return;
        }

        auto& req = *req_it;
        auto& req_meta = m_cfg.m_dram->m_command_meta(req.command);
        auto& req_scope = m_cfg.m_dram->m_command_scopes(req.command);
        if (!(req_meta.is_opening && req_scope == m_cfg.m_row_level)) {
            if (m_clk % m_window_period_clk == 0) {
                close_window();
            }
            return;
        }
        if (req.source_id < 0 || req.source_id >= m_num_cores) {
            s_policy_sidecar_invalid_source_id++;
            if (m_clk % m_window_period_clk == 0) {
                close_window();
            }
            return;
        }

        s_policy_sidecar_opening_requests++;
        int source_id = req.source_id;
        m_window_refs[source_id]++;
        s_policy_sidecar_max_window_refs_core[source_id] = std::max(
            s_policy_sidecar_max_window_refs_core[source_id],
            (uint64_t) m_window_refs[source_id]
        );
        evaluate_rules(source_id);
        if (m_clk % m_window_period_clk == 0) {
            close_window();
        }
    }

    void finalize() override {
        for (int i = 0; i < m_num_cores; i++) {
            if (m_throttled[i]) {
                s_policy_sidecar_duration_core[i] += m_clk - m_throttle_begin_clk[i];
            }
            int limit = m_llc->get_blacklist_max_mshrs(i);
            s_policy_sidecar_finalize_mshr_limit_core[i] = limit;
            if (s_policy_sidecar_finalize_mshr_limit < 0) {
                s_policy_sidecar_finalize_mshr_limit = limit;
            }
        }
        for (int feature_id = 1; feature_id <= 2; feature_id++) {
            if (s_policy_sidecar_feature_samples[feature_id] == 0) {
                s_policy_sidecar_feature_min[feature_id] = 0;
                s_policy_sidecar_feature_max[feature_id] = 0;
            }
        }
        std::cout << "policy_sidecar_declared_policy_ir_sha256: " << m_policy_ir_sha256 << std::endl;
        std::cout << "policy_sidecar_loaded_schema_version: " << m_schema_version << std::endl;
    }

private:
    bool is_supported_feature(int feature_id) const {
        return feature_id == kFeatureActivationFast || feature_id == kFeatureActivationSlow;
    }

    bool is_supported_operator(int operator_id) const {
        return operator_id == kOpGte || operator_id == kOpGt || operator_id == kOpLte || operator_id == kOpLt;
    }

    bool is_supported_action(int action_type) const {
        return action_type == kActionSetQuota || action_type == kActionDecreaseQuota;
    }

    int feature_value(int feature_id, int source_id) {
        int value = 0;
        if (feature_id == kFeatureActivationFast) {
            value = m_window_refs[source_id];
        } else if (feature_id == kFeatureActivationSlow) {
            value = m_prev_window_refs[source_id];
        } else {
            s_policy_sidecar_unsupported_feature_count++;
            s_policy_sidecar_policy_runtime_error_count++;
            return 0;
        }
        s_policy_sidecar_feature_samples[feature_id]++;
        s_policy_sidecar_feature_min[feature_id] = std::min(s_policy_sidecar_feature_min[feature_id], (int64_t) value);
        s_policy_sidecar_feature_max[feature_id] = std::max(s_policy_sidecar_feature_max[feature_id], (int64_t) value);
        s_policy_sidecar_feature_sum[feature_id] += value;
        return value;
    }

    bool compare(int lhs, int operator_id, int rhs) {
        if (operator_id == kOpGte) return lhs >= rhs;
        if (operator_id == kOpGt) return lhs > rhs;
        if (operator_id == kOpLte) return lhs <= rhs;
        if (operator_id == kOpLt) return lhs < rhs;
        s_policy_sidecar_policy_runtime_error_count++;
        return false;
    }

    void evaluate_rules(int source_id) {
        for (int i = 0; i < (int) m_rules.size(); i++) {
            const Rule& rule = m_rules[i];
            s_policy_sidecar_rule_evaluation_count[i]++;
            int value = feature_value(rule.feature_id, source_id);
            if (!compare(value, rule.operator_id, rule.threshold)) {
                continue;
            }
            s_policy_sidecar_rule_hit_count[i]++;
            if (!m_throttled[source_id]) {
                apply_action(source_id, rule);
            }
            break;
        }
    }

    void close_window() {
        s_policy_sidecar_windows++;
        for (int i = 0; i < m_num_cores; i++) {
            if (m_throttled[i]) {
                m_llc->erase_blacklist(i);
                m_llc->set_blacklist_max_mshrs(i, m_quota_max + 1);
                s_policy_sidecar_duration_core[i] += m_clk - m_throttle_begin_clk[i];
                m_throttled[i] = false;
            }
            m_prev_window_refs[i] = m_window_refs[i];
            m_window_refs[i] = 0;
        }
    }

    void apply_action(int source_id, const Rule& rule) {
        if (!m_enabled || s_policy_sidecar_policy_loaded != 1) {
            return;
        }
        int cur_limit = m_llc->get_blacklist_max_mshrs(source_id);
        int next_limit = cur_limit;
        if (rule.action_type == kActionSetQuota) {
            next_limit = std::max(m_quota_min, std::min(m_quota_max, rule.action_value));
        } else if (rule.action_type == kActionDecreaseQuota) {
            next_limit = std::max(m_quota_min, cur_limit - std::max(0, rule.action_value));
        } else {
            s_policy_sidecar_policy_runtime_error_count++;
            return;
        }
        s_policy_sidecar_throttle_entered++;
        m_throttled[source_id] = true;
        m_llc->add_blacklist(source_id);
        m_llc->set_blacklist_max_mshrs(source_id, next_limit);
        if (rule.action_type == kActionSetQuota) {
            s_policy_sidecar_action_set_quota_count++;
        } else if (rule.action_type == kActionDecreaseQuota) {
            s_policy_sidecar_action_decrease_quota_count++;
        }
        s_policy_sidecar_last_mshr_before = cur_limit;
        s_policy_sidecar_last_mshr_after = next_limit;
        s_policy_sidecar_quota_before_last = cur_limit;
        s_policy_sidecar_quota_after_last = next_limit;
        s_policy_sidecar_action_value_last = rule.action_value;
        s_policy_sidecar_max_mshr_before = std::max(s_policy_sidecar_max_mshr_before, cur_limit);
        if (s_policy_sidecar_min_mshr_after < 0) {
            s_policy_sidecar_min_mshr_after = next_limit;
        } else {
            s_policy_sidecar_min_mshr_after = std::min(s_policy_sidecar_min_mshr_after, next_limit);
        }
        m_throttle_begin_clk[source_id] = m_clk;
        s_policy_sidecar_actions_applied++;
        s_policy_sidecar_actions_core[source_id]++;
        s_policy_sidecar_blacklist_success++;
    }
};

}       // namespace Ramulator
