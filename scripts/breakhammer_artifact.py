"""HammerEVO BreakHammer artifact metadata.

This module is intentionally small and importable by tests and adapters.  It
describes the D0 mechanisms used by HammerEVO's matrix validators and the
original BreakHammer D1 profile used as the first incumbent.
"""

from __future__ import annotations

from math import ceil, floor
from copy import deepcopy
from typing import Any

D0_NAMES = ("AQUA", "Graphene", "Hydra", "PARA", "REGA", "RFM", "TWiCe-Ideal", "PRAC")
NRH_VALUES = (4096, 2048, 1024, 512, 256, 128, 64)

BREAKHAMMER_PROFILE: dict[str, Any] = {
    "throttle_type": "MEAN",
    "throttle_flat_thresh": 32,
    "throttle_dynamic_thresh": 0.65,
    # DDR5 refresh window (tREF_W) is 32 ms (BreakHammer paper SS2, citing
    # JEDEC DDR5).  The paper's TH_window=64 ms reused the DDR4 value; for a
    # DDR5-VRR simulator the physically correct refresh window is 32 ms.
    "window_period_ns": 32_000_000,
    "blacklist_max_mshr": 5,
    "mshr_decrement": 1,
    "breakhammer_plus": True,
}


def _graphene_parameters(nrh: int) -> dict[str, Any]:
    t_refw_ns = 32_000_000
    t_rc_ns = 46
    k = 1
    return {
        "num_table_entries": int(ceil((t_refw_ns / t_rc_ns) / nrh * ((k + 1) / k) - 1)),
        "activation_threshold": int(floor(nrh / (k + 1))),
        "reset_period_ns": int(t_refw_ns / k),
    }


def _hydra_parameters(nrh: int) -> dict[str, Any]:
    tracking_threshold = int(floor(nrh / 2))
    return {
        "hydra_tracking_threshold": tracking_threshold,
        "hydra_group_threshold": int(floor(tracking_threshold * 4 / 5)),
        "hydra_row_group_size": 128,
        "hydra_reset_period_ns": 32_000_000,
        "hydra_rcc_num_per_rank": 4096,
        "hydra_rcc_policy": "RANDOM",
    }


def _aqua_parameters(nrh: int) -> dict[str, Any]:
    t_refw_ns = 32_000_000
    t_rc_ns = 46
    reset_period_ns = t_refw_ns
    art_threshold = int(floor(nrh / 2))
    num_art_entries = int(ceil((t_refw_ns / t_rc_ns) / art_threshold))
    t_agg = art_threshold * t_rc_ns
    t_move = (128 * 5 + t_rc_ns) * 2
    num_qrows_per_bank = int(ceil(t_refw_ns / (16 * t_move + t_agg)))
    return {
        "art_threshold": art_threshold,
        "num_art_entries": num_art_entries,
        "num_qrows_per_bank": num_qrows_per_bank,
        "num_fpt_entries": num_qrows_per_bank,
        "reset_period_ns": reset_period_ns,
    }


def _twice_parameters(nrh: int) -> dict[str, Any]:
    t_refw_ns = 32_000_000
    t_refi_ns = 3900
    twice_rh_threshold = int(floor(nrh / 2))
    return {
        "twice_rh_threshold": twice_rh_threshold,
        "twice_pruning_interval_threshold": twice_rh_threshold / (t_refw_ns / t_refi_ns),
    }


def _rega_parameters(nrh: int) -> dict[str, Any]:
    """ThrottleREGA V/T/tRAS derivation from the original BreakHammer artifact.

    ``get_rega_parameters`` derives ``V = ceil(SUBARR_SIZE / tRH)``,
    ``T = ceil(tRH / SUBARR_SIZE)`` and ``tRAS = ceil(32 + (V-1)*17.5)``.
    The tRAS term is a DRAM timing override (``DRAM.tRAS``), not a plugin
    parameter, so it is surfaced via ``d0_spec(...)["dram"]["tRAS"]``.
    """

    subarray_size = 512
    threshold = max(1, int(nrh))
    V = int(ceil(subarray_size / threshold))
    T = int(ceil(threshold / subarray_size))
    return {
        "V": V,
        "T": T,
        "tRAS": int(ceil(32 + (V - 1) * 17.5)),
    }


def _rfm_threshold(nrh: int) -> int:
    """RFM per-bank activation threshold from the original BreakHammer artifact.

    ``get_rfm_parameters`` maps the RowHammer threshold to an RFM threshold via
    a fixed pair table, falling back to 80 for large thresholds.  Binding
    ``rfm_thresh = nrh`` directly (as the previous metadata did) made RFM
    ~51x less sensitive at ``nrh=4096`` (threshold 4096 instead of 80), so the
    attacker never accumulated enough RFM actions for BreakHammer to throttle.
    """

    threshold = max(1, int(nrh))
    for bound, rfm_thresh in ((16, 1), (20, 2), (32, 3), (64, 6), (128, 13), (256, 27), (512, 60)):
        if threshold <= bound:
            return rfm_thresh
    return 80


def _para_parameters(nrh: int) -> dict[str, Any]:
    """PARA probability from the original BreakHammer artifact.

    ``get_para_parameters`` sets ``threshold = 1 - (1e-15) ** (1 / tRH)``.  The
    previous ``1.0 / nrh`` was ~34x smaller at ``nrh=4096``, making PARA issue
    victim-row refreshes far less often than the artifact intends.
    """

    threshold = max(1, int(nrh))
    probability = 1.0 - (10.0 ** -15) ** (1.0 / threshold)
    return {"threshold": probability}


def _plugins_for(mitigation: str, nrh: int) -> dict[str, Any]:
    rega = _rega_parameters(nrh)
    dram: dict[str, Any] = {}
    if mitigation == "REGA":
        # REGA's tRAS term is a DRAM timing override, matching the original
        # add_mitigation: config["MemorySystem"]["DRAM"]["tRAS"] = tRAS.
        dram["tRAS"] = rega["tRAS"]
    plugins_by_name: dict[str, list[dict[str, Any]]] = {
        "AQUA": [{"ControllerPlugin": {"impl": "AQUA", **_aqua_parameters(nrh)}}],
        "Graphene": [{"ControllerPlugin": {"impl": "Graphene", **_graphene_parameters(nrh)}}],
        "Hydra": [{"ControllerPlugin": {"impl": "Hydra", **_hydra_parameters(nrh)}}],
        "PARA": [{"ControllerPlugin": {"impl": "PARA", **_para_parameters(nrh)}}],
        "REGA": [{"ControllerPlugin": {"impl": "ThrottleREGA", "V": rega["V"], "T": rega["T"]}}],
        "RFM": [
            {"ControllerPlugin": {"impl": "ThrottleRFM"}},
            {"ControllerPlugin": {"impl": "RFMManager", "rfm_thresh": _rfm_threshold(nrh), "rfm_plus": False}},
        ],
        "TWiCe-Ideal": [{"ControllerPlugin": {"impl": "TWiCe-Ideal", **_twice_parameters(nrh)}}],
        "Dummy": [{"ControllerPlugin": {"impl": "DummyMitigation"}}],
    }
    return {
        "name": mitigation,
        "nrh": nrh,
        "controller_impl": "BHDRAMController",
        "scheduler_impl": "BHScheduler",
        "plugins": deepcopy(plugins_by_name.get(mitigation, plugins_by_name["Dummy"])),
        "dram": dram,
    }


def d0_spec(name: str, nrh: int) -> dict[str, Any]:
    """Return the concrete controller/plugin installation for one D0."""

    canonical = {
        "aqua": "AQUA",
        "graphene": "Graphene",
        "hydra": "Hydra",
        "para": "PARA",
        "rega": "REGA",
        "rfm": "RFM",
        "twice": "TWiCe-Ideal",
        "twice-ideal": "TWiCe-Ideal",
        "twice_ideal": "TWiCe-Ideal",
        "prac": "PRAC",
        "dummy": "Dummy",
    }.get(name.lower(), name)
    if canonical == "PRAC":
        return {
            "name": "PRAC",
            "nrh": nrh,
            "controller_impl": "PRACDRAMController",
            "scheduler_impl": "PRACScheduler",
            "plugins": [{"ControllerPlugin": {"impl": "PRAC", "nrh": nrh}}],
            "dram": {"PRAC": True},
        }
    return _plugins_for(canonical, nrh)


__all__ = ["BREAKHAMMER_PROFILE", "D0_NAMES", "NRH_VALUES", "d0_spec"]
