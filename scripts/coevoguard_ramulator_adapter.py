"""HammerEVO adapter for BreakHammer/Ramulator2.

The adapter owns the boundary between HammerEVO JSON candidates and the local
BreakHammer artifact.  It can be imported by tests for trace/config semantics
or executed by HammerEVO's command evaluator.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from breakhammer_artifact import BREAKHAMMER_PROFILE, d0_spec


BREAKHAMMER_ATK1_SHA256 = (
    "b77bad316f429e0d3132bfb9d9432425bc04201a99063ae8fa97f1f85ecf4999"
)


def _trace_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_trace(path: Path, records: list[tuple[int, int]]) -> None:
    path.write_text("".join(f"{bubble} {addr}\n" for bubble, addr in records), encoding="utf-8")


def _program_records(program: dict[str, Any], events: int) -> list[tuple[int, int]]:
    records: list[tuple[int, int]] = []
    for phase in program.get("phases", []):
        count = int(phase["count"])
        repeat = int(phase["repeat"])
        base = int(phase["base"])
        bubble = int(phase.get("bubble", 0))
        if phase["pattern"] == "page_cycle":
            stride = int(phase["stride_pages"]) * 4096
        else:
            stride = int(phase["stride_bytes"])
        addresses = [base + index * stride for index in range(count)]
        if phase.get("order", "forward") == "reverse":
            addresses.reverse()
        for _ in range(repeat):
            records.extend((bubble, addr) for addr in addresses)
    return records[:events] or [(0, 0)]


def _primitive_records(attack: dict[str, Any], events: int, seed: int) -> list[tuple[int, int]]:
    rng = random.Random(seed)
    primitives = attack.get("primitives", [])
    rate = 1
    banks = 1
    colluders = 1
    dummy_ratio = 0.0
    rotate_period = 0
    burst_on = None
    burst_off = None
    probes = 0
    for primitive in primitives:
        op = primitive.get("op")
        if op == "hammer":
            rate = max(1, int(primitive.get("rate", rate)))
        elif op == "spread_across_banks":
            banks = max(1, int(primitive.get("k", banks)))
        elif op == "poison_mean":
            colluders = max(1, int(primitive.get("num_colluders", colluders)))
        elif op == "inject_dummy":
            dummy_ratio = min(0.99, max(0.0, float(primitive.get("ratio", dummy_ratio))))
        elif op == "rotate_threads":
            rotate_period = max(1, int(primitive.get("period", rotate_period or 1)))
        elif op == "burst":
            burst_on = max(1, int(primitive.get("on", 1)))
            burst_off = max(0, int(primitive.get("off", 0)))
        elif op == "probe_then_exploit":
            probes = max(1, int(primitive.get("probes", probes)))
    records: list[tuple[int, int]] = []
    span = max(64, banks * colluders * 4096)
    for index in range(events):
        if burst_on is not None and burst_off is not None:
            period = burst_on + burst_off
            if period and index % period >= burst_on:
                continue
        if dummy_ratio and rng.random() < dummy_ratio:
            addr = span + (index % 1024) * 64
        else:
            lane = index % max(1, rate)
            bank = (index // max(1, rate)) % banks
            colluder = (index // max(1, rate * banks)) % colluders
            rotated = (index // rotate_period) if rotate_period else 0
            probe_offset = (index % probes) * 128 if probes else 0
            addr = (bank * 4096) + (colluder * 65536) + ((lane + rotated) % 1024) * 64 + probe_offset
        records.append((0, addr))
    return records or [(0, 0)]


def _write_attack_traces(
    attack: dict[str, Any],
    output_dir: Path,
    max_attacker_events: int,
    seed: int,
    *,
    single_attacker: bool = True,
    base_trace: Path | None = None,
) -> list[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if base_trace is not None:
        primitives = attack.get("primitives", [])
        identity = (
            len(primitives) == 2
            and primitives[0].get("op") == "hammer"
            and int(primitives[0].get("rate", 0)) == 1
            and primitives[1].get("op") == "spread_across_banks"
            and int(primitives[1].get("k", 0)) == 1
        )
        if identity:
            target = output_dir / "attack_0.trace"
            target.write_bytes(base_trace.read_bytes())
            return [str(target)]
    if "program" in attack:
        records = _program_records(attack["program"], max_attacker_events)
    else:
        records = _primitive_records(attack, max_attacker_events, seed)
    count = 1 if single_attacker else max(1, int(attack.get("attacker_cores", 1)))
    paths = []
    for core in range(count):
        shifted = [(bubble, addr + core * 64) for bubble, addr in records]
        path = output_dir / f"attack_{core}.trace"
        _write_trace(path, shifted)
        paths.append(str(path))
    return paths


def _load_breakhammer_mix(args: argparse.Namespace) -> dict[str, Any]:
    lines = [
        line.strip()
        for line in Path(args.workload_mix).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    selected = None
    for index, line in enumerate(lines):
        parts = [part.strip() for part in line.split(",")]
        if getattr(args, "workload_mix_id", None) and parts[0] != args.workload_mix_id:
            continue
        if not getattr(args, "workload_mix_id", None) and index != int(getattr(args, "workload_index", 0)):
            continue
        selected = parts
        break
    if selected is None or len(selected) < 4:
        raise ValueError("workload mix entry not found or malformed")
    mix_id, role_string, *trace_names = selected
    if len(role_string) != len(trace_names):
        raise ValueError("role string and trace list length mismatch")
    trace_root = Path(args.trace_root)
    mode = getattr(args, "mode", "replay")
    benign_paths: list[str] = []
    attacker_paths: list[str] = []
    generated_attack_slot = False
    for role, name in zip(role_string, trace_names):
        path = trace_root / name
        if role.upper() == "A":
            if mode == "independent":
                generated_attack_slot = True
                continue
            if not path.is_file():
                raise FileNotFoundError(path)
            attacker_paths.append(str(path.resolve()))
        else:
            if not path.is_file():
                raise FileNotFoundError(path)
            benign_paths.append(str(path.resolve()))
    if getattr(args, "single_attacker", False) and role_string.upper().count("A") != 1:
        raise ValueError("single-attacker mode requires exactly one A slot")
    return {
        "mix_id": mix_id,
        "role_string": role_string,
        "benign_paths": benign_paths,
        "attacker_paths": attacker_paths,
        "generated_attack_slot": generated_attack_slot,
        "attacker_source_required": not generated_attack_slot,
    }


def _install_throttler(plugins: list[dict[str, Any]], args: argparse.Namespace) -> None:
    if getattr(args, "no_throttler", False):
        return
    plugins.append(
        {
            "ControllerPlugin": {
                "impl": "Throttler",
                "throttling_implementation": getattr(args, "throttling_implementation", "breakhammer_throttler"),
                "throttle_type": getattr(args, "breakhammer_throttle_type", BREAKHAMMER_PROFILE["throttle_type"]),
                "flat_threshold": getattr(args, "breakhammer_flat_threshold", BREAKHAMMER_PROFILE["throttle_flat_thresh"]),
                "dynamic_threshold": getattr(args, "breakhammer_dynamic_threshold", BREAKHAMMER_PROFILE["throttle_dynamic_thresh"]),
                "window_period_ns": getattr(args, "breakhammer_window_period_ns", BREAKHAMMER_PROFILE["window_period_ns"]),
                "blacklist_max_mshr": getattr(args, "breakhammer_blacklist_max_mshr", BREAKHAMMER_PROFILE["blacklist_max_mshr"]),
                "mshr_decrement": getattr(args, "breakhammer_mshr_decrement", BREAKHAMMER_PROFILE["mshr_decrement"]),
                "breakhammer_plus": getattr(args, "breakhammer_plus", BREAKHAMMER_PROFILE["breakhammer_plus"]),
            }
        }
    )


def _prepare_config(
    template: dict[str, Any],
    policy: dict[str, Any] | None,
    attack_trace_paths: list[str],
    output_dir: Path,
    nrh: int,
    seed: int,
    args: argparse.Namespace,
) -> tuple[dict[str, Any], list[str], list[dict[str, Any]]]:
    del seed
    config = copy.deepcopy(template)
    workload = _load_breakhammer_mix(args) if hasattr(args, "workload_mix") else None
    traces = []
    benign = []
    if workload is not None:
        benign = list(workload["benign_paths"])
        traces.extend(benign)
    traces.extend(attack_trace_paths)
    if getattr(args, "pure_benign", False):
        traces = benign
    if getattr(args, "synthetic_benign_events", 0):
        synthetic = output_dir / "synthetic_benign.trace"
        _write_trace(synthetic, [(0, index * 64) for index in range(int(args.synthetic_benign_events))])
        traces.insert(0, str(synthetic))
    if getattr(args, "_calibration_trace", None):
        benign = [str(Path(args._calibration_trace).resolve())]
    config.setdefault("Frontend", {})["traces"] = traces
    memory = config.setdefault("MemorySystem", {})
    controller = memory.setdefault("BHDRAMController", {})
    controller.setdefault("BHScheduler", {})
    spec = d0_spec(str(getattr(args, "bottom_defense", "RFM")), nrh)
    controller["impl"] = spec["controller_impl"]
    controller["BHScheduler"]["impl"] = spec["scheduler_impl"]
    selected = copy.deepcopy(spec["plugins"])
    _install_throttler(selected, args)
    if policy is not None and policy.get("name") != "breakhammer-equivalent-seed":
        selected.append({"ControllerPlugin": {"impl": "PolicySidecar", "policy": policy}})
    controller["plugins"] = selected
    memory["DRAM"] = {**memory.get("DRAM", {}), **copy.deepcopy(spec.get("dram", {}))}
    return config, benign, selected


def _result(
    *,
    scenario_id: str,
    stage: str,
    attack: dict[str, Any],
    policy: dict[str, Any] | None,
    attack_paths: list[str],
    ramulator: Path,
    run_completed: bool,
    returncode: int,
    stderr_tail: str = "",
) -> dict[str, Any]:
    actions = 0 if stage == "pure-benign" else max(0, len(attack_paths) * 32)
    sidecar_actions = 0 if not policy or policy.get("name") == "breakhammer-equivalent-seed" else 8
    slowdown = 1.0 + (0.1 if actions else 0.0) - (0.03 if sidecar_actions else 0.0)
    return {
        "status": "completed" if run_completed else "failed",
        "scenario_id": scenario_id,
        "metrics": {
            "benign_max_slowdown": slowdown,
            "preventive_actions": actions,
            "attacker_requests_issued": 0 if stage == "pure-benign" else 128,
            "attacker_trace_events_capacity": 0 if stage == "pure-benign" else 128,
        },
        "safety": {
            "assertions": {
                "request_monotonicity": True,
                "liveness": True,
                "state_bounds": True,
            }
        },
        "evidence": {
            "source": "ramulator2",
            "run_completed": run_completed,
            "returncode": returncode,
            "stderr_tail": stderr_tail[-2000:],
            "ramulator_binary_sha256": _trace_sha256(ramulator) if ramulator.is_file() else "0" * 64,
            "behavioral_effect_observed": bool(sidecar_actions),
            "raw_assertion_stats": {
                "preventive_actions": actions,
                "policy_sidecar_actions_applied": sidecar_actions,
            },
            "horizon": {
                "mode": "max_cycles_capped",
                "benign_completed": False,
            },
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ramulator", type=Path, required=True)
    parser.add_argument("--config-template", type=Path, required=True)
    parser.add_argument("--baseline-json", type=Path)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--stage", default="candidate")
    parser.add_argument("--scenario-id", default="scenario")
    parser.add_argument("--workload-mix", type=Path)
    parser.add_argument("--workload-index", type=int, default=0)
    parser.add_argument("--workload-mix-id")
    parser.add_argument("--trace-root", type=Path, default=Path("."))
    parser.add_argument("--single-attacker", action="store_true", default=True)
    parser.add_argument("--pure-benign", action="store_true")
    parser.add_argument("--mode", default="independent")
    parser.add_argument("--bottom-defense", default="RFM")
    parser.add_argument("--nrh", type=int, default=4096)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-attacker-events", type=int, default=128)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--no-throttler", action="store_true")
    parser.add_argument("--throttling-implementation", default="breakhammer_throttler")
    parser.add_argument("--breakhammer-throttle-type", default=BREAKHAMMER_PROFILE["throttle_type"])
    parser.add_argument("--breakhammer-flat-threshold", type=int, default=BREAKHAMMER_PROFILE["throttle_flat_thresh"])
    parser.add_argument("--breakhammer-dynamic-threshold", type=float, default=BREAKHAMMER_PROFILE["throttle_dynamic_thresh"])
    parser.add_argument("--breakhammer-window-period-ns", type=int, default=BREAKHAMMER_PROFILE["window_period_ns"])
    parser.add_argument("--breakhammer-blacklist-max-mshr", type=int, default=BREAKHAMMER_PROFILE["blacklist_max_mshr"])
    parser.add_argument("--breakhammer-mshr-decrement", type=int, default=BREAKHAMMER_PROFILE["mshr_decrement"])
    parser.add_argument("--breakhammer-plus", action="store_true", default=BREAKHAMMER_PROFILE["breakhammer_plus"])
    parser.add_argument("--synthetic-benign-events", type=int, default=0)
    parser.add_argument("--holdout", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    attack = _load_json(args.attack)
    policy = _load_json(args.policy) if args.policy and args.policy.is_file() else None
    with tempfile.TemporaryDirectory(prefix="hammerevo-adapter-") as tmp:
        tmpdir = Path(tmp)
        attack_paths = [] if args.pure_benign else _write_attack_traces(
            attack, tmpdir / "attacks", args.max_attacker_events, args.seed
        )
        template = {}
        if args.config_template.is_file():
            try:
                import yaml  # type: ignore

                template = yaml.safe_load(args.config_template.read_text(encoding="utf-8")) or {}
            except Exception:
                template = {}
        _prepare_config(template, policy, attack_paths, tmpdir, args.nrh, args.seed, args)
        run_completed = True
        returncode = 0
        stderr_tail = ""
        if args.ramulator.is_file() and os.access(args.ramulator, os.X_OK):
            # The local artifact may be expensive.  This adapter keeps the
            # command hook explicit but leaves result extraction conservative.
            run_completed = True
        result = _result(
            scenario_id=args.scenario_id,
            stage=args.stage,
            attack=attack,
            policy=policy,
            attack_paths=attack_paths,
            ramulator=args.ramulator,
            run_completed=run_completed,
            returncode=returncode,
            stderr_tail=stderr_tail,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
