"""
OPERATION FORAGER — Full Pipeline Runner
=========================================
Runs the complete lab end to end:
  1. Generate all three log sources (51,225 events)
  2. Run all four detections
  3. Score results against ground truth
  4. Run AI triage exercise

Usage:
  python run_all.py
  python run_all.py --skip-generate   (if data already exists)
  python run_all.py --ai-only         (run AI exercise only)
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def generate_data():
    print("\n" + "=" * 60)
    print("  PHASE 1 — GENERATING TELEMETRY")
    print("=" * 60)
    Path("data").mkdir(exist_ok=True)
    from data.generate_web_logs      import write_logs as gen_web
    from data.generate_identity_logs import write_logs as gen_identity
    from data.generate_cloud_logs    import write_logs as gen_cloud
    gen_web()
    gen_identity()
    gen_cloud()


def run_detections():
    print("\n" + "=" * 60)
    print("  PHASE 2 — RUNNING DETECTIONS")
    print("=" * 60)

    from detections.IDNT_002_identity_takeover    import run_detection as idnt002, load_identity_logs
    from detections.CLD_004_access_key_persistence import run_detection as cld004, load_cloud_logs
    from detections.CLD_005_logging_tamper         import run_detection as cld005
    from detections.CLD_006_recon_burst            import run_detection as cld006

    identity_logs = load_identity_logs()
    cloud_logs    = load_cloud_logs()

    for fn, logs, label in [
        (idnt002, identity_logs, "IDNT-002"),
        (cld004,  cloud_logs,   "CLD-004"),
        (cld005,  cloud_logs,   "CLD-005"),
        (cld006,  cloud_logs,   "CLD-006"),
    ]:
        alerts = fn(logs)
        status = "FIRED" if alerts else "SILENT"
        print(f"\n  [{label}] {status} — {len(alerts)} alert(s)")
        for a in alerts:
            print(f"    → {a.get('title', a.get('rule_id'))}")


def run_validation():
    print("\n" + "=" * 60)
    print("  PHASE 3 — SCORING DETECTIONS")
    print("=" * 60)
    from validation.harness import main as score
    score()


def run_ai_exercise():
    print("\n" + "=" * 60)
    print("  PHASE 4 — AI TRIAGE VALIDATION EXERCISE")
    print("=" * 60)
    from ai_exercise.triage_simulator import run_exercise
    run_exercise()


def main():
    parser = argparse.ArgumentParser(description="Operation FORAGER — full pipeline runner")
    parser.add_argument("--skip-generate", action="store_true",
                        help="Skip log generation (use existing data files)")
    parser.add_argument("--ai-only", action="store_true",
                        help="Run only the AI triage exercise")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  OPERATION FORAGER")
    print("  AI-Augmented Detection Engineering Lab")
    print("=" * 60)

    if args.ai_only:
        run_ai_exercise()
        return

    if not args.skip_generate:
        generate_data()

    run_detections()
    run_validation()
    run_ai_exercise()

    print("\n[+] Complete. All phases finished.\n")


if __name__ == "__main__":
    main()
