"""Opt-in live model check against synthetic identity evidence only."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.copilot import summarize_case
from core.detector import Detector
from core.incidents import summarize_investigation
from core.investigations import Investigation
from core.pipeline import input_from_profile, load_inputs
from core.rule_engine import RuleEngine

root = Path(__file__).resolve().parents[1]
case = Investigation.create('Synthetic local model verification')
case.events, _ = load_inputs([input_from_profile('entra_audit', root / 'examples/identity_review.jsonl')])
case.alerts = Detector(RuleEngine.from_directory(root / 'rules')).run(case.events)
started = time.monotonic()
result = summarize_case(summarize_investigation(case), structured=True)
print('Validated citations:', len(result['evidence']), 'Elapsed seconds:', round(time.monotonic() - started, 1))
