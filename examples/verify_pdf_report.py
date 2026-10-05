from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.investigations import Investigation
from core.pipeline import input_from_profile, load_inputs
from core.rule_engine import RuleEngine
from core.detector import Detector
from core.pdf_report import render_case_pdf

root = Path(__file__).resolve().parents[1]
case = Investigation.create('Synthetic identity investigation', 'Manual PDF layout verification with synthetic evidence.')
case.events, _ = load_inputs([input_from_profile('entra_audit', root / 'examples/identity_review.jsonl')])
case.alerts = Detector(RuleEngine.from_directory(root / 'rules')).run(case.events)
case.alert_reviews[case.alerts[0].id] = {'disposition': 'investigating', 'notes': 'Verify the approved maintenance record and workload owner.'}
case.ai_analysis = 'Synthetic report test only. Evidence: ' + case.events[0].id + '\nUnknowns: maintenance approval not supplied.\nNext checks: confirm application owner.'
output = root / 'output/pdf'
output.mkdir(parents=True, exist_ok=True)
(output / 'synthetic-case-report.pdf').write_bytes(render_case_pdf(case))
print(output / 'synthetic-case-report.pdf')
