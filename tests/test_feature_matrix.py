import importlib.util
from pathlib import Path


def test_every_feature_has_three_case_definitions_with_real_references():
    path=Path(__file__).resolve().parents[1]/'scripts/feature_test_report.py'
    spec=importlib.util.spec_from_file_location('feature_test_report',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    rows=module.cases();module.validate(rows)
    assert len({row['feature_id'] for row in rows})==143
    assert len(rows)==429
