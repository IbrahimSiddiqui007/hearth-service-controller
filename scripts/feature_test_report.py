"""Publish all feature scenarios and map real test evidence without fake passes."""
import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
from feature_cases import cases


def validate(rows):
    if len(rows)!=429 or len({row['id'] for row in rows})!=429:
        raise ValueError('Every one of143 features needs distinct valid/invalid/edge cases')
    for feature in {row['feature_id'] for row in rows}:
        if {row['kind'] for row in rows if row['feature_id']==feature}!={'valid','invalid','edge'}:
            raise ValueError('Incomplete feature case triplet: '+feature)
    for row in rows:
        ref=row['test']
        if ref and ref.startswith('tests/'):
            source,name=ref.split('::',1)
            definitions={node.name for node in ast.walk(ast.parse((ROOT/source).read_text(encoding='utf-8'))) if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
            if name.split('[')[0] not in definitions:
                raise ValueError('Missing behavioral test reference: '+ref)


def evidence(args):
    results={}
    if args.junit:
        for case in ET.parse(args.junit).getroot().iter('testcase'):
            module=case.get('classname','').replace('.','/')+'.py'
            if not module.startswith('tests/'):
                module='tests/'+module
            ref=module+'::'+case.get('name','')
            value='failed' if case.find('failure') is not None or case.find('error') is not None else 'skipped' if case.find('skipped') is not None else 'passed'
            results[ref]=value
    for filename in (args.node,args.browser):
        if filename:
            results.update(json.loads(Path(filename).read_text(encoding='utf-8')))
    return results


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--junit');parser.add_argument('--node');parser.add_argument('--browser')
    parser.add_argument('--require-implemented-pass',action='store_true')
    args=parser.parse_args()
    rows=cases();validate(rows);results=evidence(args)
    for row in rows:
        ref=row['test']
        if ref is None:
            row['evidence']='planned; feature not implemented'
        elif ref in results:
            row['evidence']=results[ref]
        elif ref.startswith('tests/'):
            matches=[value for key,value in results.items() if key.startswith(ref+'[')]
            row['evidence']='passed' if matches and all(value=='passed' for value in matches) else 'failed' if 'failed' in matches else 'skipped' if 'skipped' in matches else 'not run'
        else:
            row['evidence']='not run'
    counts=Counter(row['evidence'] for row in rows)
    output={'features':143,'cases':429,'counts':dict(counts),'cases_detail':rows,
            'note':'Scenarios trace to behavioral assertions. Shared integration tests can exercise several scenarios;429 is not the pytest test count. Deferred native verification is independent of mocked/source pass results.'}
    (ROOT/'docs/feature-test-matrix.json').write_text(json.dumps(output,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=['# Complete feature test matrix','',
           '143 features · 429 named cases: valid, invalid and null/edge for every feature. All original 140 entries plus 3 additions are retained.',
           '', 'Cases trace to existing/new behavioral tests and browser evidence. Shared integration tests can exercise several scenarios; this does not mean 429 distinct pytest tests ran. Planned features are not marked passing. Native verification for the six owner-deferred rows remains separate from source/mock evidence.',
           '', '| Case | Feature | Scenario / expected behavior | Behavioral test | Evidence |','| --- | --- | --- | --- | --- |']
    for row in rows:
        cells=[row['id'],row['feature'],row['scenario'],row['test'] or 'Planned; no engine yet',row['evidence']]
        lines.append('| '+' | '.join(str(cell).replace('|','\\|').replace('\n',' ') for cell in cells)+' |')
    (ROOT/'docs/FEATURE-TEST-MATRIX.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    features=[]
    for row in rows[::3]:
        features.append({key:row[key] for key in ('feature_id','feature','description','implementation','target_verification')})
    (ROOT/'docs/feature-list.json').write_text(json.dumps(features,ensure_ascii=False,indent=2),encoding='utf-8')
    catalog=['# Every feature','', 'Complete 143-entry list; original descriptions and requested additions are preserved. See FEATURE-STATUS.md for coverage and FEATURE-TEST-MATRIX.md for the three cases per feature.','', '| ID | Feature | Description | Implementation | Target evidence |','| --- | --- | --- | --- | --- |']
    catalog+=['| '+' | '.join(str(row[key]).replace('|','\\|').replace('\n',' ') for key in ('feature_id','feature','description','implementation','target_verification'))+' |' for row in features]
    (ROOT/'docs/FEATURE-LIST.md').write_text('\n'.join(catalog)+'\n',encoding='utf-8')
    print(json.dumps({'features':143,'cases':429,'evidence':dict(counts)}))
    if args.require_implemented_pass and any(row['test'] and row['evidence']!='passed' for row in rows):
        raise SystemExit('Implemented feature evidence is incomplete; inspect the matrix before claiming coverage')


if __name__=='__main__':main()
