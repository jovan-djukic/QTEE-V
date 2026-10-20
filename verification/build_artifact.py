"""Package only the verified model, reproducible inputs, logs and documentation."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import zipfile

REPO=Path(__file__).resolve().parents[1]

def digest(data):
    return hashlib.sha256(data).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=REPO.parent/'QTEE-V-verification-artifact.zip')
    args=parser.parse_args()
    results=REPO/'verification'/'results'
    summary=json.loads((results/'summary.json').read_text(encoding='utf-8'))
    model=REPO/'protocol.pv'
    assert summary['model_sha256']==digest(model.read_bytes()),'Model changed since verification.'
    assert len(summary['runs'])==21 and all(r['passed'] for r in summary['runs']), 'Run the full suite first.'
    security=next(r for r in summary['runs'] if r['name']=='security')
    assert len(security['results'])==17
    report=[
        '# Verification results', '', summary['tool'], '',
        'Model SHA-256: `'+summary['model_sha256']+'`.', '',
        'All 17 security results are proved under the model assumptions. The suite also',
        'checks 18 reachability/rejection outcomes and two possession regressions.',
        'See README.md for implementation-alignment requirements and trust assumptions.', '',
        '## Security results', '', '| Query | ProVerif result |', '| --- | --- |',
    ]
    for row in security['results']:
        query=row['query'].replace('|','\\|')
        report.append('| `'+query+'` | '+row['result']+' |')
    report+=['','## Reachability and regression checks','',
             'A false non-reachability result is expected when an event should be reachable.', '',
             '| Check | Required event outcome | Actual result |', '| --- | --- | --- |']
    for run in summary['runs'][1:]:
        assert len(run['results'])==1
        required='Unreachable' if run['expected_unreachable'] else 'Reachable'
        report.append('| '+run['name']+' | '+required+' | '+run['results'][0]['result']+' |')
    report+=['','Reproduce from the QTEE-V directory:', '',
             '```sh','python verification/run_verification.py --proverif /path/to/proverif --group all --timeout 120','```','']
    (REPO/'verification'/'RESULTS.md').write_text('\n'.join(report),encoding='utf-8')
    include=[model,REPO/'verification'/'README.md',REPO/'verification'/'RESULTS.md',
             REPO/'verification'/'run_verification.py',REPO/'verification'/'build_artifact.py',
             results/'summary.json']
    for run in summary['runs']:
        pv=results/run['input']
        assert digest(pv.read_bytes())==run['input_sha256'],pv
        include.extend([pv,results/run['log']])
    for name in ['protocol_original.pv','protocol_reachability.pv',
                 'proverif_original.log','proverif_reachability.log']:
        include.append(REPO/'verification'/'baseline'/name)
    baseline=(REPO/'verification'/'baseline'/'protocol_original.pv').read_text(encoding='utf-8')
    patch=''.join(difflib.unified_diff(baseline.splitlines(True),model.read_text(encoding='utf-8').splitlines(True),
                                     fromfile='baseline/protocol_original.pv',tofile='protocol.pv'))
    payload={('QTEE-V/'+p.relative_to(REPO).as_posix()):p.read_bytes() for p in include}
    payload['QTEE-V/verification/model_changes.diff']=patch.encode('utf-8')
    manifest={'tool':summary['tool'],'model_sha256':summary['model_sha256'],
              'counts':{'security_queries':17,'reachability_rejection_queries':18,'possession_regressions':2},
              'files':{name:digest(data) for name,data in sorted(payload.items())}}
    payload['manifest.json']=(json.dumps(manifest,indent=2)+'\n').encode('utf-8')
    with zipfile.ZipFile(args.output,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,data in sorted(payload.items()):archive.writestr(name,data)
    with zipfile.ZipFile(args.output) as archive:
        assert archive.testzip() is None
        assert all(digest(archive.read(n))==h for n,h in manifest['files'].items())
    print('Created '+str(args.output.name)+f' ({args.output.stat().st_size:,} bytes, {len(payload)} entries).')

if __name__=='__main__':
    main()
