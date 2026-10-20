"""Run ProVerif with bounded wall time and preserve exact inputs/results.

No third-party Python packages are needed. Timeouts are recorded as timeouts,
never as successful verification. Security and reachability are separate groups.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]
BEGIN = '(* BEGIN SECURITY QUERIES *)'
END = '(* END SECURITY QUERIES *)'

REACHABILITY = [
    ('issue_r0', 'query pb: bitstring, n: bitstring, m: bitstring; event(CtrlIssuedCert(R0, n, m, pb)).', False),
    ('issue_r1', 'query pb: bitstring, n: bitstring, m: bitstring; event(CtrlIssuedCert(R1, n, m, pb)).', False),
    ('issue_r2', 'query pb: bitstring, n: bitstring, m: bitstring; event(CtrlIssuedCert(R2, n, m, pb)).', False),
    ('cert_r0', 'query pb: bitstring, n: bitstring, m: bitstring; event(RelayGotCert(R0, n, m, pb)).', False),
    ('cert_r1', 'query pb: bitstring, n: bitstring, m: bitstring; event(RelayGotCert(R1, n, m, pb)).', False),
    ('cert_r2', 'query pb: bitstring, n: bitstring, m: bitstring; event(RelayGotCert(R2, n, m, pb)).', False),
    ('submit_forward', 'query event(AppSubmitted(secret_msg, APP_L, R0)).', False),
    ('submit_reverse', 'query event(AppSubmitted(secret_msg_reverse, APP_R, R2)).', False),
    ('receive_forward_0', 'query event(RelayGotHop(secret_msg, APP_L, R0)).', False),
    ('receive_forward_1', 'query event(RelayGotHop(secret_msg, R0, R1)).', False),
    ('receive_forward_2', 'query event(RelayGotHop(secret_msg, R1, R2)).', False),
    ('receive_reverse_2', 'query event(RelayGotHop(secret_msg_reverse, APP_R, R2)).', False),
    ('receive_reverse_1', 'query event(RelayGotHop(secret_msg_reverse, R2, R1)).', False),
    ('receive_reverse_0', 'query event(RelayGotHop(secret_msg_reverse, R1, R0)).', False),
    ('deliver_forward', 'query event(AppDelivered(secret_msg, R2, APP_R)).', False),
    ('deliver_reverse', 'query event(AppDelivered(secret_msg_reverse, R0, APP_L)).', False),
    ('bad_image_signs', 'query n: bitstring; event(RelaySignedReport(R1, n, bad_meas(R1))).', False),
    ('bad_image_rejected', 'query rid: bitstring, n: bitstring; event(CtrlGotAttest(rid, n, bad_meas(rid))).', True),
]

def possession_regressions(source):
    """A concrete attacker has public certificates and its own signing key.

    The same chosen-payload event must be unreachable with possession checked
    and reachable when that one check is removed. End-to-end honest-path
    reachability is established separately on the full replicated model.
    """
    start=source.index(BEGIN)
    finish=source.index(END)+len(END)
    query='query event(RelayGotHop(tag_reg, APP_L, R0)).\n'
    prefix=source[:start]+query+source[finish:source.rindex('\nprocess\n')]
    attacker='''
let PublicCertImpersonator(app_cert: bitstring, server_cert: bitstring) =
    let pkb(server_pk: pkey) = cert_getpk(server_cert) in
    let wrapped = aenc(tag_authed, server_pk) in
    out(net, (app_cert, wrapped));
    in(net, challenge_m: bitstring);
    let (=tag_hop_challenge, =APP_L, =R0, challenge: bitstring) =
        sdec(challenge_m, tag_authed) in
    new attacker_sk: skey;
    out(net, sign((tag_hop_proof, APP_L, R0, wrapped, challenge), attacker_sk));
    out(net, senc((tag_hop_data, tag_reg, APP_L, R0), tag_authed)).

process
    new ca_sk: skey;
    let ca_pkb = pkb(pk(ca_sk)) in
    new relay_sk: skey;
    new app_sk: skey;
    let relay_cert = cert_make(R0, pkb(pk(relay_sk)), ca_sk) in
    let app_cert = cert_make(APP_L, pkb(pk(app_sk)), ca_sk) in
    out(net, ca_pkb);
    out(net, relay_cert);
    out(net, app_cert);
    event RelayLoadedCfg(R0, tag_nonce, APP_L, R1);
    (
        RelayHop(R0, APP_L, R1, relay_sk, relay_cert, ca_pkb)
      | PublicCertImpersonator(app_cert, relay_cert)
    )
'''
    checked=prefix+attacker
    needle='    if verify(proof_rx, transcript, peer_pk) = ok() then'
    a=checked.index('let RelayHop(')
    b=checked.index('let RelaySetup(',a)
    assert checked[a:b].count(needle)==1
    mutated=checked[:a]+checked[a:b].replace(needle,'    (* MUTATION: possession verification omitted. *)')+checked[b:]
    return [('public_cert_replay_rejected',checked,True),
            ('possession_check_removed',mutated,False)]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proverif', default=shutil.which('proverif'))
    parser.add_argument('--model', type=Path, default=REPO/'protocol.pv')
    parser.add_argument('--group', choices=['security','reachability','regression','all'], default='all')
    parser.add_argument('--case', action='append', help='Run named reachability cases only.')
    parser.add_argument('--timeout', type=int, default=120, help='Seconds per invocation.')
    parser.add_argument('--output', type=Path, default=REPO/'verification'/'results')
    args=parser.parse_args()
    if args.timeout<=0:
        parser.error('--timeout must be positive.')
    if args.case and args.group not in ('reachability','all'):
        parser.error('--case selects reachability checks; choose --group reachability or all.')
    if not args.proverif:
        parser.error('Set --proverif to the installed/portable ProVerif executable.')
    exe=Path(args.proverif).resolve()
    model=args.model.resolve()
    source=model.read_text(encoding='utf-8')
    assert source.count(BEGIN)==source.count(END)==1
    start=source.index(BEGIN)
    finish=source.index(END)+len(END)
    args.output.mkdir(parents=True,exist_ok=True)
    jobs=[]
    if args.group in ('security','all') and not args.case:
        jobs.append(('security', source, None))
    if args.group in ('reachability','all'):
        cases=[c for c in REACHABILITY if not args.case or c[0] in args.case]
        if args.case and set(args.case)-{c[0] for c in cases}:
            parser.error('Unknown case name.')
        for name,query,expected in cases:
            jobs.append((name,source[:start]+query+'\n'+source[finish:],expected))
    if args.group in ('regression','all') and not args.case:
        jobs.extend(possession_regressions(source))
    version=subprocess.run([str(exe),'-help'],capture_output=True,text=True,check=True).stdout.splitlines()[0]
    model_label=str(model.relative_to(REPO)) if model.is_relative_to(REPO) else model.name
    summary={'tool':version,'model':model_label,'model_sha256':hashlib.sha256(model.read_bytes()).hexdigest(),
             'command_options':{'group':args.group,'cases':args.case,'timeout_seconds':args.timeout},'runs':[]}
    failed=False
    for name,text,expected in jobs:
        pv=args.output/(name+'.pv')
        log=args.output/(name+'.log')
        pv.write_text(text,encoding='utf-8')
        print('Running '+name+' ...',flush=True)
        began=time.monotonic()
        timeout=False
        with log.open('wb') as stream:
            try:
                completed=subprocess.run([str(exe),str(pv.resolve())],stdout=stream,stderr=subprocess.STDOUT,
                                         timeout=args.timeout,check=False)
                code=completed.returncode
            except subprocess.TimeoutExpired:
                timeout=True
                code=None
        output=log.read_text(encoding='utf-8',errors='replace')
        results=re.findall(r'^RESULT (.*?) (is true|is false|cannot be proved)\.$',output,re.M)
        ok=not timeout and code==0 and bool(results)
        if expected is None:
            declared=len(re.findall(r'^query\b',text[start:finish],re.M))
            ok=ok and len(results)==declared and all(r[1]=='is true' for r in results)
        else:
            ok=ok and len(results)==1 and results[0][1]==('is true' if expected else 'is false')
        row={'name':name,'passed':ok,'timeout':timeout,'exit_code':code,
             'seconds':round(time.monotonic()-began,3),'expected_unreachable':expected,
             'results':[{'query':q,'result':r} for q,r in results],
             'input':pv.name,'input_sha256':hashlib.sha256(pv.read_bytes()).hexdigest(),'log':log.name}
        summary['runs'].append(row)
        (args.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
        status='PASS' if ok else ('TIMEOUT' if timeout else 'REVIEW')
        print(f'{name}: {status} ({row["seconds"]} s; {len(results)} result(s))',flush=True)
        failed=failed or not ok
    return 1 if failed else 0

if __name__=='__main__':
    sys.exit(main())
