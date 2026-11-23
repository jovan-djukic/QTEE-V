# Verification results

Proverif 2.05. Cryptographic protocol verifier, by Bruno Blanchet, Vincent Cheval, and Marc Sylvestre

Model SHA-256: `6f530d2d69fd47fbacf37b2e63a57dc9e06f1b56fa17dbd61cf7917e7d2f1ce9`.

All 17 security results are proved under the model assumptions. The suite also
checks 18 reachability/rejection outcomes and two possession regressions.
See README.md for implementation-alignment requirements and trust assumptions.

## Security results

| Query | ProVerif result |
| --- | --- |
| `not attacker(secret_msg[])` | is true |
| `not attacker(secret_msg_reverse[])` | is true |
| `not attacker(qkd_k(R0,R1))` | is true |
| `not attacker(qkd_k(R1,R2))` | is true |
| `not attacker(qkd_k(R1,R0))` | is true |
| `not attacker(qkd_k(R2,R1))` | is true |
| `event(CtrlIssuedCert(rid_7,n_7,m,pb)) ==> event(CtrlGotAttest(rid_7,n_7,m))` | is true |
| `event(CtrlGotAttest(rid_7,n_7,m)) ==> event(CtrlGotRegister(rid_7))` | is true |
| `inj-event(CtrlIssuedCert(rid_7,n_7,m,pb)) ==> inj-event(CtrlGotAttest(rid_7,n_7,m))` | is true |
| `inj-event(CtrlGotAttest(rid_7,n_7,m)) ==> inj-event(RelaySignedReport(rid_7,n_7,m))` | is true |
| `event(RelayGotHop(m,f,t)) ==> event(HopSent(m,f,t))` | is true |
| `event(RelayGotHop(x,f,t)) ==> event(RelayLoadedCfg(t,n_7,f,r)) \|\| event(RelayLoadedCfg(t,n_7,l,f))` | is true |
| `event(RelaySentHop(x,f,t)) ==> event(RelayLoadedCfg(f,n_7,l,t)) \|\| event(RelayLoadedCfg(f,n_7,t,r))` | is true |
| `event(RelayLoadedCfg(rid_7,n_7,l,r)) ==> event(CtrlSentCfg(rid_7,n_7,l,r))` | is true |
| `event(RelayGotCert(rid_7,n_7,m,pb)) ==> event(CtrlIssuedCert(rid_7,n_7,m,pb))` | is true |
| `inj-event(HopPeerAuthenticated(f,t,ek_17,n_7)) ==> inj-event(HopSignedTranscript(f,t,ek_17,n_7))` | is true |
| `event(AppDelivered(m,f,t)) ==> event(HopSent(m,f,t))` | is true |

## Reachability and regression checks

A false non-reachability result is expected when an event should be reachable.

| Check | Required event outcome | Actual result |
| --- | --- | --- |
| issue_r0 | Reachable | is false |
| issue_r1 | Reachable | is false |
| issue_r2 | Reachable | is false |
| cert_r0 | Reachable | is false |
| cert_r1 | Reachable | is false |
| cert_r2 | Reachable | is false |
| submit_forward | Reachable | is false |
| submit_reverse | Reachable | is false |
| receive_forward_0 | Reachable | is false |
| receive_forward_1 | Reachable | is false |
| receive_forward_2 | Reachable | is false |
| receive_reverse_2 | Reachable | is false |
| receive_reverse_1 | Reachable | is false |
| receive_reverse_0 | Reachable | is false |
| deliver_forward | Reachable | is false |
| deliver_reverse | Reachable | is false |
| bad_image_signs | Reachable | is false |
| bad_image_rejected | Unreachable | is true |
| public_cert_replay_rejected | Unreachable | is true |
| possession_check_removed | Reachable | is false |

Reproduce from the QTEE-V directory:

```sh
python verification/run_verification.py --proverif /path/to/proverif --group all --timeout 120
```

## Device-binding variants (`--group variants`)

| Variant | Expected | Observed |
|---|---|---|
| `v1_per_device_binding` | all 17 security queries true | all 17 true |
| `v2_shared_root_key` | `secret_msg`, Q4, Q10, Q11 false; other 13 true | as expected: `not attacker(secret_msg[])`, Q4, Q10 and Q11 are false; `secret_msg_reverse` and the rest true |

Inputs, logs and `summary.json` are in `verification/variants/`. Reproduce with:

```sh
python verification/run_verification.py --proverif /path/to/proverif --group variants
```
