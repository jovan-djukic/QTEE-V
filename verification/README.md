# QTEE-V verification artifact

The current entry point is [`../protocol.pv`](../protocol.pv). The baseline is
[`baseline/protocol_original.pv`](baseline/protocol_original.pv); its prior results
are retained to document the unreachable forwarding path in that version.

## Reproduce

Use Python 3.9 or newer and ProVerif 2.05. Python has no third-party dependencies.
Install or extract ProVerif from its [official distribution](https://bblanche.gitlabpages.inria.fr/proverif/).

From the QTEE-V directory:

```sh
python verification/run_verification.py --proverif /path/to/proverif --group all --timeout 120
```

The runner records the tool version, exact model hash, generated inputs, full logs,
elapsed times, timeouts and result strings in `results/summary.json` and sibling
files. A timeout or `cannot be proved` result fails the expected-result check.

The groups can also be run individually with `--group security`,
`--group reachability`, or `--group regression`. Separate runs overwrite the
summary with that run's selected group; use `--group all` for the complete artifact.

## Changes to the baseline

- Topology lookup now has one common certificate-issuance continuation for all
  three relays. Node identities are public constants so the lookup reductions are
  well-defined.
- The controller's certificate/key are generated once, matching its persistent
  runtime identity. Setup inputs retain public-network adversary control.
- Setup and hop records have distinct tags. Public CA and hardware verification
  keys are published. Reference measurements are public, one per relay ID
  (`meas(rid)`), as the implementation compiles the ID into each enclave image.
- Signatures have a `getmess` reduction: signatures do not confer confidentiality.
- A symbolic client-possession exchange signs a transcript containing sender,
  destination, encrypted key transport and fresh receiver challenge. The symmetric
  channel key is not exposed by the signature.
- Receiver acceptance occurs before selecting an outgoing certificate; peer
  topology checks precede the receiver's challenge. Outgoing identity is checked
  before initiating the next connection.
- `HopSent` records message origin for both applications and relays. Relay-only
  `RelaySentHop` records forwarding. All send events precede their data outputs.
- Attestation nonce/measurement are included in certificate events. Configuration
  events agree on relay, nonce and both neighbors. This records session agreement;
  the actual report still does **not** sign the later-generated relay public key.
- Both applications have sources and sinks. Both directions have concrete secret
  payloads and end-to-end delivery reachability checks.
- Additional device-image processes sign unexpected measurements under the same
  ideal hardware key. They reach report generation but not controller acceptance.
- The setup nonce input has ProVerif's `[precise]` annotation. This eliminates a
  Horn-clause approximation that mixes several nonce inputs for one setup
  execution. It does not assume a security property or remove real executions.
  No user axioms, weakened queries, private network, bounded replication or
  disabled active attacker are used to obtain the security results.

## Query inventory

The integrated model has **17 security queries**: two payload secrecy queries,
four directional hop-key consistency queries, and eleven correspondences.

| Query | Meaning |
| --- | --- |
| Payloads | Forward and reverse application secrets remain undisclosed. |
| Hop keys | Four private ordered-pair terms remain undisclosed under the assumed key source. |
| Q1 | Certificate issuance follows accepted attestation with the same identity, nonce and measurement. |
| Q2 | Attestation acceptance follows registration. This is a local ordering invariant. |
| Q3 | Certificate issuance injectively corresponds to the accepted attestation session. |
| Q4 | Accepted evidence has a distinct matching hardware report-generation event. |
| Q5 | Each relay acceptance has a preceding same-payload, same-edge origin event. |
| Q6 | Relay receive identities match a loaded neighbor. |
| Q7 | Relay forwarding destinations match a loaded neighbor. |
| Q8 | Loaded configuration originated with the controller in that setup session. |
| Q9 | Accepted relay credentials match controller issuance in the same setup session. |
| Q10 | Hop peer authentication has a distinct matching transcript-signing event. |
| Q11 | Application delivery has a preceding same-edge origin event. |

The runner also checks **18 reachability/rejection queries**: issuance and
certificate receipt for every relay; submission in both directions; all six relay
receptions; both destination deliveries; unexpected-image report generation; and
unreachability of accepted unexpected measurements.

For a standalone event query, `not event(...) is false` is the expected successful
reachability result. It supplies an execution trace; it is not a failed security
property. `not event(...) is true` is expected for rejected unexpected measurements.

Two focused post-setup regressions exercise public-certificate impersonation.
The attacker has public certificate fields, its own unrelated signing key, and
chooses a known channel key and payload. The chosen acceptance event is unreachable
with the possession check, and reachable when that one verification check is
removed. The mutated copy is generated only under `results/`; it is not the model
entry point. Honest-path reachability is independently checked on the integrated,
replicated model.

## Assumptions and implementation correspondence

This is a symbolic verification of the modeled protocol, not a proof of the C,
Python, Keystone, WolfSSL, QKD hardware, or complete TLS 1.3 implementations.

The possession exchange is an abstraction of TLS authentication and transcript
binding. Its extra messages are not an application-protocol change to deploy in
the runtime. Record sequence counters and full TLS negotiation are not modeled;
message-origin correspondences are non-injective and do not promise exactly-once
delivery.

The model requires exact intended controller and destination identities, in
addition to CA checks. The runtime now enforces them: `relay.py` and `relay.c`
require the controller certificate's CN to be `QKD Relay Controller`, and refuse
to forward unless the next hop's certificate CN is the configured neighbour in
that direction; incoming peers are restricted by the neighbour whitelist. The test
client enforces its neighbour with `--expect-peer` (APP_L: R0, APP_R: R2). Tests 7
and 8 of `demo/run_demo.py` exercise the outgoing checks against impostors holding
genuine CA-signed certificates for other identities. The model repair itself
changes no runtime code.

Private QKD-key provisioning, hardware-key isolation and the CA remain trust
assumptions. A private key-source query cannot validate an unmodeled KME channel.
Unexpected-image behavior is limited to ideal attestation report generation; it
does not cover hardware compromise, side channels, rollback, invasive attacks or
compromised approved code. Quantum resistance remains a computational assumption
about the deployed algorithms.

## Availability

The model, runner, baseline and exact results are packaged in the accompanying
`QTEE-V-verification-artifact.zip`. This is a local deliverable. The revised files
have not been pushed to a public repository or assigned an archival DOI. Publish
that exact artifact and add its permanent link before a manuscript submission.
