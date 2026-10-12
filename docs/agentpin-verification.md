# AgentPin credential verification

AgentSniff deliberately separates AgentPin discovery from identity verification.

- The network scanner treats `/.well-known/agent-identity.json` as self-asserted discovery evidence. It never calls an identity “verified” merely because a document has the expected fields.
- `agentsniff verify-agentpin` verifies a credential that was presented through an AgentPin transport binding or another trusted application flow.

## Verify a credential

Pass the credential on standard input when possible so the JWT is not exposed in shell history or the process list:

```bash
agentsniff verify-agentpin \
  --trust-bundle agentpin-trust-bundle.json \
  --audience verifier.example < credential.jwt
```

For file-oriented workflows:

```bash
agentsniff verify-agentpin \
  --credential-file credential.jwt \
  --trust-bundle agentpin-trust-bundle.json \
  --pin-store ~/.agentsniff/agentpin-pins.json \
  --audience verifier.example
```

The command emits a JSON verification report. Exit status `0` means every configured verification check succeeded. Exit status `2` means the credential was rejected. Invalid command input or unreadable files exit `1`.

## Serve verification over REST or MCP

`agentsniff serve` can expose the same verifier through
`POST /api/agentpin/verify` and the `verify_agentpin_credential` MCP tool at
`POST /mcp`. Configure the trust material on the server, not in a caller's
request:

```yaml
agentpin_trust_bundle_path: "/etc/agentsniff/agentpin-trust-bundle.json"
agentpin_pin_store_path: "~/.agentsniff/agentpin-pins.json"
agentpin_expected_audience: "verifier.example"
```

All three settings are operator-controlled. REST and MCP inputs contain only
the presented credential, so a credential presenter cannot nominate its own
key, revocation data, trust bundle, audience, or pin store. Successful calls
share one serialized read/verify/atomic-write pin transaction, preventing
concurrent first-use requests from overwriting newer continuity state.

The MCP endpoint supports stateless protocol revision `2026-07-28` and legacy
`2025-11-25` initialization. It is protected by the same API authentication as
the dashboard. Keep local deployments on loopback; remote deployments require
a strong API token and TLS termination.

## Trust bundle requirements

The bundle uses AgentPin's `agentpin_bundle_version: "0.1"` format. It must contain exactly one discovery document and one current revocation document for:

- the credential issuer; and
- every domain named in the credential's delegation chain.

Distribute the bundle through an authenticated out-of-band channel. A bundle chosen or modified by the credential presenter is not a trust anchor.

AgentSniff does not fetch discovery or revocation URLs while verifying a credential. This makes the source of trust explicit and prevents untrusted `iss` or delegation claims from triggering SSRF, redirects, or unbounded response downloads. Credential input is capped at 64 KiB; trust bundles and pin stores are capped at 4 MiB.

## Checks performed

The verifier fails closed unless all applicable checks pass:

- JWT type and ES256 algorithm;
- credential `iat`, `nbf`, `exp`, declared agent TTL, and the absolute 24-hour lifetime cap;
- canonical issuer domain, subject binding, discovery schema, selected P-256 key, and key expiry;
- active agent status, capability taxonomy and narrowing, and constraint narrowing;
- credential, agent, and key revocation;
- every delegation signature, role, domain, agent, capability scope, revocation state, and chain-depth limit;
- expected audience when `--audience` is supplied; and
- persistent TOFU key continuity for the issuer and all delegation domains.

Operational constraints such as rate limits, destination domains, source IP ranges, and valid hours still need enforcement by the gateway or application processing the verified credential. The verification report returns both `constraints` from the credential and `discovery_constraints` from the agent declaration; consumers must enforce both, with the more restrictive result winning.

## Key rotation and pin safety

On the first successful verification for a domain, AgentSniff pins the active keys already advertised in its trusted discovery document. This permits a pre-announced rotation key to take over without weakening continuity. A later, unannounced key change is rejected with `KEY_PIN_MISMATCH` until an operator approves the new trust state through an independent process.

Pins are updated only after the credential, revocation data, delegation chain, audience, and all other checks succeed. Invalid credentials therefore cannot poison future TOFU decisions. On Unix, the pin store is atomically replaced and created with owner-only permissions; Windows uses a staged replace because the standard rename operation cannot replace an existing file there.
