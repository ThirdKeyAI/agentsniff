# Agent Gate

`agentsniff gate` decides, per inbound request, whether a client is an AI agent and whether to let it through. It runs beside your reverse proxy as a forward-auth endpoint: the proxy asks `/check` before serving each request, and the gate answers allow, challenge, or block.

The scanner looks outward from your network for agent infrastructure. The gate looks at clients coming in. Both use the same split between *presence* (what a client says it is) and *identity* (what a signature proves it is).

Typical use: a bank or fintech that must keep personal AI agents such as Meta Muse and xAI Grok out of authenticated pages, and must stop rapid automated traffic, without blocking customers.

## Quick start

```bash
agentsniff gate                     # monitor mode on 127.0.0.1:9091
agentsniff gate --enforce           # start answering 401/403
agentsniff gate --config agentsniff.yaml --decision-log /var/log/agentsniff/gate.jsonl
```

The gate starts in **monitor** mode: it logs what it would do and always answers allow. Run it that way first, read the decision log, tune, then switch to `--enforce` or `gate.mode: enforce`.

The gate refuses to start unless the signed `agent_clients` and `tls_fingerprints` datasets verify against the packaged `signing_key.pub`.

## How a decision is made

1. **Rate.** Every client has a burst counter (20 requests per second) and a sustained counter (300 per minute). A client is an IPv4 address or an IPv6 `/64` (`rate.ipv6_prefix`), since one host routinely holds a whole `/64`. Exceeding either limit applies `gate.rate.action` (default block) and holds the client in a penalty box for `penalty_secs` (default 300). This applies to every client, verified agents included, and can only make an outcome stricter. If the client address resolves to one of your `trusted_proxies`, the proxy did not forward it; the gate then skips rate limits for that request instead of putting every customer in one bucket, logs a warning, and counts it in `/stats` as `unresolved_client_ip`.
2. **Tripwires.** A request for a path in `gate.tripwires` (URLs you plant where only machines read; see [Tripwires](#tripwires)) gets the tripwire action (default block) and its client is held in the penalty box for `tripwires.penalty_secs` (default 3600). Like rate, this applies to every client and can only make an outcome stricter.
3. **Web Bot Auth.** A request tagged `web-bot-auth` whose RFC 9421 signature verifies against an operator-pinned Ed25519 key is attributed with `trusted_verified` assurance. A `web-bot-auth` signature that does not verify, or a `Signature-Agent` header with no signature, is still a self-declaration that the client is an agent. HTTP signatures without the `web-bot-auth` tag, such as PSD2 or other API request signing, are ignored.
4. **Self-declared agents.** User-agent tokens and `Signature-Agent` origins from the catalog (for example `muse-`, `meta-webindexer`, `GrokAgent`, `ChatGPT-User`) attribute the request with `self_declared` assurance. A claim that names no catalog agent is attributed to `unidentified_signed_agent`.
5. **Behavior.** Every request without a verified signature is scored from the signals below, combined with noisy-OR. Naming an agent does not switch these checks off.
6. **Decision.** A verified agent gets its policy: allow if it is in `allow_verified_agents`, else `agent_actions[id]`, `kind_actions[kind]`, or `default_agent_action` (block). A claimed agent gets the stricter of that policy and its behavior score, so a claim can never soften an outcome. An unattributed request is challenged at `challenge_threshold` (0.5) and blocked at `block_threshold` (0.8).

| Signal | Weight | Fires when |
|---|---:|---|
| `browser_ua_without_browser_headers` | 0.50 | A browser user agent sends neither `Accept-Language` nor `Sec-Fetch-*` |
| `missing_accept_language` | 0.25 | A browser user agent sends `Sec-Fetch-*` but no `Accept-Language` |
| `missing_user_agent` | 0.50 | No `User-Agent` |
| `automation_client` | 0.50 | `python-requests`, `Go-http-client`, `curl/`, `HeadlessChrome`, and similar |
| `stale_browser_version` | 0.25 / 0.40 | Chrome at least 6 (or 12) majors behind the catalog's stable baseline |
| `hosting_network` | 0.35 / 0.25 | Origin ASN is a cloud, VPN, or proxy host (browser UA / other UA) |
| `agent_operator_network` | 0.60 | A browser user agent from the network an agent runs on, such as Meta's AS32934; attributes the agent as `suspected` |
| `cdn_egress_browser` | 0.50 | Chrome on desktop Linux from a CDN egress network (Cloudflare, Fastly): the exit the ChatGPT cloud browser, Muse, and Grok Bot use. Challenges alone, never blocks alone |
| `tls_user_agent_mismatch` | 0.50 | Claims a browser, but the JA4 matches an HTTP library |
| `tls_client_library` | 0.30 | JA4 matches an HTTP library |
| `tripwire_hit` | 1.00 | The path is in `gate.tripwires`; the client is held in the penalty box |

The ASN and JA4 signals need your edge to supply those values (see [Edge headers](#edge-headers)). The header and browser-version checks apply only to user agents that claim to be a browser. Other user agents get the automation-token, network, and TLS checks only.

### What this catches, and what it does not

- **Self-identifying agents and crawlers** are matched by name and blocked by default.
- **ChatGPT cloud browser (dots)** presents stock Chrome on Linux with no token and signs requests with Web Bot Auth as `https://chatgpt.com`. A verified signature attributes it as `openai_chatgpt_cloud_browser` and your policy decides; pin the key only if you want every ChatGPT cloud-browser session, dots included, admitted. Unsigned, it is challenged by `cdn_egress_browser` when your edge supplies the ASN. A dot working through the user's own computer is that person's browser and passes.
- **Meta Muse** in browser mode has the same profile: a cloud Chromium presenting Chrome on Linux with no token, exiting from Cloudflare and Fastly addresses and almost never from Meta's AS32934. It is challenged by `cdn_egress_browser` (with an ASN header), blocked when it sends the reported `muse-` or `Meta-ExternalTest` tokens, and rate-limited when it moves faster than a person. Its text-only fetches arrive as `meta-webindexer` and are blocked by name. Meta signs a small, growing share of requests with Web Bot Auth but publishes no `Signature-Agent` origin, so nothing can be pinned yet.
- **Grok** is two clients. The chat fetcher spoofs iPhone Safari, macOS Chrome, or Go-http-client from rotating datacenter and proxy IPs and usually carries several weak signals at once; how far it gets depends on how many fire. A Chrome 139 user agent with no browser headers from M247 scores 0.805 and is blocked. The same request with Chrome 150 scores 0.756, and without an ASN header 0.70; both are challenged. Bursty timing adds a rate block on top. Grok Bot, the agent, is blocked by name when it sends `GrokAgent` or signs as `https://cursorusercontent.com`; when it does neither and drives a headful browser through the user's own connection, it is the real-browser case below.
- **Non-browser clients with an unlisted user agent** (a custom string such as `Go` or `x`) get only network and TLS signals. From a residential address they pass; from a hosting network they score 0.25.
- **An agent in a real browser, on a residential proxy, at human pace** will pass. No request-level gate stops that alone. Pair the gate with controls at login and transaction time, such as device binding and step-up authentication.

User-agent tokens and `Signature-Agent` origins are self-asserted. An `allow` in `agent_actions` or `kind_actions` (for example `kind_actions: {crawler: allow}`) can be claimed by any client that sends that name; such clients are still scored, but a plain spoof from a clean network passes. Use `allow_verified_agents` to admit agents by identity.

## Proxy configuration

Every integration follows the same contract: 2xx allows, the challenge status (default 401) and block status (default 403) deny. The gate reads the original request from `X-Forwarded-Method`, `X-Forwarded-Uri`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-For` (or `X-Original-Method` / `X-Original-URI`). It honors these only from `trusted_proxies` (default loopback). The `X-Forwarded-*` names win over `X-Original-*`, so always *set* every header you rely on at the proxy; a header you leave unset passes through whatever the client sent.

The client address must be the one your proxy saw. The gate walks `X-Forwarded-For` from the right, skipping `trusted_proxies`, and accepts `ip`, `ip:port`, and `[ipv6]:port` entries. A proxy that forwards a client-supplied `X-Forwarded-For` without appending the real peer lets every client pick its own address and escape rate limits.

If the gate is unreachable, these configurations fail closed. To fail open instead, use your proxy's equivalent of Envoy's `failure_mode_allow`.

### nginx

```nginx
location / {
    auth_request /_agentsniff;
    auth_request_set $as_decision $upstream_http_x_agentsniff_decision;
    auth_request_set $as_agent    $upstream_http_x_agentsniff_agent;
    # To your application, not to the client:
    proxy_set_header X-AgentSniff-Decision $as_decision;
    proxy_set_header X-AgentSniff-Agent    $as_agent;
    error_page 401 = @agent_challenge;

    proxy_pass http://app_backend;   # not `return`: it runs before auth_request
}

location @agent_challenge {
    # Send challenged clients to your CAPTCHA or step-up flow.
    return 302 /verify-human?next=$request_uri;
}

location = /_agentsniff {
    internal;
    proxy_pass http://127.0.0.1:9091/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-For    $remote_addr;
    proxy_set_header X-Forwarded-Method $request_method;
    proxy_set_header X-Forwarded-Uri    $request_uri;
    proxy_set_header X-Forwarded-Host   $host;
    proxy_set_header X-Forwarded-Proto  $scheme;
    proxy_set_header X-AgentSniff-Gate-Token "<token>";   # omit if the gate runs tokenless on loopback
    # proxy_set_header X-ASN $geoip2_asn;   # if you run the geoip2 module
}
```

nginx's `return` directive runs in the rewrite phase, before `auth_request`, so a location that answers with `return` is never checked. Put `auth_request` only on the locations you want gated, such as login, accounts, and transfers.

`auth_request` understands only 401 and 403 as denials and turns any other status into a 500. Keep `challenge_status` and `block_status` at 401 and 403 with nginx; the other proxies accept any 4xx.

### Caddy

```caddy
bank.example {
    forward_auth 127.0.0.1:9091 {
        uri /check
        header_up X-AgentSniff-Gate-Token {env.AGENTSNIFF_GATE_TOKEN}
        copy_headers X-AgentSniff-Decision X-AgentSniff-Agent
    }
    reverse_proxy app:8080
}
```

### Traefik

```yaml
http:
  middlewares:
    agentsniff-token:
      headers:
        customRequestHeaders:
          X-AgentSniff-Gate-Token: "<token>"
    agentsniff-gate:
      forwardAuth:
        address: http://agentsniff:9091/check
        trustForwardHeader: false     # the default; Traefik sets X-Forwarded-For itself
        authResponseHeaders: [X-AgentSniff-Decision, X-AgentSniff-Agent]
  routers:
    bank:
      rule: Host(`bank.example`)
      middlewares: [agentsniff-token, agentsniff-gate]
      service: app
```

With Traefik, add Traefik's address to `gate.trusted_proxies`. Traefik and Caddy copy the listed headers to the upstream request on allow; on a denial they return the gate's own response to the client.

### Envoy

Envoy must append the real peer address to `X-Forwarded-For`. Its default (`use_remote_address: false`) passes the client's header through untouched, which lets clients choose their own address, and collapses clients that send none onto Envoy's address. Set this on the HTTP connection manager:

```yaml
use_remote_address: true
xff_num_trusted_hops: 0   # raise only for load balancers in front of Envoy
```

```yaml
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    failure_mode_allow: false
    http_service:
      server_uri: { uri: http://127.0.0.1:9091, cluster: agentsniff_gate, timeout: 0.25s }
      path_prefix: /check
      authorization_request:
        allowed_headers:
          patterns:
          - exact: user-agent
          - exact: accept-language
          - prefix: sec-fetch-
          - prefix: signature
          - exact: x-forwarded-for
          - exact: x-forwarded-proto
        headers_to_add:
        - key: x-agentsniff-gate-token
          value: "<token>"
```

Envoy appends the original path to `/check` (a request for `/` arrives as `/check/`); the gate strips the prefix.

### Apache httpd

Apache httpd has no equivalent of `auth_request` or `forward_auth`. The
bundled `mod_authnz_fcgi` speaks FastCGI rather than HTTP, and
`mod_authnz_external` forces Basic authentication, so neither fits a gate that
answers allow, challenge or block per request. Run one of the four proxies
above in front of Apache and point its forward-auth at the gate; Apache stays
the origin.

## Edge headers

Two optional signals depend on data only the edge has.

- **ASN** (`gate.asn_header`, default `x-asn`): the client's origin autonomous system number, with or without an `AS` prefix. With nginx, use the geoip2 module and a GeoLite2-ASN database. On Cloudflare, a request-header transform rule can set it from `ip.src.asnum`.
- **JA4** (`gate.ja4_header`, default `x-ja4`): the client's JA4 TLS fingerprint, from a JA4-capable TLS terminator or your CDN's bot-management fields.
- **CloudFront**: an origin request policy that forwards `CloudFront-Viewer-ASN` and `CloudFront-Viewer-JA4-Fingerprint` gives the gate both; set `gate.asn_header: cloudfront-viewer-asn` and `gate.ja4_header: cloudfront-viewer-ja4-fingerprint`. The managed origin request policies do not forward the fingerprint headers, so create a custom one. Trust these only when the origin accepts traffic from CloudFront alone (an origin custom header secret checked at the origin, or a VPC origin); a client that can reach the origin directly can set them.

Without them the gate still runs; it just has fewer signals.

## Admitting verified agents (Web Bot Auth)

Some agents sign requests with [Web Bot Auth](https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/) (RFC 9421 HTTP Message Signatures). The gate verifies Ed25519 signatures against keys **you pin**. It never fetches the key directory named in `Signature-Agent`: a client-chosen URL on the request path would be an SSRF and latency problem.

Fetch an agent's directory yourself, check it, and pin the key:

```bash
curl -s https://chatgpt.com/.well-known/http-message-signatures-directory | jq '.keys'
```

```yaml
gate:
  allow_verified_agents: [openai_chatgpt_cloud_browser]
  web_bot_auth:
    trusted_keys:
      - agent_id: openai_chatgpt_cloud_browser
        signature_agent: "https://chatgpt.com"
        jwk: { kty: OKP, crv: Ed25519, x: "<base64url public key>" }
        # keyid defaults to the RFC 7638 JWK thumbprint, which Web Bot Auth requires
```

This key signs for every ChatGPT cloud-browser session, dots included, so pinning it admits ChatGPT browsing in general, not one agent. Grok Bot's directory is on `cursorusercontent.com`, the cloud computers it runs on; Muse has no published directory.

Verification requires:

- the `web-bot-auth` tag and a pinned `keyid`;
- `created` and `expires` within `clock_skew_secs` (default 60) of now, and no more than `max_lifetime_secs` apart (default 1 hour; the draft allows up to 24 hours, so raise it if an agent you admit signs longer and the decision log shows `lifetime_too_long`);
- coverage of `@authority` (or `@target-uri`), and of `Signature-Agent` when the header is present;
- a nonce not seen before (`require_nonce`, default true). Without a nonce a captured request replays until it expires.

The nonce cache lives in one gate process. With several gate instances, a captured request can be replayed once per instance within its lifetime, so keep the lifetime short. Set `web_bot_auth.authorities` to the hosts you serve (for example `["bank.example"]`) so a signature made for another site cannot verify here even if a proxy forwards a client-supplied `Host`. Re-pin when the agent rotates keys.

For `"signature-agent";key="..."` the gate signs over the dictionary member value, as RFC 9421 section 2.1.2 and the draft's test vectors do.

## Responses and logs

Every `/check` response carries `X-AgentSniff-Decision` and `X-AgentSniff-Request-Id`. Allow responses, which the proxy copies to your application, also carry `X-AgentSniff-Would-Decision`, `X-AgentSniff-Score`, `X-AgentSniff-Reasons` (signal ids), and, when attributed, `X-AgentSniff-Agent` and `X-AgentSniff-Assurance` (`trusted_verified`, `self_declared`, or `suspected`). Challenge and block responses omit those by default, because Traefik, Caddy, and Envoy relay a denial's headers to the client and they would tell an evader what to change. Set `deny_details: true` to include them while debugging; the decision log always has the full detail.

Every non-allow decision, and every attributed request, is written as one JSON line to stdout or `gate.decision_log` (`off` disables it). Set `log_allows: true` to log everything. The lines suit Wazuh, Splunk, or any JSON log pipeline.

| Route | Auth | Purpose |
|---|---|---|
| `/check`, `/check/*` | gate token | Forward-auth decision |
| `/decisions?limit=N` | gate token | Most recent logged decisions (up to 1,000) |
| `/stats` | gate token | Decision counters, including `unresolved_client_ip` |
| `/healthz` | none | Liveness |

## Configuration

```yaml
gate:
  mode: monitor                 # monitor | enforce
  host: "127.0.0.1"
  port: 9091
  token: ""                     # prefer AGENTSNIFF_GATE_TOKEN; required off loopback
  trusted_proxies: ["127.0.0.1/32", "::1/128"]
  client_ip_header: "x-forwarded-for"   # or x-real-ip, cf-connecting-ip, ...
  ja4_header: "x-ja4"
  asn_header: "x-asn"
  default_agent_action: block
  kind_actions: {}              # cloud_browser_agent | user_triggered_agent | crawler
  agent_actions: {}             # catalog id -> allow | challenge | block
  allow_verified_agents: []
  custom_agents: []             # same fields as catalog entries
  challenge_threshold: 0.5
  block_threshold: 0.8
  stale_browser_lag: 6
  rate:
    enabled: true
    key: ip                     # ip | ip_user_agent (see Tuning)
    ipv6_prefix: 64             # IPv6 clients are counted per /64
    burst_window_ms: 1000
    burst_limit: 20
    sustained_window_secs: 60
    sustained_limit: 300
    action: block
    penalty_secs: 300           # at most 7 days
    max_tracked_clients: 100000 # clients in the penalty box can use up to twice this
  tripwires:
    paths: []                   # exact paths, or prefixes ending in /
    action: block               # challenge | block
    penalty_secs: 3600          # at most 7 days
  web_bot_auth:
    enabled: true
    trusted_keys: []
    require_nonce: true
    max_lifetime_secs: 3600
    clock_skew_secs: 60
    max_nonces: 100000
    authorities: []             # hosts you serve; empty accepts any
  challenge_status: 401         # keep 401/403 with nginx
  block_status: 403
  deny_details: false
  decision_log: ""
  log_allows: false
```

The gate binds to loopback by default. A non-loopback listener requires a token of at least 32 bytes, sent by the proxy in `X-AgentSniff-Gate-Token`; the client's own `Authorization` header passes through untouched. A missing or wrong token gets `407`. nginx turns that into a 500 and logs an auth error; Traefik, Caddy, and Envoy pass the 407 to the client. Either way the request is denied.

### Tuning

- **Shared IPs.** Corporate NAT and carrier-grade NAT put many people behind one address. Raise the limits for those pages first. `rate.key: ip_user_agent` also helps, but a client that changes its user agent on every request then gets a fresh counter each time, so it trades rate protection for fewer false positives.
- **IPv6.** Clients are counted per `/64` by default. Raise `rate.ipv6_prefix` toward 128 if many unrelated users share a `/64`, or lower it (to 56 or 48) if attackers rotate across larger allocations.
- **Scope.** Gate the pages that matter (login, accounts, payments) rather than static assets, which browsers fetch in bursts.
- **Challenges.** A challenge is a deny unless you route it somewhere. Send it to a CAPTCHA or step-up flow, or set `challenge_status: 403`.

## Tripwires

A tripwire is a URL on your site that no person ever requests, because it is planted only where machines read: an HTML comment, a link hidden with `display:none`, a `url` in JSON-LD, a `Disallow` line in `robots.txt`. List the paths under `gate.tripwires.paths`. A client that requests one gets `tripwire_hit`, the configured action, and `penalty_secs` in the penalty box, so its next requests fail with `rate_penalty` whatever they ask for. The decision log records the client's user agent, JA4, and ASN with the hit, which is the cheapest labeled fingerprint you will get from live traffic.

```yaml
gate:
  tripwires:
    paths: ["/.internal/export.csv", "/private-area/"]
```

```html
<!-- <a href="/.internal/export.csv">export</a> -->
<a href="/private-area/statements" style="display:none" aria-hidden="true" tabindex="-1">statements</a>
```

- An entry ending in `/` matches every path under it; any other entry matches exactly. `/.internal/export.csv/` and `/%2einternal/export.csv` do not match the exact entry above, so use the prefix form for a directory and keep exact entries for files. Query strings are never compared.
- Keep traps out of the accessibility tree. A link hidden only with CSS is still read aloud; add `aria-hidden="true"` and `tabindex="-1"`, or use a comment. Screen-reader users must never trip a wire, which matters for a bank.
- Tripwires catch raw-HTML readers: the Grok fetcher, Muse's text fetch, and scripted crawlers. Agents that act on a rendered page's accessibility tree, as Muse's browser mode does, never see them. Do not make traps visible to widen coverage; that is the trade.
- `tripwires.action` decides the hit itself. The follow-up requests are answered by the penalty box, which applies `rate.action` (default block). If you route challenges to a step-up flow and want the whole sequence challenged, set both to `challenge`.
- Compliant crawlers follow hidden links. List every tripwire path under `Disallow` in `robots.txt` as well, so Googlebot and Bingbot never request it; otherwise each visit holds them in the penalty box for `penalty_secs`.
- With `rate.enabled: false`, or when the client address resolves to a trusted proxy, only the single request is denied; there is no penalty box to hold the client in.
- Change paths when you rotate pages. A trap that leaks into a sitemap or a real link becomes a false positive for everyone who follows it.

Prompt-injection canaries, hidden instructions that ask an agent to fetch a beacon URL, are a different tool. A hit proves a language model read the page, which separates agents from scripted bots, but security-aware agents recognize and refuse the trap, so yield on frontier agents is low and the hit measures injection resistance more than identity. Run them only on a research domain you own. Never ship them in a customer deployment, where you would be injecting instructions into agents that hold real customers' credentials.

## The catalog

Known agents live in the signed `agent_clients.json` dataset: user-agent tokens, `Signature-Agent` origins, operator ASNs, automation tokens, hosting ASNs, CDN egress ASNs, and the Chrome stable baseline. Each entry records:

- `status`, its provenance, in order of trust: `lab_observed` (identifiers captured on an origin we control with a per-run nonce URL, so attribution is exact), `operator_documented`, `cdn_directory`, and `third_party_reported`. The gate refuses any other value.
- `last_confirmed`, the `YYYY-MM-DD` the identifiers were last checked against a live source, or empty when they never were. Only the ChatGPT cloud browser and Grok Bot carry a date today: their key directories were fetched. Treat an old or empty date as a reason to re-verify before you build policy on the entry.
- `aliases`, the other names readers know the agent by (`dots`, `GrokAgent`, `Meta-WebIndexer`), for search and for mapping old ids.
- `sources` and `notes`.

Muse's and Grok Bot's tokens are third-party reports and a CDN directory listing, not vendor documentation. The Grok chat fetcher has no entry because it has no stable identifier; it is the behavior profile described above.

Update the dataset with `agentsniff update-signatures`. Add your own entries under `gate.custom_agents`, with the same fields.

## Keeping the catalog current

All three agents this gate is tuned for changed how they present themselves in October 2026: OpenAI started signing its cloud browser, Meta started signing a share of Muse traffic, and Grok Bot stopped. A catalog that is not re-checked is stale within weeks, and a stale entry is the biggest risk this gate carries.

The only ground truth is a labeled capture: pay for each agent, and give every task you hand it a unique per-run URL on an origin you own, such as `https://lab.example.com/r/<agent>/<nonce>`. The nonce makes attribution exact, and that capture earns the `lab_observed` tier. For each run record:

- JA4, JA4H, and JA4T, the HTTP/2 `SETTINGS` and priority frames, header order, and client hints;
- ASN, IPv4 versus IPv6, and whether the exit is a CDN, a cloud, or the user's own connection;
- timing between requests and the full subresource sequence, which separates a text fetch (no JavaScript, no assets) from a rendered browser.

Re-run weekly and after every vendor announcement, diff against the previous capture, and update `last_confirmed` for what still holds. Where a cloud build of Chromium differs from retail Chrome of the same version in its HTTP/2 or JA4H behavior, that difference is a candidate signal; the gate does not carry one until the lab has shown it.

The gate is header-only by design: it sees one request at a time plus rate counters. A session layer (asset-to-document ratio, deep links without a referrer chain, uniform action timing) or a JavaScript probe (software GL renderer, timezone against IP geography, no pointer movement before clicks) is where commercial vendors catch Muse and Grok Bot in a real browser. Either is a separate decision, because it changes what the gate is.

## Load, soak, and fuzz testing

Two tools in the repository exercise the gate without production traffic.

**Load and soak.** `gate_load` sends a mix of request profiles (complete browsers, browsers missing headers, `curl` and `python-requests`, a self-declared agent, and garbage Web Bot Auth signatures) from many distinct `X-Forwarded-For` addresses, and reports throughput, decision counts, latency percentiles, and the gate's resident memory. Start the gate in enforce mode with the decision log pointed somewhere cheap, then:

```bash
cargo run --release -p agentsniff --example gate_load -- \
    --rps 2000 --duration 3600 --clients 300000 --pid "$(pgrep -f 'agentsniff gate')"
```

`--rps 0` runs unthrottled. Use more clients than `rate.max_tracked_clients` (default 100,000) so the run covers eviction, and watch the `rss` column stay flat once the table is full. The gate must trust the generator's address (loopback is trusted by default) or every request counts as one client.

Baseline measured 2026-11-08 on a 24-core Linux host over loopback, generator and gate on the same machine, enforce mode, default configuration:

| Run | Throughput | p50 | p99 | p99.9 | Errors | Gate RSS |
|---|---:|---:|---:|---:|---:|---:|
| Unthrottled, 64 connections, 300k clients, 60s | 207,000 rps | 0.26ms | 1.05ms | 1.55ms | 0 | 67MB |
| 5,000 rps with the decision log on a file, 60s | 5,000 rps | 0.18ms | 0.42ms | 0.97ms | 0 | 58MB |
| Soak, 2,000 rps, 300k clients, 60 min (7.2M requests) | 2,000 rps | 0.21ms | 0.81ms | 2.02ms | 0 | 48 to 58MB |

Resident memory settled within ten minutes and moved between 48MB and 58MB for the rest of the hour as the rate table evicted and refilled. `/stats` counted every request and dropped no log lines. Latency is measured by the generator and includes its own HTTP client, so the gate alone is faster than these numbers.

**Fuzzing.** `crates/agentsniff-gate/fuzz` holds four `cargo fuzz` targets (nightly toolchain): `sfv` (RFC 8941 structured fields, with a serialize-and-reparse fixed-point check), `cidr`, `webbotauth` (arbitrary headers against a pinned key, asserting nothing ever verifies), and `engine` (the whole decision path, asserting the score stays in range).

```bash
cd crates/agentsniff-gate && cargo +nightly fuzz run engine -- -max_total_time=600 -jobs=2
```

Each target ran clean for ten minutes with two jobs on 2026-11-08 (14,000 to 280,000 executions per second depending on the target). A found input lands in `fuzz/artifacts/<target>/`; reproduce it with `cargo +nightly fuzz run <target> <that file>`.
