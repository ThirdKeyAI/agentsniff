# agentsniff-gate

The decision engine behind `agentsniff gate`, AgentSniff's inbound agent gate
for forward-auth proxies. Given one HTTP request's facts it returns allow,
challenge or block: it matches known agents from the signed catalog by user
agent and `Signature-Agent`, verifies Web Bot Auth signatures against
operator-pinned keys, scores unverified clients from their behavior, and
enforces per-client rate limits. It never fetches key directories or any
other remote data, and it needs `agentsniff-signatures` for the datasets.
The HTTP listener that proxies call lives in the `agentsniff` crate.

Apache-2.0, copyright Jascha Wanger / ThirdKey AI.
