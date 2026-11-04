# agentsniff-signatures

The signed detection datasets that AgentSniff ships with, and the code that
verifies them. Every dataset under `assets/signatures/` is embedded at build
time together with its detached ECDSA P-256 signature and is accepted only
when that signature verifies against the pinned public key in
`signing_key.pub`. A dataset that fails verification is reported as
unverified and never used; nothing in this crate fetches data from the
network. Runtime overlays from `~/.agentsniff/signatures/` are accepted on
the same terms, as a complete set or not at all.

Apache-2.0, copyright Jascha Wanger / ThirdKey AI.
