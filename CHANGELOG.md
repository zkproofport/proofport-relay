# Changelog

## [0.1.1](https://github.com/zkproofport/proofport-relay/compare/proofport-relay-v0.1.0...proofport-relay-v0.1.1) (2026-09-13)


### Features

* **logging:** enhance all endpoint and auth logging for full observability ([6b5c185](https://github.com/zkproofport/proofport-relay/commit/6b5c185ce46692407cb702e59bb9df6c1204b905))
* **relay:** carry a return target so the app can hand control back ([5d23151](https://github.com/zkproofport/proofport-relay/commit/5d231519efbcf8ed372cded1cfc4b87f95dade2f))
* **relay:** move to the published SDK 0.3.0, which carries arc_eligibility ([9c10b23](https://github.com/zkproofport/proofport-relay/commit/9c10b236c5c7de238940daaaf27f995569040cbc))
* **relay:** one signature policy, keyed by the SDK's circuit ids ([5c2ed63](https://github.com/zkproofport/proofport-relay/commit/5c2ed63b590d5cb1ae81e7dcab70249f126720a0))
* session-based auth, remove clientId, circuit-specific signing ([82271aa](https://github.com/zkproofport/proofport-relay/commit/82271aa451f497a4fe612974fc673bdf19f8a7bb))


### Bug Fixes

* correct PORT default, CORS wildcard parsing, and env var guards ([0e53765](https://github.com/zkproofport/proofport-relay/commit/0e537654fee61f8517bbb84c0600ebbc46020baa))
* **logging:** mask sensitive data in all log output ([1156ab7](https://github.com/zkproofport/proofport-relay/commit/1156ab72cbef0569285e9113db4bdf2a5386d3c7))
* pass dappName/dappIcon/message through to deep link ([5187c80](https://github.com/zkproofport/proofport-relay/commit/5187c8083dde380d455a92396d8b8c1aec116d77))
* **relay:** returnScheme accepts schemes only, and denies bare https ([0e2a8ca](https://github.com/zkproofport/proofport-relay/commit/0e2a8ca88fe2733f6666c0f9c1449fa3fc791eb0))
* remove free tier Socket.IO restriction and add auth logging ([6c26609](https://github.com/zkproofport/proofport-relay/commit/6c266093c7b893d1f5db07e1366086674a6e524e))


### Refactoring

* remove nullifier from proof callback and poll responses ([8218397](https://github.com/zkproofport/proofport-relay/commit/82183978964c60bb1c658aae6929326269b941d5))
* remove Redis in-memory fallback, require REDIS_URL ([503e132](https://github.com/zkproofport/proofport-relay/commit/503e132c8c5addc7f18da6a9ed8ca66b34764c8d))
* rename ZKProofPort to ZKProofport in relay source and docs ([f45968f](https://github.com/zkproofport/proofport-relay/commit/f45968f41f5d7f8019942239c6f8ddaa97f5624d))
* replace JWT auth with challenge-signature verification ([29cdc72](https://github.com/zkproofport/proofport-relay/commit/29cdc724dfb80d8e890cbbcf17f737f4de9b4ec5))
