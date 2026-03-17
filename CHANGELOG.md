# Changelog

## [0.1.1](https://github.com/zkproofport/proofport-relay/compare/proofport-relay-v0.1.0...proofport-relay-v0.1.1) (2026-03-17)


### Features

* **logging:** enhance all endpoint and auth logging for full observability ([6b5c185](https://github.com/zkproofport/proofport-relay/commit/6b5c185ce46692407cb702e59bb9df6c1204b905))
* session-based auth, remove clientId, circuit-specific signing ([82271aa](https://github.com/zkproofport/proofport-relay/commit/82271aa451f497a4fe612974fc673bdf19f8a7bb))


### Bug Fixes

* correct PORT default, CORS wildcard parsing, and env var guards ([0e53765](https://github.com/zkproofport/proofport-relay/commit/0e537654fee61f8517bbb84c0600ebbc46020baa))
* **logging:** mask sensitive data in all log output ([1156ab7](https://github.com/zkproofport/proofport-relay/commit/1156ab72cbef0569285e9113db4bdf2a5386d3c7))
* pass dappName/dappIcon/message through to deep link ([5187c80](https://github.com/zkproofport/proofport-relay/commit/5187c8083dde380d455a92396d8b8c1aec116d77))
* remove free tier Socket.IO restriction and add auth logging ([6c26609](https://github.com/zkproofport/proofport-relay/commit/6c266093c7b893d1f5db07e1366086674a6e524e))


### Refactoring

* remove nullifier from proof callback and poll responses ([8218397](https://github.com/zkproofport/proofport-relay/commit/82183978964c60bb1c658aae6929326269b941d5))
* remove Redis in-memory fallback, require REDIS_URL ([503e132](https://github.com/zkproofport/proofport-relay/commit/503e132c8c5addc7f18da6a9ed8ca66b34764c8d))
* rename ZKProofPort to ZKProofport in relay source and docs ([f45968f](https://github.com/zkproofport/proofport-relay/commit/f45968f41f5d7f8019942239c6f8ddaa97f5624d))
* replace JWT auth with challenge-signature verification ([29cdc72](https://github.com/zkproofport/proofport-relay/commit/29cdc724dfb80d8e890cbbcf17f737f4de9b4ec5))
