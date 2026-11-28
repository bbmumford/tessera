# Changelog

## [0.3.0](https://github.com/bbmumford/tessera/compare/v0.2.0...v0.3.0) (2026-11-28)


### ⚠ BREAKING CHANGES

* NewSQLStore is removed; open the store with OpenSQLStore(db, DigestKeys{Current: key}).

### Bug Fixes

* a cookie domain override is held to the allowed roots ([1956c97](https://github.com/bbmumford/tessera/commit/1956c9798af756d48b2d34ce7c6f7c4202b438b0))
* a handoff redemption clears its token from the URL and never replaces a live session ([d334d13](https://github.com/bbmumford/tessera/commit/d334d132d06331016a4bdabdb5d86c4b771bff2e))
* a mutation that lands during a cache read-through stays in effect ([2a7ed50](https://github.com/bbmumford/tessera/commit/2a7ed5001ae4bd3b7be1bb994117688bc446ef80))
* a request host that is an IPv6 literal keeps its address ([6f18fb1](https://github.com/bbmumford/tessera/commit/6f18fb1dfd8b2567bd347ffd59c258920db7a2c1))
* a session key too long for a cookie leaves no live session behind ([6e3ce3e](https://github.com/bbmumford/tessera/commit/6e3ce3e548ca319b0b53ee0d542c5c689d765ef6))
* LogoutAll wipes in the partition of the session the cookie names ([b22ee9a](https://github.com/bbmumford/tessera/commit/b22ee9aa4adbcc44ab9396af7b71f38d81d629a8))
* LogoutCurrent reports a delete the store failed ([e90c92d](https://github.com/bbmumford/tessera/commit/e90c92dd8fce745b2353128952b117a2499f90a0))
* MemStore lists only a subject's unexpired sessions, as SQLStore does ([8aa2e8a](https://github.com/bbmumford/tessera/commit/8aa2e8afa0aefca52428cc667bead7426044ca14))
* the session cache updates its entry on a touch instead of evicting it ([53668c3](https://github.com/bbmumford/tessera/commit/53668c34298f909a0338a881f3b2123f4c58672d))
* the session cache updates its entry on a touch instead of evicting it ([32de4d9](https://github.com/bbmumford/tessera/commit/32de4d998ba074a71a857ee819f04e34bd024dc7))
* the SQL session store always digests session keys under a key ([86568f5](https://github.com/bbmumford/tessera/commit/86568f517b6fbe6db508412d813df38e4862db84))
* the SQL store refuses a chosen session key that is not the minted form ([5b9ec1d](https://github.com/bbmumford/tessera/commit/5b9ec1d807aead6a703c7336a459f95a205eb10c))


### Performance Improvements

* the session cache scans its map for aged entries at most once per TTL ([726b674](https://github.com/bbmumford/tessera/commit/726b674386bed21e417191432412c19113a4f1c7))

## [0.2.0](https://github.com/bbmumford/tessera/compare/v0.1.0...v0.2.0) (2026-11-25)


### Features

* a session records how the sign-in chose its partition (Session.PartitionVia) ([b4f77b6](https://github.com/bbmumford/tessera/commit/b4f77b6ab4157724986b790d8875a7cee23447a3))
