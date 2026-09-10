# Changelog
All notable changes to this project will be documented in this file.


## [Unreleased]

### Modified
- Migrated dependency to `github.com/svicknesh/kdf/v2 v2.0.0`, removing the `github.com/svicknesh/kdf v1.2.1` requirement.
- Adapted to `kdf/v2`'s error-returning `SetSalt` and `Generate` methods; errors are now checked and propagated instead of discarded.
- Corrected README documentation error stating the HMAC step used `sha3-384`; it actually uses `sha3-256`.

### Added
- Deterministic compatibility regression test asserting the derived key and signature remain byte-for-byte identical after the `kdf/v2` migration.


## [1.0.1] - 2024-02-08 Vicknesh Suppramaniam

### Modified
- Updated go modules.
- Rewrote parts using the `kdf` library using the new methods.


## [1.0.0] - 2023-05-12 Vicknesh Suppramaniam

### Added
- Initial code creation.