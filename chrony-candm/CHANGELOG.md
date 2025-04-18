# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2025-04-18
### Added
- async query_uds function that works without spawning a whole runtime
- UnixDatagramClient so that the async UDS socket can be easily re-used or otherwise controlled by the caller

## [0.1.2] - 2024-02-26
### Fixed
- Fixed an issue with SourceData request size

## [0.1.1] - 2021-12-23
### Fixed
- Fixed an issue constructing ChronyFloats from f64s

## [0.1.0] - 2021-11-01
### Added
- Initial working version