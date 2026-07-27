# Changelog

Notable changes to OpsForge will be recorded here.

## Unreleased

- Validated PortLens parser and runtime behavior against genuine iproute2 `ss` 6.1.0 output on Ubuntu 24.04.1 LTS under WSL, with regression coverage for the observed IPv4 and IPv6 endpoint forms.
- Added the experimental initial PortLens implementation for inspecting local TCP listening sockets, with best-effort process enrichment, tests, and minimal CI.
- Established the initial repository foundation documentation, license, and repository hygiene files.
