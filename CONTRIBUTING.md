# Contributing to xdr-defense

This repository owns read-only exploration of DNS, network, process, and file telemetry. The [README](README.md) defines the UI and search API. Consult the [Agent telemetry mappings](https://github.com/kplrm/xdr-agent/blob/main/docs/telemetry.md) when interpreting emitted fields.

## Development and validation

Use the Node.js version and dependency tooling required by your target OpenSearch Dashboards checkout. Install plugin dependencies with the committed Yarn lockfile where needed. Point `OSD_ROOT` at a bootstrapped checkout matching your deployment:

```bash
export OSD_ROOT=/path/to/bootstrapped/OpenSearch-Dashboards
npm test
npm run build
```

The build targets the version of `OSD_ROOT` by default. An explicit `--opensearch-dashboards-version` must match that checkout. The build uses disposable staging; keep the upstream checkout untouched.

For UI changes, check each affected tab in Dashboards with representative telemetry. Verify the time picker, search, filters, pagination, empty results, and event details. Include screenshots for visible changes.

## Engineering expectations

- Preserve read-only behavior and keep time, host, module, and query filters consistent across charts and tables.
- Keep telemetry field interpretation aligned with the authoritative Agent mappings.
- Handle missing fields, malformed events, empty results, and rolled-over backing indices.
- Preserve event metadata and the full source document in event details.
- Add focused search/API regression coverage when behavior changes.
- Match the existing TypeScript, React, and Dashboards UI patterns.

## Issues and pull requests

Use this repository's [issue tracker](https://github.com/kplrm/xdr-defense/issues) for general questions, reproducible bugs, and proposals. Discuss substantial changes before implementation.

1. Fork the repository and branch from `main`.
2. Keep the change focused and follow the existing code style.
3. Add regression coverage for changed behavior and update affected documentation.
4. In your PR, explain the problem, resulting behavior, validation performed, and compatibility impact. List any checks you could not run, including the reason.

Use sanitized logs and fixtures; remove secrets and identifying customer data before posting.

## License and attribution

By submitting a contribution, you agree to license your original changes under the [GNU Affero General Public License, version 3 only](LICENSE) (`AGPL-3.0`). You retain copyright in your contributions. Submit only work you have the right to contribute, and preserve existing copyright and third-party license notices.

## Security reports

Report vulnerabilities through this repository's [private vulnerability reporting](https://github.com/kplrm/xdr-defense/security/advisories/new) when enabled. Include affected versions, reproduction steps, impact, and sanitized supporting details. Keep vulnerability, bypass, and credential details out of public issues.

If private reporting is unavailable, open an issue asking the maintainer for a private reporting channel without describing the vulnerability.

## Conduct

Be respectful, direct, and technically concrete in issues, reviews, and discussions.
