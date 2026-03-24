# xdr-coordinator Notes

This workspace does not currently include `xdr-coordinator` sources.

When available, add an adapter in that plugin to call:

- `GET /api/xdr-defense/policy`
- `PUT /api/xdr-defense/policy`
- `GET /api/xdr-defense/artifacts`
- `POST /api/xdr-defense/artifacts`
- `POST /api/xdr-defense/rollback/confirm`

This keeps rule/threat-intel/artifact lifecycle centralized in `xdr-defense` while preserving existing agent fleet views in `xdr-coordinator`.
