# Contributing to xdr-defense

Thanks for your interest in improving xdr-defense.

## Development setup

From the OpenSearch Dashboards repository root:

```bash
yarn osd bootstrap --single-version=loose
cd plugins/xdr-defense
yarn build
```

## Versioning

Plugin version is source-of-truth in `VERSION`.
`yarn build` runs `version:sync` to keep `package.json` and `opensearch_dashboards.json` aligned.

## Pull request checklist

- Keep changes focused and reviewable.
- Add or update tests when behavior changes.
- Run `yarn build` before opening PR.
- Update `README.md` if setup or API behavior changes.
- Add yourself to `AUTHORS` after your first merged contribution.

## License

By contributing, you agree your contributions are licensed under AGPL-3.0 as described in `LICENSE`.
