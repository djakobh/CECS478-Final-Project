# Contributing

## Getting Started

1. Clone the repository and run `make bootstrap` to set up your environment.
2. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes, write tests where applicable, and verify with `make test`.
4. Submit a pull request against `main` with a clear description of what changed and why.

## Branch Naming

| Type | Pattern | Example |
|---|---|---|
| Feature | `feature/<name>` | `feature/http-parser` |
| Bug fix | `fix/<name>` | `fix/dns-false-positives` |
| Docs | `docs/<name>` | `docs/update-setup` |

## Commit Messages

Use short, imperative-mood subject lines (≤ 72 chars):

```
Add HTTP header validation logic
Fix off-by-one in packet length check
Update README with PCAP instructions
```

## Code Style

- Follow the language conventions used in `src/`.
- Keep functions focused and small.
- Do not commit PCAP files larger than a few MB without discussion.

## Testing

All new detection logic should include a corresponding test in `tests/`. Run the full suite with:

```bash
make test
```

## Ethics & Scope

All contributions must remain within the controlled lab environment scope defined in the project proposal. Do not add functionality that targets real external systems or captures live public network traffic.

## Questions

Open an issue or reach out to the project maintainer.
