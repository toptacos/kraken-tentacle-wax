# Security

- Secret minisign key stays at `~/.minisign/minisign.key` or `payload.secret_key` under an allow-listed path.
- HMAC fixture key is `$KRAKEN_HOME/.kraken/data/wax/wax.key` mode `0600`.
- `finish` drops `secret_key` and `identity`.
- `seal`/`open` require the `age` binary. No fake age format.
- Jail: no `keys/`, licenses, catalog, topta.
