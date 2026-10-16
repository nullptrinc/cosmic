# cosmic

Starry's package manager. Applications ship as `.apf` files (Astra Package
Format): a zip with a JSON manifest, a SHA-256 list of every file and
Ed25519 signatures. See [SPEC.md](SPEC.md).

```sh
cosmic keygen dev.key                     # dev.key and dev.key.pub; prints the key id
cosmic pack myapp/ myapp.apf -k dev.key   # myapp/ holds manifest.json and the files
cosmic sign myapp.apf -k platform.key     # add a signature (platform, store...)
cosmic verify myapp.apf
cosmic install myapp.apf                  # as root
cosmic list
cosmic remove org.example.myapp
```

- Every file is hashed and every signature checked before anything is
  installed; paths are restricted so no entry can land outside the app.
- The first install pins the app's signing keys; updates must be signed by
  one of them and have a higher `build`.
- A signature by a key in `/etc/cosmic/keys/*.pub` makes a platform app.
- Apps unpack to `/data/cosmic/apps/<id>`, owned by root; each app gets its
  own uid (from 10000) and a private `/data/cosmic/data/<id>`. Updates swap
  the directory atomically and keep the data.
- `pack` is reproducible: the same files give the same `.apf`.

`COSMIC_ROOT` and `COSMIC_KEYS` move the install root and the platform key
directory, for tests.

Build: `meson setup build && ninja -C build`. Needs OpenSSL 3 (libcrypto),
libarchive and json-c.

## License

MIT, see [LICENSE](LICENSE).
