# APF: the Astra Package Format, version 1

An `.apf` file is one application for Starry. `cosmic` builds, signs,
verifies, installs and removes them.

## Archive

A zip archive (stored or deflated entries) of regular files and directories.

- Paths are relative, `/`-separated, made of `A-Z a-z 0-9 . _ -`; no empty,
  `.` or `..` components, at most 255 bytes. No symlinks, devices or duplicates.
- At most 10000 entries and 1 GiB unpacked.
- A file is executable when its zip mode has any execute bit.

```
manifest.json
qml/main.qml          (or bin/<program>)
icons/...
i18n/ru.qm            Qt translations, one per locale
META-INF/files        the content list
META-INF/<keyid>.sig  one per signature
```

## Content list

`META-INF/files` lists every file outside `META-INF/`, `manifest.json`
included, sorted by path in byte order, one per line:

```
<sha256 hex> <size in bytes> <path>
```

The archive must contain exactly these files, with these sizes and hashes.

## Signatures

Each `META-INF/<keyid>.sig` holds:

```
key ed25519 <base64 of the 32-byte public key>
sig <base64 of the 64-byte signature>
```

The signature is Ed25519 over the 64-byte SHA-512 digest of the bytes
`cosmic-apf-1\n` followed by the bytes of `META-INF/files`. Signing a
digest lets OpenPGP cards such as a YubiKey hold the key (see
`tools/apf-sign-gpg`). `<keyid>` is the first 16 hex digits of the SHA-256
of the raw public key, in lower case. A package needs at least one
valid signature; invalid ones make it invalid.

Trust is decided at install time, not by the file:

- **Developer key.** The first install records the package's key ids. An
  update must carry a valid signature from one of them (key continuity, as
  on Android).
- **Platform key.** A valid signature by a key in `/etc/cosmic/keys/*.pub`
  marks the app as a platform app, which may hold platform permissions.
  More signers (a store, say) are just more `.sig` files.

## Manifest

```json
{
  "format": 1,
  "id": "org.starry.dialer",
  "version": "1.0.0",
  "build": 3,
  "api": 1,
  "name": { "en": "Phone", "ru": "Телефон" },
  "icon": "icons/dialer.svg",
  "color": "#27AE60",
  "entry": { "type": "qml", "path": "qml/main.qml" },
  "permissions": ["telephony"]
}
```

| Field | |
|---|---|
| `format` | 1 |
| `id` | reverse-DNS, lower case: at least two dot-separated labels of `a-z 0-9 -`, starting with a letter, at most 128 bytes |
| `version` | shown to people; any short string |
| `build` | integer ≥ 1; an update must have a higher one |
| `api` | the lowest Starry platform API level the app needs |
| `name` | display name per locale (`en`, `ru`, `pt_BR`...); `en` is required |
| `icon` | optional; a file in the package |
| `color` | optional; `#RRGGBB`, the icon tile until icons are drawn |
| `entry.type` | `qml` (run by Stardust) or `native` |
| `entry.path` | a file in the package; executable for `native` |
| `permissions` | optional; names of what the app may use |

Unknown fields are ignored, so later formats can add them.

Names fall back from the user's locale (`ru_RU`) to its language (`ru`) to `en`.

## Installed layout

Under `/data/cosmic` (`$COSMIC_ROOT` overrides):

| Path | |
|---|---|
| `apps/<id>/` | the unpacked package, owned by root, read-only to the app |
| `data/<id>/` | the app's private data, owned by its uid, mode 0700 |
| `state/apps/<id>.json` | uid, signer key ids, platform flag, build, install time |
| `state/uids` | `<id> <uid>` per line; uids start at 10000 and are never reused |

An update unpacks next to the old version and swaps the directories
atomically; data is kept. Removal deletes the app and its data.
