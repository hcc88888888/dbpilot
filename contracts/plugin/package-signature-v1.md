# DBPilot plugin package signature v1

Status: binding Server and Agent contract.

## Container

A package is one `application/gzip` member containing a tar archive rooted at
`plugin-package/`. Gzip optional header fields are forbidden. Raw compressed
suffix bytes and concatenated gzip members are forbidden.

Tar may contain the canonical `plugin-package/` root directory, canonical
child directory headers, and regular files. Absolute paths, backslashes,
unclean paths, duplicate names, links, devices and other special types are
forbidden. Bounded zero record padding after the tar end markers is accepted;
non-zero decompressed suffix data is forbidden. All decompressed bytes,
including headers and padding, count against the expanded-size limit.

Tar ownership and mode fields are transport metadata and are not trusted or
authenticated. An installer creates private directories as `0700`, executable
files as `0500`, and retained manifests/configuration content as `0400`.
Setuid/setgid/sticky bits from tar headers are never propagated.

## Canonical manifest

`plugin-package/manifest.json` is UTF-8 JSON whose bytes equal the compact,
lexicographically key-sorted JSON encoding of its parsed value. Unknown,
script/hook/download, or secret-bearing fields are forbidden. Its `files`
array declares every regular package file except the manifest and signature.
Every path, byte length and lowercase SHA-256 is independently derived and
matched by the verifier.

Declared Linux executables are ELF64 little-endian static `ET_EXEC` files.
`amd64` maps to `EM_X86_64`; `arm64` maps to `EM_AARCH64`. `PT_INTERP`,
`PT_DYNAMIC`, dynamic sections, RPATH/RUNPATH metadata, shebangs and non-ELF
payloads are forbidden.

## Logical-content digest

Directory headers, tar ownership/modes/timestamps, gzip metadata, padding and
`plugin-package/SIGNATURE.ed25519` are excluded from the signed logical model.
All other regular entries, including `manifest.json`, are sorted by UTF-8 path
bytes. The SHA-256 input is:

```text
dbpilot-plugin-content-v1\n
len(path) ":" path
len(decimal_size) ":" decimal_size
len(lower_hex_sha256) ":" lower_hex_sha256
... repeated for every sorted regular entry ...
```

Lengths are decimal counts of UTF-8 bytes with no leading zero. `decimal_size`
is the base-10 file byte length. The result is `content_digest`.

## Signature message

Let `manifest_digest = SHA256(canonical manifest bytes)`. The exact Ed25519
message bytes are ASCII:

```text
dbpilot-plugin-signature-v1\n
manifest-sha256:<64 lowercase hex>\n
content-sha256:<64 lowercase hex>\n
```

`SIGNATURE.ed25519` is exactly the raw 64-byte Ed25519 signature. Publisher and
key IDs select an approved public key; they do not carry key material.

The compressed `.tar.gz` SHA-256 is independently derived from the complete
uploaded bytes and stored as immutable Artifact metadata. It is deliberately
not part of the self-contained signature message because the archive contains
the signature file itself.

## Fixtures

`backend/internal/plugincatalog/testdata/package-v1/` contains fixed amd64 and
arm64 ELF bytes, a canonical manifest, public key, signature and digest/message
values generated independently of verifier implementation. Server tests
consume the corpus directly. Task 9 Agent verification must consume the same
files and produce the same decisions.
