# File Encryptor

File Encryptor is CLI tool to **encrypt / decrypt files and folders** into/from a single authenticated container (`.enc`).

It is designed with safe defaults and hardened extraction to reduce common “archive-style” risks (path traversal, destination collisions, symlink tricks), while keeping usage simple.



## Features

- **Encrypt files and directories** into one container
- **Decrypt** back into a destination directory
- AEAD per chunk:
  - **AES-256-GCM**
  - **ChaCha20-Poly1305**
- Authenticated container header: **HMAC-SHA256**
- Chunked streaming format (handles large files)
- Atomic operations:
  - container write uses temp file + atomic replace
  - extracted files use temp file + atomic replace
- Safe path policy:
  - refuses `..`, absolute paths, backslashes in container paths
  - Windows hardening: device names, invalid chars, trailing dot/space segments
  - duplicate destination collisions are rejected
- Symlink policy (encryption):
  - symlinks are refused by default
  - `--follow-symlinks` allows encrypting **symlink file targets**
  - optional hardening: `--symlink-targets-within-root`



## Requirements

- Python **3.9+** (recommended)
- `cryptography`

Install dependency:

```bash
pip install cryptography
```



## Quick Start

### Encrypt (keyfile mode)

```bash
python3 encryptor.py --files ./docs ./photo.jpg --out backup.enc --mode key --keyfile my.key
```

- If `my.key` doesn’t exist, it will be created (securely).
- By default, encryption uses **AESGCM**.

### Encrypt (password mode)

```bash
python3 encryptor.py --files ./folder --out folder.enc --mode password
```

You will be prompted for the password.

### Encrypt (ChaCha20-Poly1305)

```bash
python3 encryptor.py --files ./folder --out folder.enc --mode password --cipher chacha20poly1305
```

### Decrypt

```bash
python3 encryptor.py --decrypt --files backup.enc --out ./restored --keyfile my.key
```

If the container requires a password, you will be prompted.

### Overwrite behavior

- `--overwrite`:
  - encryption: replace existing output container
  - decryption: overwrite extracted files if they already exist

```bash
python3 encryptor.py --decrypt --files backup.enc --out ./restored --keyfile my.key --overwrite
```



## CLI Reference

### Modes

- **Encrypt** (default)  
  Use `--mode key|password|both`

- **Decrypt**  
  Use `--decrypt` (mode and cipher are read from the container header)

### Arguments

| Flag | Encrypt | Decrypt | Description |
||--:|--:|-|
| `--files` | ✅ | ✅ | Encrypt: one or more input paths. Decrypt: exactly one container path. |
| `--out` | ✅ | ✅ | Encrypt: output container file. Decrypt: output directory. |
| `--mode` | ✅ | ❌ | `key`, `password`, or `both` |
| `--cipher` | ✅ | ❌ | `aesgcm` or `chacha20poly1305` |
| `--chunk-size` | ✅ | ❌ | Chunk size in bytes (default `1048576`, range `4096..16777216`) |
| `--keyfile` | ✅* | ✅* | Required for `mode=key`/`both` containers |
| `--password` | ✅* | ✅* | If omitted and required, tool will prompt |
| `--overwrite` | ✅ | ✅ | Replace output container / overwrite extracted files |
| `--overwrite-keyfile` | ✅ | ❌ | Allow overwriting an existing keyfile (**dangerous**) |
| `--follow-symlinks` | ✅ | ❌ | Allow encrypting symlink **file** targets |
| `--symlink-targets-within-root` | ✅ | ❌ | Require symlink targets to remain within input root (needs `--follow-symlinks`) |

\* depends on container mode.



## Container Path Policy (Encryption)

Each input becomes its own **root** inside the container:

- input file `./photo.jpg` → stored as `photo.jpg`
- input dir `./docs` → stored as `docs/<relative_path_inside_docs>`

If multiple inputs share the same basename, roots are disambiguated deterministically:

- `data`, `data__2`, `data__3`, ...



## Security Notes

### Password mode
Password-based encryption uses **scrypt** with parameters stored in the header and hardened sanity limits during parsing.  
Use a strong password (long + unique).

### Avoid passing passwords via CLI
Using `--password` may expose the password via shell history / process listing on some systems. Prefer prompt input.

### Extraction hardening
During decryption, the tool rejects:
- path traversal (`..`, absolute paths)
- duplicate destination collisions
- Windows-reserved device names and invalid filename patterns
- symlink components in the output path (best-effort hardening)



## Examples

Encrypt a directory and a file into one container (keyfile):

```bash
python3 encryptor.py --files ./docs ./photo.jpg --out archive.enc --mode key --keyfile archive.key
```

Encrypt multiple inputs with the same basename:

```bash
python3 encryptor.py --files ./data ./backup/data --out data.enc --mode key --keyfile my.key
```

Decrypt to an existing directory (only overwrites if `--overwrite` is set):

```bash
python3 encryptor.py --decrypt --files data.enc --out ./restored --keyfile my.key
```


