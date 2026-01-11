#!/usr/bin/env python3
# encryptor.py
#
# Production-ready file/folder encryptor/decryptor.
# Container format v1: authenticated header (HMAC-SHA256) + per-chunk AEAD (AES-256-GCM or ChaCha20-Poly1305).
#
# Dependencies: stdlib + cryptography

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import secrets
import struct
import sys
from dataclasses import dataclass
from enum import IntEnum
from getpass import getpass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, List, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# =========================
# Constants / Limits
# =========================

MAGIC = b"ENCR"
VERSION = 1

KEYFILE_MAGIC_LINE = "ENCRKEYv1"
KEY_LEN = 32
MASTER_SEED_LEN = 64
HMAC_LEN = 32
NONCE_PREFIX_LEN = 8
COUNTER_MAX = 0xFFFFFFFF

DEFAULT_CIPHER = "aesgcm"
DEFAULT_CHUNK_SIZE = 1_048_576
MIN_CHUNK_SIZE = 4096
MAX_CHUNK_SIZE = 16_777_216

# DoS / sanity limits
MAX_PATH_LEN = 4096

# Password KDF defaults (stored in header)
SCRYPT_N = 1 << 15  # 32768 (~32 MiB memory with r=8)
SCRYPT_R = 8
SCRYPT_P = 1

# Hardened limits for reading containers (v1 compatibility preserved)
MAX_SCRYPT_N = 1 << 20  # upper bound for parsing; memory limit below is the main control
MAX_SCRYPT_R = 64
MAX_SCRYPT_P = 16
MAX_SCRYPT_MEM = 512 * 1024 * 1024  # 512 MiB, mem ~= 128 * r * N bytes (scrypt estimate)

HKDF_INFO = b"ENCRv1"


# =========================
# Enums / Data
# =========================

class CipherId(IntEnum):
    AESGCM = 1
    CHACHA20POLY1305 = 2

    @staticmethod
    def from_cli(name: str) -> "CipherId":
        n = name.lower()
        if n == "aesgcm":
            return CipherId.AESGCM
        if n == "chacha20poly1305":
            return CipherId.CHACHA20POLY1305
        raise ValueError(f"Unsupported cipher: {name}")

    def to_cli(self) -> str:
        return "aesgcm" if self == CipherId.AESGCM else "chacha20poly1305"


class ModeId(IntEnum):
    KEY = 1
    PASSWORD = 2
    BOTH = 3

    @staticmethod
    def from_cli(name: str) -> "ModeId":
        n = name.lower()
        if n == "key":
            return ModeId.KEY
        if n == "password":
            return ModeId.PASSWORD
        if n == "both":
            return ModeId.BOTH
        raise ValueError(f"Unsupported mode: {name}")

    def human(self) -> str:
        if self == ModeId.KEY:
            return "KEY"
        if self == ModeId.PASSWORD:
            return "PASSWORD"
        return "BOTH"


class RecordType(IntEnum):
    FILE_BEGIN = 1
    FILE_END = 2
    EOF = 255


@dataclass(frozen=True)
class ScryptParams:
    n: int
    r: int
    p: int


@dataclass(frozen=True)
class Header:
    version: int
    cipher_id: CipherId
    mode_id: ModeId
    salt: bytes
    scrypt_params: Optional[ScryptParams]
    chunk_size: int

    header_without_hmac: bytes
    header_hash: bytes  # SHA256(header_without_hmac)
    stored_hmac: bytes


# =========================
# Errors
# =========================

class EncryptorError(Exception):
    pass


class FormatError(EncryptorError):
    pass


class SecretError(EncryptorError):
    pass


# =========================
# Helpers
# =========================

def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def read_exact(f: BinaryIO, n: int) -> bytes:
    if n < 0:
        raise FormatError("Invalid read size.")
    buf = bytearray()
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            raise FormatError("Unexpected EOF while reading container.")
        buf += chunk
    return bytes(buf)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compare_digest(a: bytes, b: bytes) -> bool:
    return secrets.compare_digest(a, b)


def _ensure_chunk_size_ok(chunk_size: int) -> None:
    if not (MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE):
        raise EncryptorError(
            f"--chunk-size must be in [{MIN_CHUNK_SIZE} .. {MAX_CHUNK_SIZE}], got {chunk_size}"
        )


def _is_windows_drive_path(p: str) -> bool:
    # Reject e.g. "C:foo", "C:\\foo" or "\\\\server\\share"
    if len(p) >= 2 and p[1] == ":" and p[0].isalpha():
        return True
    if p.startswith("\\\\"):
        return True
    return False


def _fsync_fileobj_best_effort(f: BinaryIO) -> None:
    try:
        f.flush()
    except Exception:
        return
    try:
        os.fsync(f.fileno())
    except Exception:
        pass


def _fsync_dir_best_effort(dir_path: Path) -> None:
    if os.name != "posix":
        return
    try:
        fd = os.open(str(dir_path), os.O_RDONLY)
    except Exception:
        return
    try:
        os.fsync(fd)
    except Exception:
        pass
    finally:
        try:
            os.close(fd)
        except Exception:
            pass


def _unlink_best_effort(p: Path) -> None:
    try:
        p.unlink()
    except FileNotFoundError:
        pass
    except Exception:
        pass


def _random_token(nbytes: int = 8) -> str:
    return secrets.token_hex(nbytes)


def _posix_open_flags_no_follow() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _secure_open_exclusive(path: Path, *, mode: int = 0o600) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if os.name == "posix":
        flags |= _posix_open_flags_no_follow()
    return os.open(str(path), flags, mode)


def _secure_create_tmp_file(
    parent_dir: Path,
    base_name: str,
    *,
    prefix: str = "",
    suffix: str = "",
) -> Tuple[Path, BinaryIO]:
    parent_dir = parent_dir.resolve()
    if not parent_dir.is_dir():
        raise EncryptorError(f"Internal: temp parent is not a directory: {parent_dir}")

    for _ in range(128):
        token = _random_token(8)
        name = f"{prefix}{base_name}{suffix}.{token}"
        tmp_path = parent_dir / name
        try:
            fd = _secure_open_exclusive(tmp_path, mode=0o600 if os.name == "posix" else 0o666)
        except FileExistsError:
            continue
        except OSError as ex:
            raise EncryptorError(f"Failed to create temporary file in {parent_dir}: {ex}") from ex

        try:
            f = os.fdopen(fd, "wb", closefd=True)
        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass
            _unlink_best_effort(tmp_path)
            raise
        return tmp_path, f

    raise EncryptorError(f"Failed to create a unique temporary file in {parent_dir} (too many collisions).")


def _atomic_replace_file(tmp_path: Path, final_path: Path) -> None:
    os.replace(tmp_path, final_path)
    _fsync_dir_best_effort(final_path.parent)


# =========================
# Path validation / joining
# =========================

_WINDOWS_DEVICE_NAMES = {
    "con", "prn", "aux", "nul",
    *{f"com{i}" for i in range(1, 10)},
    *{f"lpt{i}" for i in range(1, 10)},
}
_WINDOWS_INVALID_CHARS = set('<>:"/\\|?*')


def _is_windows_reserved_device_segment(seg: str) -> bool:
    base = seg.split(".", 1)[0]
    return base.casefold() in _WINDOWS_DEVICE_NAMES


def validate_container_relpath(path_str: str) -> PurePosixPath:
    """
    Path traversal defense:
    - must be relative posix path
    - no absolute, no drive letters/UNC, no '..', no backslashes
    - Windows hardening:
      * reject invalid filename chars: < > : " / \\ | ? *
      * reject segments ending with ' ' or '.'
      * reject reserved device names (CON, NUL, COM1.., LPT1.. etc), case-insensitive
      * reject drive-like segments (X:)
    """
    if not path_str:
        raise FormatError("Invalid empty path in container.")
    if "\x00" in path_str:
        raise FormatError("Invalid NUL byte in path.")
    if "\\" in path_str:
        raise FormatError("Invalid path separator in container path (backslash).")
    if os.name == "nt" and _is_windows_drive_path(path_str):
        raise FormatError("Invalid path in container (drive/UNC path).")

    p = PurePosixPath(path_str)
    if p.is_absolute():
        raise FormatError("Invalid absolute path in container.")

    for part in p.parts:
        if part in ("..", ".", ""):
            raise FormatError("Invalid path traversal component in container path.")
        if os.name == "nt":
            if any((ch in _WINDOWS_INVALID_CHARS) for ch in part):
                raise FormatError("Invalid character in path segment for Windows extraction.")
            if part.endswith(" ") or part.endswith("."):
                raise FormatError("Invalid path segment for Windows (trailing space/dot).")
            if _is_windows_reserved_device_segment(part):
                raise FormatError("Invalid Windows device name in path segment.")
            if len(part) >= 2 and part[1] == ":" and part[0].isalpha():
                raise FormatError("Invalid drive-like path segment in container.")
    return p


def safe_join(base_dir: Path, rel_posix: PurePosixPath) -> Path:
    """
    Join base_dir with rel_posix safely (no traversal).
    Works with both relative and absolute base_dir on Windows.

    Windows hardening: prevent re-anchoring / base ignoring:
    - candidate must not change drive/anchor relative to base_dir
    - then enforce sandbox via resolve()+relative_to()
    """
    candidate = base_dir.joinpath(*rel_posix.parts)

    if os.name == "nt":
        base_drive = base_dir.drive
        cand_drive = candidate.drive
        if cand_drive:
            if not base_drive or cand_drive.lower() != base_drive.lower():
                raise FormatError("Unsafe destination path (drive re-anchoring) detected.")
        base_anchor = base_dir.anchor
        cand_anchor = candidate.anchor
        if base_anchor:
            if not cand_anchor or cand_anchor.lower() != base_anchor.lower():
                raise FormatError("Unsafe destination path (anchor re-anchoring) detected.")
        else:
            if cand_anchor:
                raise FormatError("Unsafe destination path (unexpected absolute/anchored path) detected.")

    base_real = base_dir.resolve()
    cand_real = candidate.resolve()

    try:
        cand_real.relative_to(base_real)
    except ValueError as ex:
        raise FormatError("Path traversal detected while extracting.") from ex

    return candidate


def _ensure_no_symlink_components(base_dir: Path, target_dir: Path) -> None:
    """
    Best-effort hardening: ensure no component on the path from base_dir to target_dir is a symlink.
    Uses is_symlink() directly (not exists()) so dangling symlinks are detected too.
    """
    try:
        if base_dir.is_symlink():
            raise FormatError("Output directory must not be a symlink.")
    except OSError as ex:
        raise EncryptorError(f"Failed to stat output directory: {base_dir} ({ex})") from ex

    current = base_dir
    try:
        rel = target_dir.relative_to(base_dir)
        parts = rel.parts
    except ValueError:
        base_real = base_dir.resolve()
        target_real = target_dir.resolve()
        try:
            rel = target_real.relative_to(base_real)
        except ValueError as ex:
            raise FormatError("Path traversal detected while extracting.") from ex
        current = base_real
        parts = rel.parts

    for part in parts:
        current = current / part
        try:
            if current.is_symlink():
                raise FormatError("Symlink component in output path is not allowed.")
        except OSError as ex:
            raise EncryptorError(f"Failed to stat output path component: {current} ({ex})") from ex


# =========================
# Keyfile handling
# =========================

def read_keyfile(path: Path) -> bytes:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as ex:
        raise SecretError(f"Keyfile not found: {path}") from ex
    except OSError as ex:
        raise SecretError(f"Failed to read keyfile: {path} ({ex})") from ex

    lines = raw.splitlines()
    non_empty = [ln.strip() for ln in lines if ln.strip() != ""]
    if len(non_empty) != 2:
        raise SecretError("Invalid keyfile format: expected exactly 2 non-empty lines.")
    if non_empty[0] != KEYFILE_MAGIC_LINE:
        raise SecretError("Invalid keyfile: bad magic line.")
    try:
        key = base64.b64decode(non_empty[1], validate=True)
    except Exception as ex:
        raise SecretError("Invalid keyfile: base64 decode failed.") from ex
    if len(key) != KEY_LEN:
        raise SecretError("Invalid keyfile: expected 32 bytes key after base64 decode.")
    return key


def _chmod_600_if_possible(path: Path) -> None:
    try:
        if os.name == "posix":
            os.chmod(path, 0o600)
    except Exception:
        pass


def _write_bytes_secure_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = _secure_open_exclusive(path, mode=0o600 if os.name == "posix" else 0o666)
    except FileExistsError as ex:
        raise SecretError(f"Keyfile already exists and overwriting is forbidden: {path}") from ex
    except OSError as ex:
        raise SecretError(f"Failed to create keyfile: {path} ({ex})") from ex

    try:
        with os.fdopen(fd, "wb", closefd=True) as f:
            f.write(data)
            _fsync_fileobj_best_effort(f)
    except OSError as ex:
        _unlink_best_effort(path)
        raise SecretError(f"Failed to write keyfile: {path} ({ex})") from ex

    _chmod_600_if_possible(path)


def _write_bytes_atomic_replace(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path, tmp_f = _secure_create_tmp_file(
        path.parent,
        base_name=path.name,
        prefix=".",
        suffix=".keytmp",
    )
    try:
        with tmp_f:
            tmp_f.write(data)
            _fsync_fileobj_best_effort(tmp_f)
        _atomic_replace_file(tmp_path, path)
    except OSError as ex:
        _unlink_best_effort(tmp_path)
        raise SecretError(f"Failed to overwrite keyfile: {path} ({ex})") from ex

    _chmod_600_if_possible(path)


def write_keyfile(path: Path, key: bytes, overwrite: bool = False) -> None:
    if len(key) != KEY_LEN:
        raise ValueError("Internal: key length must be 32 bytes.")
    content = f"{KEYFILE_MAGIC_LINE}\n{base64.b64encode(key).decode('ascii')}\n".encode("utf-8")

    if path.exists() and not overwrite:
        raise SecretError(
            f"Keyfile already exists and overwriting is forbidden: {path}\n"
            f"Use a different --keyfile path (or --overwrite-keyfile if you really want to replace it)."
        )
    if not overwrite:
        _write_bytes_secure_exclusive(path, content)
    else:
        _write_bytes_atomic_replace(path, content)


def ensure_keyfile(path: Path, overwrite_keyfile: bool = False) -> bytes:
    if path.exists():
        if overwrite_keyfile:
            key = os.urandom(KEY_LEN)
            write_keyfile(path, key, overwrite=True)
            return key
        return read_keyfile(path)

    key = os.urandom(KEY_LEN)
    write_keyfile(path, key, overwrite=False)
    return key


# =========================
# KDF / Keys / MAC
# =========================

def scrypt_derive(password: str, salt: bytes, params: ScryptParams, length: int) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password must be str")
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=params.n,
        r=params.r,
        p=params.p,
    )
    return kdf.derive(password.encode("utf-8"))


def hkdf_derive(ikm: bytes, salt: bytes, length: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(ikm)


def derive_master_seed(
    mode_id: ModeId,
    salt: bytes,
    scrypt_params: Optional[ScryptParams],
    keyfile_key: Optional[bytes],
    password: Optional[str],
) -> bytes:
    if len(salt) < 8:
        raise SecretError("Internal: salt too short.")

    if mode_id == ModeId.PASSWORD:
        if password is None:
            raise SecretError("Password required but not provided.")
        if scrypt_params is None:
            raise SecretError("Internal: scrypt params missing for password mode.")
        return scrypt_derive(password, salt, scrypt_params, MASTER_SEED_LEN)

    if mode_id == ModeId.KEY:
        if keyfile_key is None:
            raise SecretError("Keyfile required but not provided.")
        return hkdf_derive(keyfile_key, salt=salt, length=MASTER_SEED_LEN)

    if mode_id == ModeId.BOTH:
        if password is None:
            raise SecretError("Password required but not provided.")
        if keyfile_key is None:
            raise SecretError("Keyfile required but not provided.")
        if scrypt_params is None:
            raise SecretError("Internal: scrypt params missing for both mode.")
        pw_seed = scrypt_derive(password, salt, scrypt_params, length=32)
        return hkdf_derive(keyfile_key, salt=pw_seed, length=MASTER_SEED_LEN)

    raise SecretError("Unsupported mode in container.")


def split_seed(master_seed: bytes) -> Tuple[bytes, bytes]:
    if len(master_seed) != MASTER_SEED_LEN:
        raise ValueError("Internal: master_seed length mismatch.")
    return master_seed[:32], master_seed[32:]


def compute_header_hmac(mac_key: bytes, header_without_hmac: bytes) -> bytes:
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(header_without_hmac)
    return h.finalize()


# =========================
# Header encode/decode
# =========================

def build_header_without_hmac(
    cipher_id: CipherId,
    mode_id: ModeId,
    salt: bytes,
    scrypt_params: Optional[ScryptParams],
    chunk_size: int,
) -> bytes:
    if len(salt) != 16:
        raise EncryptorError("Internal: salt must be 16 bytes for v1.")
    _ensure_chunk_size_ok(chunk_size)

    parts = []
    parts.append(struct.pack("<4sHBBH", MAGIC, VERSION, int(cipher_id), int(mode_id), len(salt)))
    parts.append(salt)

    if mode_id in (ModeId.PASSWORD, ModeId.BOTH):
        if scrypt_params is None:
            raise EncryptorError("Internal: scrypt params required for password/both.")
        parts.append(struct.pack("<III", scrypt_params.n, scrypt_params.r, scrypt_params.p))

    parts.append(struct.pack("<I", chunk_size))
    return b"".join(parts)


def write_header(f: BinaryIO, header_without_hmac: bytes, header_hmac: bytes) -> None:
    if len(header_hmac) != HMAC_LEN:
        raise EncryptorError("Internal: header HMAC must be 32 bytes.")
    f.write(header_without_hmac)
    f.write(struct.pack("<H", len(header_hmac)))
    f.write(header_hmac)


def read_header(f: BinaryIO) -> Header:
    fixed = read_exact(f, 4 + 2 + 1 + 1 + 2)
    magic, ver, cipher_id_u8, mode_id_u8, salt_len = struct.unpack("<4sHBBH", fixed)

    if magic != MAGIC:
        raise FormatError("Not an ENCR container (bad magic).")
    if ver != VERSION:
        raise FormatError(f"Unsupported container version: {ver}")
    try:
        cipher_id = CipherId(cipher_id_u8)
    except ValueError as ex:
        raise FormatError(f"Unsupported cipher_id in container: {cipher_id_u8}") from ex
    try:
        mode_id = ModeId(mode_id_u8)
    except ValueError as ex:
        raise FormatError(f"Unsupported mode_id in container: {mode_id_u8}") from ex

    if salt_len > 1024:
        raise FormatError("Unreasonable salt_len in header.")
    salt = read_exact(f, salt_len)
    if salt_len != 16:
        raise FormatError(f"Unsupported salt length for v1: {salt_len}")

    scrypt_params: Optional[ScryptParams] = None
    header_bytes = bytearray()
    header_bytes += fixed
    header_bytes += salt

    if mode_id in (ModeId.PASSWORD, ModeId.BOTH):
        raw = read_exact(f, 12)
        n, r, p = struct.unpack("<III", raw)

        if n < 2 or (n & (n - 1)) != 0:
            raise FormatError("Invalid scrypt N in header (must be power of two).")
        if r < 1 or p < 1:
            raise FormatError("Invalid scrypt r/p in header.")
        if n > MAX_SCRYPT_N:
            raise FormatError(f"Unreasonable scrypt N in header (max {MAX_SCRYPT_N}).")
        if r > MAX_SCRYPT_R:
            raise FormatError(f"Unreasonable scrypt r in header (max {MAX_SCRYPT_R}).")
        if p > MAX_SCRYPT_P:
            raise FormatError(f"Unreasonable scrypt p in header (max {MAX_SCRYPT_P}).")

        try:
            mem = 128 * r * n
        except OverflowError:
            raise FormatError("Unreasonable scrypt parameters in header (overflow).")
        if mem > MAX_SCRYPT_MEM:
            raise FormatError(
                f"Unreasonable scrypt parameters in header (estimated memory {mem} bytes exceeds limit {MAX_SCRYPT_MEM})."
            )

        scrypt_params = ScryptParams(n=n, r=r, p=p)
        header_bytes += raw

    raw_chunk = read_exact(f, 4)
    (chunk_size,) = struct.unpack("<I", raw_chunk)
    _ensure_chunk_size_ok(chunk_size)
    header_bytes += raw_chunk

    header_without_hmac = bytes(header_bytes)
    header_hash = sha256(header_without_hmac)

    raw_hlen = read_exact(f, 2)
    (hlen,) = struct.unpack("<H", raw_hlen)
    if hlen != HMAC_LEN:
        raise FormatError(f"Unsupported header_hmac_len: {hlen} (expected {HMAC_LEN})")
    stored_hmac = read_exact(f, hlen)

    return Header(
        version=ver,
        cipher_id=cipher_id,
        mode_id=mode_id,
        salt=salt,
        scrypt_params=scrypt_params,
        chunk_size=chunk_size,
        header_without_hmac=header_without_hmac,
        header_hash=header_hash,
        stored_hmac=stored_hmac,
    )


# =========================
# AAD / AEAD
# =========================

def build_aad_prefix(header: Header, rel_path_posix: str, orig_size: int) -> bytes:
    path_bytes = rel_path_posix.encode("utf-8")
    if len(path_bytes) > 65535:
        raise EncryptorError("Internal: path too long for encoding.")
    if orig_size < 0:
        raise EncryptorError("Internal: negative size.")

    aad = bytearray()
    aad += MAGIC
    aad += struct.pack("<H", header.version)
    aad += struct.pack("<B", int(header.cipher_id))
    aad += struct.pack("<B", int(header.mode_id))
    aad += header.header_hash
    aad += struct.pack("<H", len(path_bytes))
    aad += path_bytes
    aad += struct.pack("<Q", orig_size)
    return bytes(aad)


def build_aad(header: Header, rel_path_posix: str, orig_size: int, chunk_index: int) -> bytes:
    if chunk_index < 0 or chunk_index > COUNTER_MAX:
        raise EncryptorError("Internal: invalid chunk index.")
    return build_aad_prefix(header, rel_path_posix, orig_size) + struct.pack("<I", chunk_index)


def make_nonce(prefix8: bytes, counter: int) -> bytes:
    if len(prefix8) != 8:
        raise EncryptorError("Internal: nonce prefix must be 8 bytes.")
    if not (0 <= counter <= COUNTER_MAX):
        raise EncryptorError("Chunk counter overflow.")
    return prefix8 + struct.pack(">I", counter)  # counter big-endian


def get_aead(cipher_id: CipherId, enc_key: bytes):
    if len(enc_key) != 32:
        raise EncryptorError("Internal: enc_key must be 32 bytes.")
    if cipher_id == CipherId.AESGCM:
        return AESGCM(enc_key)
    if cipher_id == CipherId.CHACHA20POLY1305:
        return ChaCha20Poly1305(enc_key)
    raise EncryptorError("Unsupported cipher.")


# =========================
# File collection (encrypt)
# =========================

def _iter_files_in_dir(root: Path) -> Iterable[Path]:
    # os.walk uses scandir internally on modern Python; keep it for correctness and simplicity.
    for dirpath, _, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            yield Path(dirpath) / name


def _ensure_safe_rel_parts(parts: Sequence[str]) -> None:
    for part in parts:
        if part in ("", ".", ".."):
            raise EncryptorError(f"Refusing unsafe path component during encryption: {part!r}")


def _suffix_name(name: str, n: int) -> str:
    if n <= 1:
        return name
    p = Path(name)
    stem = p.stem
    suf = p.suffix
    if stem == "" and suf == "":
        return f"{name}__{n}"
    if suf:
        return f"{stem}__{n}{suf}"
    return f"{name}__{n}"


def _unique_root_name(base: str, used_roots: set[str]) -> str:
    if base not in used_roots:
        return base
    i = 2
    while True:
        cand = _suffix_name(base, i)
        if cand not in used_roots:
            return cand
        i += 1
        if i > 1_000_000:
            raise EncryptorError("Unable to generate unique root name (too many collisions).")


def collect_files(
    inputs: Sequence[Path],
    follow_symlinks: bool,
    symlink_targets_within_root: bool,
) -> List[Tuple[Path, str]]:
    if not inputs:
        raise EncryptorError("No input paths provided.")
    if symlink_targets_within_root and not follow_symlinks:
        raise EncryptorError("--symlink-targets-within-root requires --follow-symlinks.")

    used_roots: set[str] = set()
    roots: List[Tuple[Path, Path, str]] = []  # (raw_input_path, resolved_abs_input, unique_root_name)

    for raw_p in inputs:
        p = raw_p.expanduser()
        try:
            abs_p = p.resolve(strict=True)
        except FileNotFoundError as ex:
            raise EncryptorError(f"Input path not found: {raw_p}") from ex
        except OSError as ex:
            raise EncryptorError(f"Failed to access input path: {raw_p} ({ex})") from ex

        if p.is_symlink() and not follow_symlinks:
            raise EncryptorError(
                f"Refusing to encrypt symlink input (safe default): {raw_p}\n"
                f"Use --follow-symlinks to allow encrypting symlink targets."
            )

        if not (abs_p.is_file() or abs_p.is_dir()):
            raise EncryptorError(f"Unsupported input type (not a file/dir): {raw_p}")

        base = p.name or abs_p.name
        if base in ("", ".", ".."):
            raise EncryptorError(f"Unsupported input path (cannot derive a safe basename): {raw_p}")

        _ensure_safe_rel_parts([base])

        unique = _unique_root_name(base, used_roots)
        used_roots.add(unique)

        _ensure_safe_rel_parts([unique])
        validate_container_relpath(unique)

        roots.append((p, abs_p, unique))

    files: List[Tuple[Path, str]] = []

    for raw_p, abs_p, root_name in roots:
        if abs_p.is_dir():
            root_scope = abs_p
            for fp in _iter_files_in_dir(abs_p):
                try:
                    is_link = fp.is_symlink()
                except OSError as ex:
                    raise EncryptorError(f"Failed to stat file: {fp} ({ex})") from ex

                if is_link and not follow_symlinks:
                    raise EncryptorError(
                        f"Refusing to encrypt symlink file (safe default): {fp}\n"
                        f"Use --follow-symlinks to allow encrypting symlink targets."
                    )

                try:
                    abs_fp = fp.resolve(strict=True)
                except FileNotFoundError:
                    continue
                except OSError as ex:
                    raise EncryptorError(f"Failed to access file: {fp} ({ex}) from ex") from ex

                if not abs_fp.is_file():
                    continue

                if is_link and follow_symlinks and symlink_targets_within_root:
                    try:
                        abs_fp.relative_to(root_scope)
                    except ValueError as ex:
                        raise EncryptorError(
                            f"Symlink target escapes input root (blocked by --symlink-targets-within-root): {fp}"
                        ) from ex

                try:
                    rel_inside = fp.relative_to(abs_p)
                except ValueError as ex:
                    raise EncryptorError(f"Internal: file escaped its root unexpectedly: {fp}") from ex

                rel_parts = (root_name,) + tuple(PurePosixPath(rel_inside.as_posix()).parts)
                _ensure_safe_rel_parts(rel_parts)
                rel_posix = PurePosixPath(*rel_parts).as_posix()
                validate_container_relpath(rel_posix)
                files.append((abs_fp, rel_posix))

        elif abs_p.is_file():
            try:
                is_link = raw_p.is_symlink()
            except OSError as ex:
                raise EncryptorError(f"Failed to stat input file: {raw_p} ({ex})") from ex

            if is_link and not follow_symlinks:
                raise EncryptorError(
                    f"Refusing to encrypt symlink file (safe default): {raw_p}\n"
                    f"Use --follow-symlinks to allow encrypting symlink targets."
                )

            if is_link and follow_symlinks and symlink_targets_within_root:
                try:
                    scope = raw_p.expanduser().parent.resolve(strict=True)
                except OSError as ex:
                    raise EncryptorError(f"Failed to resolve symlink scope for {raw_p}: {ex}") from ex
                try:
                    abs_p.relative_to(scope)
                except ValueError as ex:
                    raise EncryptorError(
                        f"Symlink target escapes input directory (blocked by --symlink-targets-within-root): {raw_p}"
                    ) from ex

            validate_container_relpath(root_name)
            files.append((abs_p, root_name))
        else:
            raise EncryptorError(f"Unsupported input type (not a file/dir): {raw_p}")

    # Ensure no duplicate container paths would be produced
    seen_rel: set[str] = set()
    for _, rel in files:
        key = rel.casefold() if os.name == "nt" else rel
        if key in seen_rel:
            raise EncryptorError(f"Duplicate container path would occur: {rel}")
        seen_rel.add(key)

    files.sort(key=lambda t: t[1])
    return files


# =========================
# Container records IO
# =========================

def write_record_file_begin(f: BinaryIO, rel_path: str, orig_size: int, nonce_prefix: bytes) -> None:
    try:
        path_b = rel_path.encode("utf-8")
    except UnicodeEncodeError as ex:
        raise EncryptorError(f"Path is not valid UTF-8 for container: {rel_path!r}") from ex

    if len(path_b) > 65535:
        raise EncryptorError("Path too long to store in container.")
    if len(path_b) > MAX_PATH_LEN:
        raise EncryptorError(f"Path too long (>{MAX_PATH_LEN}): {rel_path}")
    f.write(struct.pack("<B", int(RecordType.FILE_BEGIN)))
    f.write(struct.pack("<H", len(path_b)))
    f.write(path_b)
    f.write(struct.pack("<Q", orig_size))
    f.write(nonce_prefix)


def write_record_file_end(f: BinaryIO) -> None:
    f.write(struct.pack("<B", int(RecordType.FILE_END)))


def write_record_eof(f: BinaryIO) -> None:
    f.write(struct.pack("<B", int(RecordType.EOF)))


def write_chunk_record(f: BinaryIO, chunk_index: int, plain_len: int, ciphertext: bytes) -> None:
    if chunk_index < 0 or chunk_index > COUNTER_MAX:
        raise EncryptorError("Chunk counter overflow.")
    if plain_len < 0 or plain_len > 0xFFFFFFFF:
        raise EncryptorError("Invalid plain_len.")
    if len(ciphertext) > 0xFFFFFFFF:
        raise EncryptorError("cipher_len too large.")
    f.write(struct.pack("<III", chunk_index, plain_len, len(ciphertext)))
    f.write(ciphertext)


# =========================
# Encrypt
# =========================

def encrypt_container(
    input_paths: Sequence[Path],
    out_path: Path,
    cipher_id: CipherId,
    mode_id: ModeId,
    keyfile_path: Optional[Path],
    password: Optional[str],
    chunk_size: int,
    overwrite: bool,
    overwrite_keyfile: bool,
    follow_symlinks: bool,
    symlink_targets_within_root: bool,
) -> None:
    _ensure_chunk_size_ok(chunk_size)

    if mode_id == ModeId.PASSWORD:
        if keyfile_path is not None:
            raise SecretError("Mode=PASSWORD: --keyfile is not allowed.")
        if password is None:
            password = getpass("Password: ")
        if password == "":
            raise SecretError("Empty password is not allowed.")
        keyfile_key = None
        scrypt_params = ScryptParams(SCRYPT_N, SCRYPT_R, SCRYPT_P)

    elif mode_id == ModeId.KEY:
        if password is not None:
            raise SecretError("Mode=KEY: --password is not allowed.")
        if keyfile_path is None:
            raise SecretError("Mode=KEY: --keyfile is required.")
        keyfile_key = ensure_keyfile(keyfile_path, overwrite_keyfile=overwrite_keyfile)
        scrypt_params = None

    elif mode_id == ModeId.BOTH:
        if keyfile_path is None:
            raise SecretError("Mode=BOTH: --keyfile is required.")
        if password is None:
            password = getpass("Password: ")
        if password == "":
            raise SecretError("Empty password is not allowed.")
        keyfile_key = ensure_keyfile(keyfile_path, overwrite_keyfile=overwrite_keyfile)
        scrypt_params = ScryptParams(SCRYPT_N, SCRYPT_R, SCRYPT_P)

    else:
        raise SecretError("Unsupported mode.")

    files = collect_files(
        input_paths,
        follow_symlinks=follow_symlinks,
        symlink_targets_within_root=symlink_targets_within_root,
    )
    if not files:
        raise EncryptorError("No files found to encrypt.")

    if out_path.exists() and not overwrite:
        raise EncryptorError(f"Output container already exists: {out_path} (use --overwrite to replace).")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    salt = os.urandom(16)

    master_seed = derive_master_seed(
        mode_id=mode_id,
        salt=salt,
        scrypt_params=scrypt_params,
        keyfile_key=keyfile_key,
        password=password,
    )
    enc_key, mac_key = split_seed(master_seed)

    header_wo = build_header_without_hmac(
        cipher_id=cipher_id,
        mode_id=mode_id,
        salt=salt,
        scrypt_params=scrypt_params,
        chunk_size=chunk_size,
    )
    header_mac = compute_header_hmac(mac_key, header_wo)
    header_hash = sha256(header_wo)

    header = Header(
        version=VERSION,
        cipher_id=cipher_id,
        mode_id=mode_id,
        salt=salt,
        scrypt_params=scrypt_params,
        chunk_size=chunk_size,
        header_without_hmac=header_wo,
        header_hash=header_hash,
        stored_hmac=header_mac,
    )

    aead = get_aead(cipher_id, enc_key)

    tmp_path, tmp_f = _secure_create_tmp_file(
        out_path.parent,
        base_name=out_path.name,
        prefix=".",
        suffix=".contmp",
    )

    try:
        with tmp_f as out_f:
            write_header(out_f, header_wo, header_mac)

            for abs_fp, rel_path in files:
                st = abs_fp.stat()
                orig_size = int(st.st_size)
                nonce_prefix = os.urandom(8)

                write_record_file_begin(out_f, rel_path, orig_size, nonce_prefix)

                aad_prefix = build_aad_prefix(header, rel_path, orig_size)

                chunk_index = 0
                written_plain = 0

                with open(abs_fp, "rb") as in_f:
                    while True:
                        plain = in_f.read(chunk_size)
                        if plain == b"":
                            if orig_size == 0 and chunk_index == 0:
                                plain = b""
                            else:
                                break

                        if chunk_index > COUNTER_MAX:
                            raise EncryptorError("Chunk counter overflow (too many chunks).")
                        nonce = make_nonce(nonce_prefix, chunk_index)
                        aad = aad_prefix + struct.pack("<I", chunk_index)
                        ct = aead.encrypt(nonce, plain, aad)

                        if len(ct) != len(plain) + 16:
                            raise EncryptorError("Internal: unexpected AEAD ciphertext length.")

                        write_chunk_record(out_f, chunk_index, len(plain), ct)

                        written_plain += len(plain)
                        chunk_index += 1

                        if orig_size == 0:
                            break

                if written_plain != orig_size:
                    raise EncryptorError(
                        f"Size mismatch while encrypting {abs_fp}: expected {orig_size}, read {written_plain}"
                    )

                write_record_file_end(out_f)

            write_record_eof(out_f)
            _fsync_fileobj_best_effort(out_f)

        _atomic_replace_file(tmp_path, out_path)

    except Exception:
        _unlink_best_effort(tmp_path)
        raise


# =========================
# Decrypt
# =========================

def print_mode_requirements(mode_id: ModeId) -> None:
    if mode_id == ModeId.KEY:
        print("Container mode: KEY (keyfile required)")
    elif mode_id == ModeId.PASSWORD:
        print("Container mode: PASSWORD (password required)")
    elif mode_id == ModeId.BOTH:
        print("Container mode: BOTH (keyfile + password required)")
    else:
        print("Container mode: UNKNOWN")


def _enforce_decrypt_secret_strictness(
    mode_id: ModeId,
    keyfile_path: Optional[Path],
    password: Optional[str],
) -> Tuple[Optional[Path], Optional[str]]:
    if mode_id == ModeId.PASSWORD:
        if keyfile_path is not None:
            raise SecretError(
                "Container mode=PASSWORD: --keyfile was provided but must NOT be provided for this container."
            )
        if password is None:
            password = getpass("Password: ")
        if password == "":
            raise SecretError("Empty password is not allowed.")
        return None, password

    if mode_id == ModeId.KEY:
        if password is not None:
            raise SecretError(
                "Container mode=KEY: --password was provided but must NOT be provided for this container."
            )
        if keyfile_path is None:
            raise SecretError("Container mode=KEY: --keyfile is required.")
        return keyfile_path, None

    if mode_id == ModeId.BOTH:
        if keyfile_path is None:
            raise SecretError("Container mode=BOTH: --keyfile is required.")
        if password is None:
            password = getpass("Password: ")
        if password == "":
            raise SecretError("Empty password is not allowed.")
        return keyfile_path, password

    raise SecretError("Unsupported mode in container.")


def decrypt_container(
    container_path: Path,
    out_dir: Path,
    keyfile_path: Optional[Path],
    password: Optional[str],
    overwrite: bool,
) -> None:
    try:
        f = open(container_path, "rb")
    except OSError as ex:
        raise EncryptorError(f"Failed to open container: {container_path} ({ex})") from ex

    with f:
        try:
            header = read_header(f)

            print_mode_requirements(header.mode_id)

            keyfile_path, password = _enforce_decrypt_secret_strictness(
                header.mode_id, keyfile_path, password
            )

            keyfile_key = None
            if header.mode_id in (ModeId.KEY, ModeId.BOTH):
                assert keyfile_path is not None
                keyfile_key = read_keyfile(keyfile_path)

            master_seed = derive_master_seed(
                mode_id=header.mode_id,
                salt=header.salt,
                scrypt_params=header.scrypt_params,
                keyfile_key=keyfile_key,
                password=password,
            )
            enc_key, mac_key = split_seed(master_seed)

            expected_hmac = compute_header_hmac(mac_key, header.header_without_hmac)
            if not compare_digest(expected_hmac, header.stored_hmac):
                raise SecretError("Header HMAC mismatch: wrong secrets or corrupted container.")

            # Output dir policy: existing dir allowed; overwrite applies only to files.
            if out_dir.exists():
                if not out_dir.is_dir():
                    raise EncryptorError(f"--out must be a directory path, got existing non-dir: {out_dir}")
                try:
                    if out_dir.is_symlink():
                        raise EncryptorError("--out directory must not be a symlink.")
                except OSError as ex:
                    raise EncryptorError(f"Failed to stat --out directory: {out_dir} ({ex})") from ex
            else:
                out_dir.mkdir(parents=True, exist_ok=False)

            aead = get_aead(header.cipher_id, enc_key)
            seen_dest: set[str] = set()

            while True:
                rt_raw = f.read(1)
                if rt_raw == b"":
                    raise FormatError("Unexpected EOF: missing EOF record.")
                (rt,) = struct.unpack("<B", rt_raw)

                if rt == int(RecordType.EOF):
                    break

                if rt != int(RecordType.FILE_BEGIN):
                    raise FormatError(f"Unexpected record_type: {rt} (expected FILE_BEGIN or EOF)")

                path_len_raw = read_exact(f, 2)
                (path_len,) = struct.unpack("<H", path_len_raw)
                if path_len > MAX_PATH_LEN:
                    raise FormatError(f"path_len too large: {path_len} (limit {MAX_PATH_LEN})")

                path_b = read_exact(f, path_len)
                try:
                    rel_path_str = path_b.decode("utf-8")
                except UnicodeDecodeError as ex:
                    raise FormatError("Invalid UTF-8 path in container.") from ex

                rel_posix = validate_container_relpath(rel_path_str)

                # Collision detection (Windows-aware): reflect real destination normalization.
                final_path_for_key = safe_join(out_dir, rel_posix)
                dest_key = os.path.normcase(str(final_path_for_key)) if os.name == "nt" else str(final_path_for_key)
                if dest_key in seen_dest:
                    raise FormatError(f"Duplicate destination path in container is not allowed: {rel_path_str}")
                seen_dest.add(dest_key)

                orig_size_raw = read_exact(f, 8)
                (orig_size,) = struct.unpack("<Q", orig_size_raw)

                nonce_prefix = read_exact(f, 8)

                aad_prefix = build_aad_prefix(header, rel_path_str, orig_size)

                expected_chunk = 0
                total_written = 0

                final_path = final_path_for_key
                final_parent = final_path.parent

                tmp_path: Optional[Path] = None
                tmp_fh: Optional[BinaryIO] = None
                created_dirs = False
                created_file = False

                try:
                    while True:
                        chunk_hdr = read_exact(f, 12)
                        chunk_index, plain_len, cipher_len = struct.unpack("<III", chunk_hdr)

                        if chunk_index != expected_chunk:
                            raise FormatError(
                                f"Unexpected chunk_index for {rel_path_str}: got {chunk_index}, expected {expected_chunk}"
                            )
                        expected_chunk += 1

                        if plain_len > header.chunk_size:
                            raise FormatError(
                                f"plain_len {plain_len} exceeds chunk_size {header.chunk_size} for {rel_path_str}"
                            )

                        if cipher_len != plain_len + 16:
                            raise FormatError(
                                f"Invalid cipher_len for {rel_path_str}: got {cipher_len}, expected {plain_len + 16}"
                            )

                        remaining = orig_size - total_written
                        if orig_size == 0:
                            if chunk_index != 0:
                                raise FormatError(f"Empty file must start with chunk_index=0 for {rel_path_str}")
                            if plain_len != 0:
                                raise FormatError(f"Empty file must have plain_len=0 for {rel_path_str}")
                        else:
                            if remaining > 0 and plain_len == 0:
                                raise FormatError(f"Zero-length chunk is not allowed for non-empty file: {rel_path_str}")
                            if plain_len > remaining:
                                raise FormatError(
                                    f"plain_len {plain_len} exceeds remaining bytes {remaining} for {rel_path_str}"
                                )

                        ciphertext = read_exact(f, cipher_len)

                        nonce = make_nonce(nonce_prefix, chunk_index)
                        aad = aad_prefix + struct.pack("<I", chunk_index)

                        try:
                            plaintext = aead.decrypt(nonce, ciphertext, aad)
                        except InvalidTag as ex:
                            raise SecretError(
                                f"InvalidTag while decrypting {rel_path_str}: wrong secrets or corrupted container."
                            ) from ex

                        if len(plaintext) != plain_len:
                            raise FormatError("Decrypted plaintext length mismatch.")

                        # No mkdir/file creation until after first chunk tag validation (we are here => validated).
                        if not created_file:
                            _ensure_no_symlink_components(out_dir, final_parent)

                            if not created_dirs:
                                final_parent.mkdir(parents=True, exist_ok=True)
                                created_dirs = True

                            # Recompute destination and re-check symlink chain after mkdir (defense-in-depth)
                            final_path = safe_join(out_dir, rel_posix)
                            final_parent = final_path.parent
                            _ensure_no_symlink_components(out_dir, final_parent)

                            if final_path.exists():
                                if final_path.is_dir():
                                    raise EncryptorError(f"Refusing to overwrite existing directory: {final_path}")
                                if not overwrite:
                                    raise EncryptorError(
                                        f"Refusing to overwrite existing file: {final_path} (use --overwrite)"
                                    )

                            tmp_path, tmp_fh = _secure_create_tmp_file(
                                final_parent,
                                base_name=final_path.name,
                                prefix=".",
                                suffix=".part",
                            )
                            created_file = True

                        assert tmp_fh is not None
                        assert tmp_path is not None

                        if orig_size > 0 and total_written < orig_size and plain_len == 0:
                            raise FormatError(f"Zero-length chunk without progress for {rel_path_str}")

                        if total_written + plain_len > orig_size:
                            raise FormatError(
                                f"Decrypted data exceeds orig_size for {rel_path_str} "
                                f"({total_written + plain_len} > {orig_size})"
                            )

                        tmp_fh.write(plaintext)
                        total_written += plain_len

                        if total_written == orig_size:
                            break

                    end_raw = read_exact(f, 1)
                    (end_rt,) = struct.unpack("<B", end_raw)
                    if end_rt != int(RecordType.FILE_END):
                        raise FormatError(f"Missing FILE_END for {rel_path_str} (got {end_rt})")

                    if total_written != orig_size:
                        raise FormatError(
                            f"File size mismatch for {rel_path_str}: wrote {total_written}, expected {orig_size}"
                        )

                    if tmp_fh is not None:
                        _fsync_fileobj_best_effort(tmp_fh)
                        tmp_fh.close()
                        tmp_fh = None

                    # Should always have a tmp_path once first chunk is processed; keep fallback for robustness.
                    if tmp_path is None:
                        _ensure_no_symlink_components(out_dir, final_parent)
                        final_parent.mkdir(parents=True, exist_ok=True)
                        final_path = safe_join(out_dir, rel_posix)
                        final_parent = final_path.parent
                        _ensure_no_symlink_components(out_dir, final_parent)
                        tmp_path, tmp_fh2 = _secure_create_tmp_file(
                            final_parent,
                            base_name=final_path.name,
                            prefix=".",
                            suffix=".part",
                        )
                        try:
                            with tmp_fh2:
                                _fsync_fileobj_best_effort(tmp_fh2)
                        except Exception:
                            _unlink_best_effort(tmp_path)
                            raise

                    _atomic_replace_file(tmp_path, final_path)

                except Exception:
                    try:
                        if tmp_fh is not None:
                            tmp_fh.close()
                    except Exception:
                        pass
                    if tmp_path is not None:
                        _unlink_best_effort(tmp_path)
                    raise

        except OSError as ex:
            # Avoid misleading "Failed to read container" for filesystem write errors.
            raise EncryptorError(f"I/O error during decryption/extraction: {ex}") from ex


# =========================
# CLI
# =========================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="encryptor.py",
        description="Encrypt/decrypt files and folders into/from a single authenticated container (ENCR v1).",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    g = p.add_mutually_exclusive_group()
    g.add_argument("--encrypt", action="store_true", help="Encrypt (default).")
    g.add_argument("--decrypt", action="store_true", help="Decrypt.")

    p.add_argument(
        "--files",
        nargs="+",
        required=True,
        help=(
            "Encrypt: one or more input paths (files and/or directories). Each input becomes a root in the container.\n"
            "Decrypt: exactly one path to the container."
        ),
    )
    p.add_argument("--out", required=True, help="Encrypt: output container file. Decrypt: output directory.")
    p.add_argument("--overwrite", action="store_true", help="Overwrite existing output container or extracted files.")

    p.add_argument(
        "--cipher",
        choices=["aesgcm", "chacha20poly1305"],
        default=None,
        help="Encrypt-only: AEAD cipher (default aesgcm). Not allowed for decrypt.",
    )
    p.add_argument(
        "--chunk-size",
        type=int,
        default=None,
        help=f"Encrypt-only: chunk size in bytes (default {DEFAULT_CHUNK_SIZE}). Range [{MIN_CHUNK_SIZE}..{MAX_CHUNK_SIZE}].",
    )
    p.add_argument(
        "--mode",
        choices=["key", "password", "both"],
        default=None,
        help="Encrypt-only: secret mode (required for encrypt). Not allowed for decrypt.",
    )

    p.add_argument(
        "--follow-symlinks",
        action="store_true",
        help=(
            "Encrypt-only: allow encrypting symlink FILE targets. By default, symlink inputs/files are refused.\n"
            "Note: symlink directories inside scanned trees are still not followed."
        ),
    )
    p.add_argument(
        "--symlink-targets-within-root",
        action="store_true",
        help=(
            "Encrypt-only (requires --follow-symlinks): require symlink file targets to stay within their input root.\n"
            "This is optional hardening; default is off."
        ),
    )

    p.add_argument("--keyfile", default=None, help="Path to keyfile (required for mode key/both).")
    p.add_argument("--password", default=None, help="Password string (if omitted and required, will prompt).")

    p.add_argument(
        "--overwrite-keyfile",
        action="store_true",
        help="Allow overwriting an existing keyfile (DANGEROUS; may break ability to decrypt old containers).",
    )

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    decrypt = bool(args.decrypt)
    files = [Path(x) for x in args.files]
    out = Path(args.out)

    if decrypt:
        if args.mode is not None:
            raise EncryptorError("--mode is not accepted for decrypt (mode is read from container header).")
        if args.cipher is not None:
            raise EncryptorError("--cipher is not allowed for decrypt (cipher is read from container header).")
        if args.chunk_size is not None:
            raise EncryptorError("--chunk-size is not allowed for decrypt.")
        if args.overwrite_keyfile:
            raise EncryptorError("--overwrite-keyfile is encrypt-only.")
        if args.follow_symlinks:
            raise EncryptorError("--follow-symlinks is encrypt-only.")
        if args.symlink_targets_within_root:
            raise EncryptorError("--symlink-targets-within-root is encrypt-only.")

        if len(files) != 1:
            raise EncryptorError("Decrypt requires exactly one --files path (the container).")

        container_path = files[0]
        keyfile_path = Path(args.keyfile) if args.keyfile is not None else None
        password = args.password if args.password is not None else None

        decrypt_container(
            container_path=container_path,
            out_dir=out,
            keyfile_path=keyfile_path,
            password=password,
            overwrite=bool(args.overwrite),
        )
        return 0

    if args.mode is None:
        raise EncryptorError("Encrypt requires --mode key|password|both.")
    mode_id = ModeId.from_cli(args.mode)

    cipher_id = CipherId.from_cli(args.cipher or DEFAULT_CIPHER)
    chunk_size = int(args.chunk_size) if args.chunk_size is not None else DEFAULT_CHUNK_SIZE
    _ensure_chunk_size_ok(chunk_size)

    keyfile_path = Path(args.keyfile) if args.keyfile is not None else None
    password = args.password if args.password is not None else None

    if args.symlink_targets_within_root and not args.follow_symlinks:
        raise EncryptorError("--symlink-targets-within-root requires --follow-symlinks.")

    encrypt_container(
        input_paths=files,
        out_path=out,
        cipher_id=cipher_id,
        mode_id=mode_id,
        keyfile_path=keyfile_path,
        password=password,
        chunk_size=chunk_size,
        overwrite=bool(args.overwrite),
        overwrite_keyfile=bool(args.overwrite_keyfile),
        follow_symlinks=bool(args.follow_symlinks),
        symlink_targets_within_root=bool(args.symlink_targets_within_root),
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EncryptorError as ex:
        eprint(f"Error: {ex}")
        raise SystemExit(2)
    except KeyboardInterrupt:
        eprint("Interrupted.")
        raise SystemExit(130)
