from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from crypto.signer import SecureKeyHandle, SigningError

# 32-byte dummy key (not a real Stellar secret — safe for unit tests)
_DUMMY_KEY = bytes(range(32))
_DUMMY_HASH = bytes(range(32))


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_rejects_empty_key():
    with pytest.raises(ValueError, match="non-empty"):
        SecureKeyHandle(b"")


# ---------------------------------------------------------------------------
# Context-manager lifecycle
# ---------------------------------------------------------------------------


def test_sign_outside_context_raises():
    handle = SecureKeyHandle(_DUMMY_KEY)
    with pytest.raises(SigningError, match="outside an active signing scope"):
        handle.sign(_DUMMY_HASH)


def test_sign_after_exit_raises():
    handle = SecureKeyHandle(_DUMMY_KEY)
    with handle:
        pass  # scope closes here
    with pytest.raises(SigningError, match="outside an active signing scope"):
        handle.sign(_DUMMY_HASH)


def test_key_wiped_after_exit():
    handle = SecureKeyHandle(_DUMMY_KEY)
    with handle:
        pass
    assert all(b == 0 for b in handle._buf), "Buffer must be zero-wiped on exit"


def test_key_wiped_on_exception():
    handle = SecureKeyHandle(_DUMMY_KEY)
    try:
        with handle:
            raise RuntimeError("simulated error")
    except RuntimeError:
        pass
    assert all(b == 0 for b in handle._buf), "Buffer must be zero-wiped even after exception"


# ---------------------------------------------------------------------------
# sign() validation
# ---------------------------------------------------------------------------


def test_sign_rejects_wrong_hash_length():
    with SecureKeyHandle(_DUMMY_KEY) as handle:
        with pytest.raises(ValueError, match="32 bytes"):
            handle.sign(b"too-short")


# ---------------------------------------------------------------------------
# sign() happy path (requires stellar_sdk or PyNaCl)
# ---------------------------------------------------------------------------


def test_sign_returns_64_bytes():
    pytest.importorskip("nacl", reason="PyNaCl not installed — skipping signing test")
    with SecureKeyHandle(_DUMMY_KEY) as handle:
        sig = handle.sign(_DUMMY_HASH)
    assert isinstance(sig, bytes)
    assert len(sig) == 64
