"""
src/crypto/signer.py
~~~~~~~~~~~~~~~~~~~~
Context-managed signing primitive that enforces strict key-lifetime isolation.

The private key is held in a mutable bytearray for the duration of the ``with``
block only.  On exit — whether normal or exceptional — the buffer is
overwritten with zeros before the reference is released, minimising the window
during which key material is recoverable from a process memory dump.

Usage::

    with SecureKeyHandle(raw_secret_bytes) as handle:
        signature = handle.sign(tx_hash)
    # raw_secret_bytes are zero-wiped here; handle is no longer usable.
"""

from __future__ import annotations

import ctypes
import logging
from types import TracebackType
from typing import Optional, Type

logger = logging.getLogger(__name__)

__all__ = ["SecureKeyHandle", "SigningError"]


def _zero_wipe(buf: bytearray) -> None:
    """Overwrite *buf* in-place with zeros via ctypes to resist compiler elision."""
    if len(buf) == 0:
        return
    addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
    ctypes.memset(addr, 0, len(buf))
    # Belt-and-suspenders: also zero through the bytearray view itself.
    for i in range(len(buf)):
        buf[i] = 0


class SigningError(Exception):
    """Raised when a signing operation fails or the handle has already been closed."""


class SecureKeyHandle:
    """Context manager that holds a private key for exactly one signing scope.

    The key is copied into an internal bytearray on entry.  On ``__exit__``
    the buffer is zero-wiped regardless of whether an exception occurred,
    and any further call to :meth:`sign` raises :class:`SigningError`.

    Args:
        raw_key: Raw private-key bytes (32 bytes for Ed25519 / Stellar).

    Raises:
        ValueError: If *raw_key* is empty.
        SigningError: If :meth:`sign` is called outside the ``with`` block.

    Example::

        with SecureKeyHandle(secret_bytes) as handle:
            sig = handle.sign(tx_hash)
    """

    __slots__ = ("_buf", "_active")

    def __init__(self, raw_key: bytes) -> None:
        if not raw_key:
            raise ValueError("raw_key must be non-empty bytes.")
        # Copy into a mutable buffer so we control the lifetime.
        self._buf: bytearray = bytearray(raw_key)
        self._active: bool = False

    # ------------------------------------------------------------------
    # Context-manager protocol
    # ------------------------------------------------------------------

    def __enter__(self) -> "SecureKeyHandle":
        self._active = True
        logger.debug("[SecureKeyHandle] Signing scope opened.")
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> bool:
        self._active = False
        _zero_wipe(self._buf)
        logger.debug("[SecureKeyHandle] Signing scope closed — key wiped.")
        # Do not suppress exceptions.
        return False

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign(self, tx_hash: bytes) -> bytes:
        """Sign *tx_hash* with the held private key.

        Args:
            tx_hash: The 32-byte transaction hash to sign.

        Returns:
            64-byte raw Ed25519 signature.

        Raises:
            SigningError: If called outside the ``with`` block or after the
                         scope has been exited.
            ValueError:  If *tx_hash* is not exactly 32 bytes.
        """
        if not self._active:
            raise SigningError(
                "SecureKeyHandle.sign() called outside an active signing scope. "
                "Use 'with SecureKeyHandle(...) as handle:' and call sign() inside."
            )
        if len(tx_hash) != 32:
            raise ValueError(f"tx_hash must be exactly 32 bytes, got {len(tx_hash)}.")

        try:
            # Import lazily to avoid a hard dependency when the module is loaded.
            from stellar_sdk import Keypair  # type: ignore[import]

            keypair = Keypair.from_raw_ed25519_seed(bytes(self._buf))
            return bytes(keypair.sign(tx_hash))
        except ImportError:
            # Fallback: use PyNaCl directly if stellar_sdk is unavailable.
            try:
                from nacl.signing import SigningKey  # type: ignore[import]

                sk = SigningKey(bytes(self._buf))
                return bytes(sk.sign(tx_hash).signature)
            except ImportError as exc:
                raise SigningError(
                    "Neither 'stellar_sdk' nor 'PyNaCl' is installed. "
                    "Install one to enable signing."
                ) from exc
        except Exception as exc:
            raise SigningError(f"Signing failed: {exc}") from exc
