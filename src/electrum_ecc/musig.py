# Copyright (C) 2024-2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
"""A randomized, 32-byte-message subset of BIP327 MuSig2.

This is a thin wrapper around libsecp256k1's MuSig module. It supports the
standard randomized nonce flow, key aggregation and tweaking, partial signing
and verification, and signature aggregation. It is not a complete BIP327
implementation.

Secret nonces must never be copied, serialized, or reused. This module exposes
no secret nonce serialization. It reserves each ``SecNonce`` once immediately
before signing and then attempts to erase it. Erasure is best effort: Python
cannot guarantee timely finalization, prevent process-memory copies, or promise
that an interpreter or operating system will physically overwrite memory.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from ctypes import (
    POINTER,
    Array,
    byref,
    c_char,
    c_size_t,
    cast,
    create_string_buffer,
    memset,
)
from threading import Lock
from typing import Optional

from . import ecc_fast
from .ecc_fast import LibModuleMissing, SECP256K1_EC_COMPRESSED, _libsecp256k1


_KEYAGG_CACHE_SIZE = 197
_SECNONCE_SIZE = 132
_PUBNONCE_SIZE = 132
_AGGNONCE_SIZE = 132
_SESSION_SIZE = 133
_PARTIAL_SIG_SIZE = 36

_PUBNONCE_WIRE_SIZE = 66
_AGGNONCE_WIRE_SIZE = 66
_PARTIAL_SIG_WIRE_SIZE = 32
_PUBKEY_SIZE = 64
_KEYPAIR_SIZE = 96

_INTERNAL = object()
_BYTES_LIKE = (bytes, bytearray, memoryview)


def _check() -> None:
    if not ecc_fast.HAS_MUSIG:
        raise LibModuleMissing(
            "libsecp256k1 library found but it was built without the required "
            "module (--enable-module-musig)"
        )


def _as_bytes(value: object, name: str, size: Optional[int] = None) -> bytes:
    if not isinstance(value, _BYTES_LIKE):
        raise TypeError(f"{name} must be bytes-like")
    result = bytes(value)
    if size is not None and len(result) != size:
        raise ValueError(f"{name} must be {size} bytes")
    return result


def _as_sequence(value: object, name: str) -> Sequence:
    if not isinstance(value, Sequence) or isinstance(value, _BYTES_LIKE + (str,)):
        raise TypeError(f"{name} must be a sequence")
    if len(value) == 0:
        raise ValueError(f"at least one {name[:-1]} is required")
    return value


def _require_exact(value: object, expected_type: type, name: str) -> None:
    if type(value) is not expected_type:
        raise TypeError(f"{name} must be {expected_type.__name__}")


def _pointer_array(buffers: Sequence[Array]) -> Array:
    array_type = POINTER(c_char) * len(buffers)
    return array_type(*(cast(buf, POINTER(c_char)) for buf in buffers))


def _parse_pubkey(pubkey: object) -> bytes:
    pubkey_bytes = _as_bytes(pubkey, "pubkey")
    out = create_string_buffer(_PUBKEY_SIZE)
    if 1 != _libsecp256k1.secp256k1_ec_pubkey_parse(
        _libsecp256k1.ctx, out, pubkey_bytes, len(pubkey_bytes)
    ):
        raise ValueError("invalid public key")
    return bytes(out)


def _serialize_pubkey(pubkey: Array) -> bytes:
    out = create_string_buffer(33)
    out_len = c_size_t(33)
    if 1 != _libsecp256k1.secp256k1_ec_pubkey_serialize(
        _libsecp256k1.ctx, out, byref(out_len), pubkey, SECP256K1_EC_COMPRESSED
    ):
        raise RuntimeError("public key serialization failed")
    return bytes(out)


def _keypair_from_seckey(seckey: bytes) -> Array:
    out = create_string_buffer(_KEYPAIR_SIZE)
    if 1 != _libsecp256k1.secp256k1_keypair_create(_libsecp256k1.ctx, out, seckey):
        memset(out, 0, _KEYPAIR_SIZE)
        raise ValueError("invalid seckey")
    return out


def _pubkey_from_seckey(seckey: bytes) -> bytes:
    out = create_string_buffer(_PUBKEY_SIZE)
    if 1 != _libsecp256k1.secp256k1_ec_pubkey_create(_libsecp256k1.ctx, out, seckey):
        raise ValueError("invalid seckey")
    return bytes(out)


class KeyAggCache:
    """Opaque key aggregation state, mutated in place by tweaks."""

    __slots__ = ("_buf", "_aggregate_xonly")

    def __init__(
        self, buf: object = b"", aggregate_xonly: object = b"", *, _token: object = None
    ) -> None:
        if _token is not _INTERNAL:
            raise TypeError("KeyAggCache instances must be created with from_pubkeys")
        self._buf = _as_bytes(buf, "KeyAggCache buffer", _KEYAGG_CACHE_SIZE)
        self._aggregate_xonly = _as_bytes(
            aggregate_xonly, "aggregate x-only pubkey", 32
        )

    @classmethod
    def from_pubkeys(cls, pubkeys: Sequence[bytes]) -> "KeyAggCache":
        """Aggregate an ordered, nonempty sequence of secp256k1 public keys."""
        _check()
        if cls is not KeyAggCache:
            raise TypeError("KeyAggCache subclasses are not supported")
        pubkeys = _as_sequence(pubkeys, "pubkeys")
        parsed = [_parse_pubkey(pubkey) for pubkey in pubkeys]
        buffers = [create_string_buffer(pubkey, _PUBKEY_SIZE) for pubkey in parsed]
        pointers = _pointer_array(buffers)
        aggregate_xonly = create_string_buffer(_PUBKEY_SIZE)
        cache = create_string_buffer(_KEYAGG_CACHE_SIZE)
        if 1 != _libsecp256k1.secp256k1_musig_pubkey_agg(
            _libsecp256k1.ctx,
            aggregate_xonly,
            cache,
            pointers,
            c_size_t(len(buffers)),
        ):
            raise ValueError("musig_pubkey_agg failed")
        xonly = create_string_buffer(32)
        if 1 != _libsecp256k1.secp256k1_xonly_pubkey_serialize(
            _libsecp256k1.ctx, xonly, aggregate_xonly
        ):
            raise RuntimeError("aggregate public key serialization failed")
        return cls(bytes(cache), bytes(xonly), _token=_INTERNAL)

    def aggregate_xonly_pubkey(self) -> bytes:
        """Return the current aggregate key as 32-byte BIP340 x-only bytes."""
        _require_exact(self, KeyAggCache, "keyagg_cache")
        return self._aggregate_xonly

    def apply_plain_tweak(self, tweak32: bytes) -> bytes:
        """Apply a plain EC tweak and return the compressed aggregate key."""
        return self._apply_tweak(tweak32, xonly=False)

    def apply_xonly_tweak(self, tweak32: bytes) -> bytes:
        """Apply an x-only tweak and return the compressed aggregate key."""
        return self._apply_tweak(tweak32, xonly=True)

    def _apply_tweak(self, tweak32: object, *, xonly: bool) -> bytes:
        _check()
        _require_exact(self, KeyAggCache, "keyagg_cache")
        tweak = _as_bytes(tweak32, "tweak", 32)
        cache = create_string_buffer(bytes(self._buf), _KEYAGG_CACHE_SIZE)
        output_pubkey = create_string_buffer(_PUBKEY_SIZE)
        function = (
            _libsecp256k1.secp256k1_musig_pubkey_xonly_tweak_add
            if xonly
            else _libsecp256k1.secp256k1_musig_pubkey_ec_tweak_add
        )
        if 1 != function(_libsecp256k1.ctx, output_pubkey, cache, tweak):
            raise ValueError("musig tweak failed")

        compressed = _serialize_pubkey(output_pubkey)
        self._buf = bytes(cache)
        self._aggregate_xonly = compressed[1:]
        return compressed


class PubNonce:
    """A validated, serializable 66-byte public nonce."""

    __slots__ = ("_wire",)

    def __init__(self, wire66: bytes) -> None:
        _check()
        wire = _as_bytes(wire66, "pubnonce", _PUBNONCE_WIRE_SIZE)
        out = create_string_buffer(_PUBNONCE_SIZE)
        if 1 != _libsecp256k1.secp256k1_musig_pubnonce_parse(
            _libsecp256k1.ctx, out, wire
        ):
            raise ValueError("invalid pubnonce")
        self._wire = wire

    def to_bytes(self) -> bytes:
        _require_exact(self, PubNonce, "pubnonce")
        return self._wire

    def _to_internal(self) -> bytes:
        _require_exact(self, PubNonce, "pubnonce")
        out = create_string_buffer(_PUBNONCE_SIZE)
        if 1 != _libsecp256k1.secp256k1_musig_pubnonce_parse(
            _libsecp256k1.ctx, out, self._wire
        ):
            raise RuntimeError("stored pubnonce became invalid")
        return bytes(out)


class SecNonce:
    """A single-use secret nonce with best-effort in-memory cleanup.

    ``partial_sign`` atomically reserves a nonce under a per-instance lock
    before entering libsecp256k1. From that point onward it remains consumed and
    is zeroed even if the C call fails. Python cannot guarantee complete erasure.
    """

    __slots__ = ("_buf", "_consumed", "_lock", "_pubkey", "_pubnonce")

    def __init__(self, pubkey: object = b"", *, _token: object = None) -> None:
        if _token is not _INTERNAL:
            raise TypeError("SecNonce instances must be created with nonce_gen")
        self._pubkey = _as_bytes(pubkey, "internal pubkey", _PUBKEY_SIZE)
        self._buf = create_string_buffer(_SECNONCE_SIZE)
        self._consumed = False
        self._lock = Lock()
        self._pubnonce: Optional[PubNonce] = None

    def __copy__(self) -> "SecNonce":
        raise TypeError("SecNonce must not be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> "SecNonce":
        raise TypeError("SecNonce must not be copied")

    def _reserve_for_signing(self) -> Array:
        _require_exact(self, SecNonce, "secnonce")
        with self._lock:
            if self._consumed:
                raise ValueError(
                    "secnonce already consumed (nonce reuse would leak the seckey)"
                )
            self._consumed = True
            return self._buf

    def _wipe(self) -> None:
        memset(self._buf, 0, _SECNONCE_SIZE)

    def __del__(self) -> None:
        try:
            self._wipe()
        except BaseException:
            pass


class AggNonce:
    """A validated, serializable 66-byte aggregate nonce."""

    __slots__ = ("_wire",)

    def __init__(self, wire66: bytes) -> None:
        _check()
        wire = _as_bytes(wire66, "aggnonce", _AGGNONCE_WIRE_SIZE)
        out = create_string_buffer(_AGGNONCE_SIZE)
        if 1 != _libsecp256k1.secp256k1_musig_aggnonce_parse(
            _libsecp256k1.ctx, out, wire
        ):
            raise ValueError("invalid aggnonce")
        self._wire = wire

    def to_bytes(self) -> bytes:
        _require_exact(self, AggNonce, "aggnonce")
        return self._wire

    def _to_internal(self) -> bytes:
        _require_exact(self, AggNonce, "aggnonce")
        out = create_string_buffer(_AGGNONCE_SIZE)
        if 1 != _libsecp256k1.secp256k1_musig_aggnonce_parse(
            _libsecp256k1.ctx, out, self._wire
        ):
            raise RuntimeError("stored aggnonce became invalid")
        return bytes(out)


class PartialSig:
    """A validated, serializable 32-byte MuSig2 partial signature."""

    __slots__ = ("_wire",)

    def __init__(self, wire32: bytes) -> None:
        _check()
        wire = _as_bytes(wire32, "partial sig", _PARTIAL_SIG_WIRE_SIZE)
        out = create_string_buffer(_PARTIAL_SIG_SIZE)
        if 1 != _libsecp256k1.secp256k1_musig_partial_sig_parse(
            _libsecp256k1.ctx, out, wire
        ):
            raise ValueError("invalid partial sig")
        self._wire = wire

    def to_bytes(self) -> bytes:
        _require_exact(self, PartialSig, "partial_sig")
        return self._wire

    def _to_internal(self) -> bytes:
        _require_exact(self, PartialSig, "partial_sig")
        out = create_string_buffer(_PARTIAL_SIG_SIZE)
        if 1 != _libsecp256k1.secp256k1_musig_partial_sig_parse(
            _libsecp256k1.ctx, out, self._wire
        ):
            raise RuntimeError("stored partial sig became invalid")
        return bytes(out)


class Session:
    """Opaque state created by ``nonce_process`` for one signing session."""

    __slots__ = ("_buf",)

    def __init__(self, buf: object = b"", *, _token: object = None) -> None:
        if _token is not _INTERNAL:
            raise TypeError("Session instances must be created with nonce_process")
        self._buf = _as_bytes(buf, "session", _SESSION_SIZE)


def nonce_gen(
    *,
    pubkey: bytes,
    seckey: Optional[bytes] = None,
    msg32: Optional[bytes] = None,
    keyagg_cache: Optional[KeyAggCache] = None,
    extra_input32: Optional[bytes] = None,
    session_secrand32: Optional[bytearray] = None,
) -> tuple[SecNonce, PubNonce]:
    """Generate a secret/public nonce pair using unique random session data.

    A supplied ``session_secrand32`` must be a mutable 32-byte ``bytearray`` and
    is consumed and zeroed. Otherwise, secure randomness is generated locally.
    """
    _check()
    if session_secrand32 is not None and type(session_secrand32) is not bytearray:
        raise TypeError("session_secrand32 must be a bytearray so it can be consumed")
    if session_secrand32 is not None and len(session_secrand32) != 32:
        raise ValueError("session_secrand32 must be 32 bytes")
    if session_secrand32 is None:
        session_secrand32 = bytearray(secrets.token_bytes(32))

    secnonce: Optional[SecNonce] = None
    try:
        secrand = (c_char * 32).from_buffer(session_secrand32)
        pubkey_bytes = _as_bytes(pubkey, "pubkey")
        seckey_bytes = None if seckey is None else _as_bytes(seckey, "seckey", 32)
        msg = None if msg32 is None else _as_bytes(msg32, "msg32", 32)
        extra_input = (
            None
            if extra_input32 is None
            else _as_bytes(extra_input32, "extra_input32", 32)
        )
        if keyagg_cache is not None:
            _require_exact(keyagg_cache, KeyAggCache, "keyagg_cache")
        parsed_pubkey = _parse_pubkey(pubkey_bytes)
        if (
            seckey_bytes is not None
            and _pubkey_from_seckey(seckey_bytes) != parsed_pubkey
        ):
            raise ValueError("seckey does not match pubkey")
        secnonce = SecNonce(parsed_pubkey, _token=_INTERNAL)
        pubnonce = create_string_buffer(_PUBNONCE_SIZE)
        cache = bytes(keyagg_cache._buf) if keyagg_cache is not None else None
        if 1 != _libsecp256k1.secp256k1_musig_nonce_gen(
            _libsecp256k1.ctx,
            secnonce._buf,
            pubnonce,
            secrand,
            seckey_bytes,
            parsed_pubkey,
            msg,
            cache,
            extra_input,
        ):
            raise ValueError("musig_nonce_gen failed")
        wire = create_string_buffer(_PUBNONCE_WIRE_SIZE)
        if 1 != _libsecp256k1.secp256k1_musig_pubnonce_serialize(
            _libsecp256k1.ctx, wire, pubnonce
        ):
            raise RuntimeError("pubnonce serialization failed")
        public_nonce = PubNonce(bytes(wire))
        secnonce._pubnonce = public_nonce
        return secnonce, public_nonce
    except BaseException:
        if secnonce is not None:
            secnonce._wipe()
        raise
    finally:
        session_secrand32[:] = bytes(32)


def nonce_agg(pubnonces: Sequence[PubNonce]) -> AggNonce:
    """Aggregate a nonempty sequence of public nonces."""
    _check()
    pubnonces = _as_sequence(pubnonces, "pubnonces")
    for pubnonce in pubnonces:
        _require_exact(pubnonce, PubNonce, "pubnonce")
    buffers = [
        create_string_buffer(pubnonce._to_internal(), _PUBNONCE_SIZE)
        for pubnonce in pubnonces
    ]
    pointers = _pointer_array(buffers)
    aggregate = create_string_buffer(_AGGNONCE_SIZE)
    if 1 != _libsecp256k1.secp256k1_musig_nonce_agg(
        _libsecp256k1.ctx, aggregate, pointers, c_size_t(len(buffers))
    ):
        raise ValueError("musig_nonce_agg failed")
    wire = create_string_buffer(_AGGNONCE_WIRE_SIZE)
    if 1 != _libsecp256k1.secp256k1_musig_aggnonce_serialize(
        _libsecp256k1.ctx, wire, aggregate
    ):
        raise RuntimeError("aggnonce serialization failed")
    return AggNonce(bytes(wire))


def nonce_process(
    *, aggnonce: AggNonce, msg32: bytes, keyagg_cache: KeyAggCache
) -> Session:
    """Create a signing session for a 32-byte message."""
    _check()
    _require_exact(aggnonce, AggNonce, "aggnonce")
    _require_exact(keyagg_cache, KeyAggCache, "keyagg_cache")
    msg = _as_bytes(msg32, "msg32", 32)
    session = create_string_buffer(_SESSION_SIZE)
    if 1 != _libsecp256k1.secp256k1_musig_nonce_process(
        _libsecp256k1.ctx,
        session,
        aggnonce._to_internal(),
        msg,
        bytes(keyagg_cache._buf),
    ):
        raise ValueError("musig_nonce_process failed")
    return Session(bytes(session), _token=_INTERNAL)


def partial_sign(
    *,
    secnonce: SecNonce,
    seckey: bytes,
    keyagg_cache: KeyAggCache,
    session: Session,
) -> PartialSig:
    """Create a partial signature and irrevocably consume ``secnonce``."""
    _check()
    _require_exact(secnonce, SecNonce, "secnonce")
    _require_exact(keyagg_cache, KeyAggCache, "keyagg_cache")
    _require_exact(session, Session, "session")
    seckey_bytes = _as_bytes(seckey, "seckey", 32)

    keypair = _keypair_from_seckey(seckey_bytes)
    try:
        signer_pubkey = _pubkey_from_seckey(seckey_bytes)
        if signer_pubkey != secnonce._pubkey:
            raise ValueError("seckey does not match the secnonce pubkey")
        if secnonce._pubnonce is None:
            raise RuntimeError("secnonce has no associated pubnonce")
        _require_exact(secnonce._pubnonce, PubNonce, "secnonce pubnonce")
        pubnonce = secnonce._pubnonce._to_internal()
        cache = bytes(keyagg_cache._buf)
        session_buf = session._buf
        partial_sig = create_string_buffer(_PARTIAL_SIG_SIZE)

        secnonce_buf = secnonce._reserve_for_signing()
        try:
            result = _libsecp256k1.secp256k1_musig_partial_sign(
                _libsecp256k1.ctx,
                partial_sig,
                secnonce_buf,
                keypair,
                cache,
                session_buf,
            )
        finally:
            secnonce._wipe()
        if result != 1:
            raise ValueError("musig_partial_sign failed")
        if 1 != _libsecp256k1.secp256k1_musig_partial_sig_verify(
            _libsecp256k1.ctx,
            partial_sig,
            pubnonce,
            signer_pubkey,
            cache,
            session_buf,
        ):
            raise ValueError("generated partial signature failed self-verification")
        wire = create_string_buffer(_PARTIAL_SIG_WIRE_SIZE)
        if 1 != _libsecp256k1.secp256k1_musig_partial_sig_serialize(
            _libsecp256k1.ctx, wire, partial_sig
        ):
            raise RuntimeError("partial signature serialization failed")
        return PartialSig(bytes(wire))
    finally:
        memset(keypair, 0, _KEYPAIR_SIZE)


def partial_sig_verify(
    *,
    partial_sig: PartialSig,
    pubnonce: PubNonce,
    pubkey: bytes,
    keyagg_cache: KeyAggCache,
    session: Session,
) -> bool:
    """Verify one signer's partial signature for a signing session."""
    _check()
    _require_exact(partial_sig, PartialSig, "partial_sig")
    _require_exact(pubnonce, PubNonce, "pubnonce")
    _require_exact(keyagg_cache, KeyAggCache, "keyagg_cache")
    _require_exact(session, Session, "session")
    pubkey_bytes = _as_bytes(pubkey, "pubkey")
    parsed_pubkey = _parse_pubkey(pubkey_bytes)
    return 1 == _libsecp256k1.secp256k1_musig_partial_sig_verify(
        _libsecp256k1.ctx,
        partial_sig._to_internal(),
        pubnonce._to_internal(),
        parsed_pubkey,
        bytes(keyagg_cache._buf),
        session._buf,
    )


def partial_sig_agg(*, session: Session, partial_sigs: Sequence[PartialSig]) -> bytes:
    """Aggregate partial signatures into a possibly invalid BIP340 signature.

    A successful aggregation only means the inputs were well formed. The caller
    must BIP340-verify the returned signature against the message and aggregate
    x-only public key.
    """
    _check()
    _require_exact(session, Session, "session")
    partial_sigs = _as_sequence(partial_sigs, "partial_sigs")
    for partial_sig in partial_sigs:
        _require_exact(partial_sig, PartialSig, "partial_sig")
    buffers = [
        create_string_buffer(partial_sig._to_internal(), _PARTIAL_SIG_SIZE)
        for partial_sig in partial_sigs
    ]
    pointers = _pointer_array(buffers)
    signature = create_string_buffer(64)
    if 1 != _libsecp256k1.secp256k1_musig_partial_sig_agg(
        _libsecp256k1.ctx,
        signature,
        session._buf,
        pointers,
        c_size_t(len(buffers)),
    ):
        raise ValueError("musig_partial_sig_agg failed")
    return bytes(signature)
