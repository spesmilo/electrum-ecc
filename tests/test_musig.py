import copy
from concurrent.futures import ThreadPoolExecutor
from ctypes import POINTER, addressof, c_char, c_size_t, c_void_p, memmove
import json
from pathlib import Path
from threading import Event
import unittest
from unittest import mock

from electrum_ecc import ECPrivkey, ECPubkey
from electrum_ecc import ecc_fast, musig
from electrum_ecc.util import sha256


# Canonical bitcoin/bips vectors pinned to this upstream commit:
# 9297c12729670d09f9149ec6d8bad967d8161bfe
_VECTOR_DIR = Path(__file__).with_name("data") / "bip327"
_GROUP_ORDER = bytes.fromhex(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
)


def _vectors(name: str) -> dict:
    with (_VECTOR_DIR / name).open(encoding="ascii") as f:
        return json.load(f)


def _keypair(seed: bytes) -> tuple[ECPrivkey, bytes]:
    private_key = ECPrivkey(sha256(seed))
    return private_key, private_key.get_public_key_bytes(compressed=True)


def _secnonce_from_vector(
    *, secnonce97: bytes, seckey: bytes, pubkey: bytes, pubnonce: musig.PubNonce
) -> musig.SecNonce:
    """Load a public BIP327 test nonce into v0.7.1's opaque nonce object."""
    if len(secnonce97) != 97 or secnonce97[64:] != pubkey:
        raise ValueError("invalid BIP327 secnonce fixture")
    secnonce, _ = musig.nonce_gen(pubkey=pubkey, seckey=seckey)
    # v0.7.1 stores a four-byte magic followed by the two nonce scalars.
    memmove(addressof(secnonce._buf) + 4, secnonce97, 64)
    secnonce._pubnonce = pubnonce
    return secnonce


def _signing_state(n_signers: int = 2, *, tweak: bool = False):
    private_keys, pubkeys = zip(
        *[_keypair(f"signer-{i}".encode()) for i in range(n_signers)]
    )
    msg32 = sha256(b"musig test message")
    cache = musig.KeyAggCache.from_pubkeys(pubkeys)
    if tweak:
        cache.apply_xonly_tweak(sha256(b"taproot tweak"))
    nonce_pairs = [
        musig.nonce_gen(
            pubkey=pubkey,
            seckey=private_key.get_secret_bytes(),
            msg32=msg32,
            keyagg_cache=cache,
        )
        for private_key, pubkey in zip(private_keys, pubkeys)
    ]
    secnonces, pubnonces = zip(*nonce_pairs)
    session = musig.nonce_process(
        aggnonce=musig.nonce_agg(pubnonces),
        msg32=msg32,
        keyagg_cache=cache,
    )
    return private_keys, pubkeys, msg32, cache, secnonces, pubnonces, session


def _apply_vector_tweaks(cache, data, case) -> None:
    for index, is_xonly in zip(case["tweak_indices"], case["is_xonly"]):
        tweak = bytes.fromhex(data["tweaks"][index])
        if is_xonly:
            cache.apply_xonly_tweak(tweak)
        else:
            cache.apply_plain_tweak(tweak)


@unittest.skipUnless(
    ecc_fast.HAS_MUSIG, "libsecp256k1 built without --enable-module-musig"
)
class TestMuSig(unittest.TestCase):
    def test_ctypes_pointer_array_abi(self):
        char_ptr = POINTER(c_char)
        char_ptr_ptr = POINTER(char_ptr)
        expected = {
            "secp256k1_musig_pubkey_agg": [
                c_void_p,
                char_ptr,
                char_ptr,
                char_ptr_ptr,
                c_size_t,
            ],
            "secp256k1_musig_nonce_agg": [
                c_void_p,
                char_ptr,
                char_ptr_ptr,
                c_size_t,
            ],
            "secp256k1_musig_partial_sig_agg": [
                c_void_p,
                char_ptr,
                char_ptr,
                char_ptr_ptr,
                c_size_t,
            ],
        }
        for name, argtypes in expected.items():
            with self.subTest(name=name):
                self.assertEqual(argtypes, getattr(musig._libsecp256k1, name).argtypes)

    def _round_trip(self, n_signers: int, *, tweak: bool = False) -> None:
        state = _signing_state(n_signers, tweak=tweak)
        private_keys, pubkeys, msg32, cache, secnonces, pubnonces, session = state
        partial_sigs = [
            musig.partial_sign(
                secnonce=secnonce,
                seckey=private_key.get_secret_bytes(),
                keyagg_cache=cache,
                session=session,
            )
            for private_key, secnonce in zip(private_keys, secnonces)
        ]
        for partial_sig, pubnonce, pubkey in zip(partial_sigs, pubnonces, pubkeys):
            self.assertTrue(
                musig.partial_sig_verify(
                    partial_sig=partial_sig,
                    pubnonce=pubnonce,
                    pubkey=pubkey,
                    keyagg_cache=cache,
                    session=session,
                )
            )
        signature = musig.partial_sig_agg(session=session, partial_sigs=partial_sigs)
        aggregate = ECPubkey(b"\x02" + cache.aggregate_xonly_pubkey())
        self.assertTrue(aggregate.schnorr_verify(signature, msg32))

    def test_two_and_three_signer_round_trips(self):
        self._round_trip(2)
        self._round_trip(3)

    def test_taproot_tweak_round_trips(self):
        self._round_trip(2, tweak=True)
        self._round_trip(3, tweak=True)

    def test_tweak_result_preserves_full_pubkey_parity(self):
        _, pubkeys, _, _, _, _, _ = _signing_state()
        tweak = bytes.fromhex(
            "5A25B7645A273D89B8DAB0AFAFC5338C3DC5CF1A20AD113806C11897A9CEF074"
        )
        for apply in ("apply_plain_tweak", "apply_xonly_tweak"):
            with self.subTest(apply=apply):
                cache = musig.KeyAggCache.from_pubkeys(pubkeys)
                aggregate = getattr(cache, apply)(tweak)
                self.assertEqual(3, aggregate[0])
                self.assertEqual(aggregate[1:], cache.aggregate_xonly_pubkey())

    def test_secnonce_reuse_and_copy_are_rejected(self):
        state = _signing_state()
        private_keys, _, _, cache, secnonces, _, session = state
        with self.assertRaises(TypeError):
            copy.copy(secnonces[0])
        with self.assertRaises(TypeError):
            copy.deepcopy(secnonces[0])
        musig.partial_sign(
            secnonce=secnonces[0],
            seckey=private_keys[0].get_secret_bytes(),
            keyagg_cache=cache,
            session=session,
        )
        with self.assertRaises(ValueError):
            musig.partial_sign(
                secnonce=secnonces[0],
                seckey=private_keys[0].get_secret_bytes(),
                keyagg_cache=cache,
                session=session,
            )

    def test_concurrent_secnonce_consumption_is_atomic(self):
        state = _signing_state()
        private_keys, _, _, cache, secnonces, _, session = state
        original_sign = musig._libsecp256k1.secp256k1_musig_partial_sign
        entered_sign = Event()
        finish_sign = Event()

        def blocked_sign(*args):
            entered_sign.set()
            if not finish_sign.wait(5):
                raise TimeoutError("timed out waiting to finish partial signing")
            return original_sign(*args)

        def sign():
            try:
                return musig.partial_sign(
                    secnonce=secnonces[0],
                    seckey=private_keys[0].get_secret_bytes(),
                    keyagg_cache=cache,
                    session=session,
                )
            except Exception as e:
                return e

        with mock.patch.object(
            musig._libsecp256k1,
            "secp256k1_musig_partial_sign",
            side_effect=blocked_sign,
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(sign)
                self.assertTrue(entered_sign.wait(5))
                second = executor.submit(sign)
                try:
                    second_result = second.result(timeout=5)
                    self.assertIs(type(second_result), ValueError)
                    self.assertNotEqual(bytes(132), bytes(secnonces[0]._buf))
                finally:
                    finish_sign.set()
                first_result = first.result(timeout=5)
        results = [first_result, second_result]
        self.assertEqual(1, sum(type(result) is musig.PartialSig for result in results))
        self.assertEqual(1, sum(type(result) is ValueError for result in results))

    def test_signing_failure_consumes_and_zeroes_secnonce(self):
        state = _signing_state()
        private_keys, _, _, cache, secnonces, _, session = state
        function = "secp256k1_musig_partial_sign"
        with mock.patch.object(musig._libsecp256k1, function, return_value=0):
            with self.assertRaisesRegex(ValueError, "musig_partial_sign failed"):
                musig.partial_sign(
                    secnonce=secnonces[0],
                    seckey=private_keys[0].get_secret_bytes(),
                    keyagg_cache=cache,
                    session=session,
                )
        self.assertEqual(bytes(132), bytes(secnonces[0]._buf))
        with self.assertRaises(ValueError):
            musig.partial_sign(
                secnonce=secnonces[0],
                seckey=private_keys[0].get_secret_bytes(),
                keyagg_cache=cache,
                session=session,
            )

    def test_mismatched_key_does_not_consume_before_signing(self):
        state = _signing_state()
        private_keys, _, _, cache, secnonces, _, session = state
        with self.assertRaises(ValueError):
            musig.partial_sign(
                secnonce=secnonces[0],
                seckey=private_keys[1].get_secret_bytes(),
                keyagg_cache=cache,
                session=session,
            )
        self.assertIsInstance(
            musig.partial_sign(
                secnonce=secnonces[0],
                seckey=private_keys[0].get_secret_bytes(),
                keyagg_cache=cache,
                session=session,
            ),
            musig.PartialSig,
        )

    def test_strict_opaque_argument_types(self):
        state = _signing_state()
        private_keys, pubkeys, msg32, cache, secnonces, pubnonces, session = state
        aggnonce = musig.nonce_agg(pubnonces)
        partial_sig = musig.partial_sign(
            secnonce=secnonces[1],
            seckey=private_keys[1].get_secret_bytes(),
            keyagg_cache=cache,
            session=session,
        )
        calls = [
            lambda: musig.nonce_gen(pubkey=pubkeys[0], keyagg_cache=pubnonces[0]),
            lambda: musig.nonce_agg([aggnonce]),
            lambda: musig.nonce_process(
                aggnonce=pubnonces[0], msg32=msg32, keyagg_cache=cache
            ),
            lambda: musig.nonce_process(
                aggnonce=aggnonce, msg32=msg32, keyagg_cache=session
            ),
            lambda: musig.partial_sign(
                secnonce=pubnonces[0],
                seckey=private_keys[0].get_secret_bytes(),
                keyagg_cache=cache,
                session=session,
            ),
            lambda: musig.partial_sign(
                secnonce=secnonces[0],
                seckey=private_keys[0].get_secret_bytes(),
                keyagg_cache=session,
                session=session,
            ),
            lambda: musig.partial_sign(
                secnonce=secnonces[0],
                seckey=private_keys[0].get_secret_bytes(),
                keyagg_cache=cache,
                session=cache,
            ),
            lambda: musig.partial_sig_verify(
                partial_sig=pubnonces[0],
                pubnonce=pubnonces[0],
                pubkey=pubkeys[0],
                keyagg_cache=cache,
                session=session,
            ),
            lambda: musig.partial_sig_verify(
                partial_sig=partial_sig,
                pubnonce=partial_sig,
                pubkey=pubkeys[0],
                keyagg_cache=cache,
                session=session,
            ),
            lambda: musig.partial_sig_verify(
                partial_sig=partial_sig,
                pubnonce=pubnonces[1],
                pubkey=pubkeys[1],
                keyagg_cache=session,
                session=session,
            ),
            lambda: musig.partial_sig_verify(
                partial_sig=partial_sig,
                pubnonce=pubnonces[1],
                pubkey=pubkeys[1],
                keyagg_cache=cache,
                session=cache,
            ),
            lambda: musig.partial_sig_agg(session=cache, partial_sigs=[partial_sig]),
            lambda: musig.partial_sig_agg(session=session, partial_sigs=[pubnonces[0]]),
        ]
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaises(TypeError):
                    call()

    def test_input_validation_and_invalid_scalars(self):
        _, pubkey = _keypair(b"validation")
        cache = musig.KeyAggCache.from_pubkeys([pubkey])
        invalid_calls = [
            lambda: musig.PubNonce(None),
            lambda: musig.AggNonce(None),
            lambda: musig.PartialSig(None),
            lambda: musig.KeyAggCache.from_pubkeys(None),
            lambda: musig.nonce_gen(pubkey=pubkey, msg32=object()),
        ]
        for call in invalid_calls:
            with self.subTest(call=call):
                with self.assertRaises(TypeError):
                    call()
        with self.assertRaises(ValueError):
            musig.nonce_gen(pubkey=pubkey, seckey=bytes(32))
        with self.assertRaises(ValueError):
            musig.PartialSig(_GROUP_ORDER)
        with self.assertRaises(ValueError):
            musig.PubNonce(bytes(65))
        with self.assertRaises(ValueError):
            musig.AggNonce(bytes(65))
        with self.assertRaises(ValueError):
            musig.PartialSig(bytes(31))
        with self.assertRaises(ValueError):
            cache.apply_plain_tweak(_GROUP_ORDER)
        with self.assertRaises(ValueError):
            cache.apply_xonly_tweak(bytes(31))

    def test_session_randomness_is_consumed_on_failure(self):
        _, pubkey = _keypair(b"randomness")
        session_random = bytearray(b"\x01" * 32)
        with self.assertRaises(ValueError):
            musig.nonce_gen(
                pubkey=pubkey,
                seckey=bytes.fromhex("01" * 32),
                session_secrand32=session_random,
            )
        self.assertEqual(bytearray(32), session_random)
        session_random = bytearray(b"\x02" * 32)
        with self.assertRaises(TypeError):
            musig.nonce_gen(
                pubkey=pubkey,
                msg32=object(),
                session_secrand32=session_random,
            )
        self.assertEqual(bytearray(32), session_random)
        with self.assertRaises(TypeError):
            musig.nonce_gen(pubkey=pubkey, session_secrand32=bytes(32))

    def test_nonce_generation_failure_wipes_generated_secnonce(self):
        private_key, pubkey = _keypair(b"nonce-cleanup")
        created = []
        wiped = []
        original_init = musig.SecNonce.__init__
        original_wipe = musig.SecNonce._wipe

        def track_init(secnonce, *args, **kwargs):
            original_init(secnonce, *args, **kwargs)
            created.append(secnonce)

        def track_wipe(secnonce):
            original_wipe(secnonce)
            wiped.append(secnonce)

        # Track the instance created by this nonce_gen call instead of
        # counting wipes globally: unrelated SecNonce objects from earlier
        # tests can be garbage collected during the patch window, and their
        # __del__ also invokes the patched _wipe.
        with mock.patch.object(musig.SecNonce, "__init__", track_init):
            with mock.patch.object(musig.SecNonce, "_wipe", track_wipe):
                with mock.patch.object(
                    musig._libsecp256k1,
                    "secp256k1_musig_pubnonce_serialize",
                    return_value=0,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "pubnonce serialization failed"
                    ):
                        musig.nonce_gen(
                            pubkey=pubkey,
                            seckey=private_key.get_secret_bytes(),
                        )
                self.assertEqual(1, len(created))
                secnonce = created[0]
                # `created` holds a strong reference, so this wipe cannot come
                # from __del__: nonce_gen must have wiped it on failure.
                self.assertTrue(any(entry is secnonce for entry in wiped))
        self.assertEqual(bytes(132), bytes(secnonce._buf))

    def test_tampered_partial_signature_fails_verification(self):
        state = _signing_state()
        private_keys, pubkeys, _, cache, secnonces, pubnonces, session = state
        partial_sig = musig.partial_sign(
            secnonce=secnonces[0],
            seckey=private_keys[0].get_secret_bytes(),
            keyagg_cache=cache,
            session=session,
        )
        self.assertFalse(
            musig.partial_sig_verify(
                partial_sig=partial_sig,
                pubnonce=pubnonces[1],
                pubkey=pubkeys[1],
                keyagg_cache=cache,
                session=session,
            )
        )

    def test_opaque_types_cannot_be_constructed_directly(self):
        with self.assertRaises(TypeError):
            musig.KeyAggCache(bytes(197), bytes(32))
        with self.assertRaises(TypeError):
            musig.SecNonce(bytes(64))
        with self.assertRaises(TypeError):
            musig.Session(bytes(133))

    def test_bip327_key_aggregation_vectors(self):
        data = _vectors("key_agg_vectors.json")
        pubkeys = [bytes.fromhex(value) for value in data["pubkeys"]]
        for case in data["valid_test_cases"]:
            with self.subTest(case=case):
                cache = musig.KeyAggCache.from_pubkeys(
                    [pubkeys[index] for index in case["key_indices"]]
                )
                self.assertEqual(
                    bytes.fromhex(case["expected"]), cache.aggregate_xonly_pubkey()
                )
        for case in data["error_test_cases"]:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    cache = musig.KeyAggCache.from_pubkeys(
                        [pubkeys[index] for index in case["key_indices"]]
                    )
                    _apply_vector_tweaks(cache, data, case)

    def test_bip327_nonce_generation_public_vector(self):
        data = _vectors("nonce_gen_vectors.json")
        compatible = [
            case
            for case in data["test_cases"]
            if case["aggpk"] is None and (case["msg"] is None or len(case["msg"]) == 64)
        ]
        self.assertEqual(1, len(compatible))
        for case in compatible:
            session_random = bytearray.fromhex(case["rand_"])
            _, pubnonce = musig.nonce_gen(
                pubkey=bytes.fromhex(case["pk"]),
                seckey=None if case["sk"] is None else bytes.fromhex(case["sk"]),
                msg32=None if case["msg"] is None else bytes.fromhex(case["msg"]),
                extra_input32=(
                    None
                    if case["extra_in"] is None
                    else bytes.fromhex(case["extra_in"])
                ),
                session_secrand32=session_random,
            )
            self.assertEqual(
                bytes.fromhex(case["expected_pubnonce"]), pubnonce.to_bytes()
            )

    def test_bip327_nonce_aggregation_vectors(self):
        data = _vectors("nonce_agg_vectors.json")
        pubnonce_wires = [bytes.fromhex(value) for value in data["pnonces"]]
        for case in data["valid_test_cases"]:
            with self.subTest(case=case):
                aggregate = musig.nonce_agg(
                    [musig.PubNonce(pubnonce_wires[i]) for i in case["pnonce_indices"]]
                )
                self.assertEqual(bytes.fromhex(case["expected"]), aggregate.to_bytes())
        for case in data["error_test_cases"]:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    [musig.PubNonce(pubnonce_wires[i]) for i in case["pnonce_indices"]]

    def test_bip327_sign_verify_public_vectors(self):
        data = _vectors("sign_verify_vectors.json")
        pubkeys = [bytes.fromhex(value) for value in data["pubkeys"]]
        pubnonces = [bytes.fromhex(value) for value in data["pnonces"]]
        aggnonces = [bytes.fromhex(value) for value in data["aggnonces"]]
        seckey = bytes.fromhex(data["sk"])
        secnonce97 = bytes.fromhex(data["secnonces"][0])
        msg32 = bytes.fromhex(data["msgs"][0])
        cases = [case for case in data["valid_test_cases"] if case["msg_index"] == 0]
        for case in cases:
            with self.subTest(case=case):
                cache = musig.KeyAggCache.from_pubkeys(
                    [pubkeys[i] for i in case["key_indices"]]
                )
                nonces = [musig.PubNonce(pubnonces[i]) for i in case["nonce_indices"]]
                session = musig.nonce_process(
                    aggnonce=musig.AggNonce(aggnonces[case["aggnonce_index"]]),
                    msg32=msg32,
                    keyagg_cache=cache,
                )
                signer = case["signer_index"]
                signer_pubkey = pubkeys[case["key_indices"][signer]]
                secnonce = _secnonce_from_vector(
                    secnonce97=secnonce97,
                    seckey=seckey,
                    pubkey=signer_pubkey,
                    pubnonce=nonces[signer],
                )
                partial_sig = musig.partial_sign(
                    secnonce=secnonce,
                    seckey=seckey,
                    keyagg_cache=cache,
                    session=session,
                )
                self.assertEqual(
                    bytes.fromhex(case["expected"]), partial_sig.to_bytes()
                )
        for case in data["verify_fail_test_cases"]:
            if case["msg_index"] != 0:
                continue
            with self.subTest(case=case):
                cache = musig.KeyAggCache.from_pubkeys(
                    [pubkeys[i] for i in case["key_indices"]]
                )
                nonces = [musig.PubNonce(pubnonces[i]) for i in case["nonce_indices"]]
                session = musig.nonce_process(
                    aggnonce=musig.nonce_agg(nonces),
                    msg32=msg32,
                    keyagg_cache=cache,
                )
                try:
                    partial_sig = musig.PartialSig(bytes.fromhex(case["sig"]))
                except ValueError:
                    self.assertIn("exceeds group size", case["comment"])
                    continue
                signer = case["signer_index"]
                self.assertFalse(
                    musig.partial_sig_verify(
                        partial_sig=partial_sig,
                        pubnonce=nonces[signer],
                        pubkey=pubkeys[case["key_indices"][signer]],
                        keyagg_cache=cache,
                        session=session,
                    )
                )

    def test_bip327_tweak_verify_vectors(self):
        data = _vectors("tweak_vectors.json")
        pubkeys = [bytes.fromhex(value) for value in data["pubkeys"]]
        pubnonces = [bytes.fromhex(value) for value in data["pnonces"]]
        seckey = bytes.fromhex(data["sk"])
        secnonce97 = bytes.fromhex(data["secnonce"])
        for case in data["valid_test_cases"]:
            with self.subTest(case=case):
                cache = musig.KeyAggCache.from_pubkeys(
                    [pubkeys[i] for i in case["key_indices"]]
                )
                _apply_vector_tweaks(cache, data, case)
                session = musig.nonce_process(
                    aggnonce=musig.AggNonce(bytes.fromhex(data["aggnonce"])),
                    msg32=bytes.fromhex(data["msg"]),
                    keyagg_cache=cache,
                )
                signer = case["signer_index"]
                signer_pubkey = pubkeys[case["key_indices"][signer]]
                pubnonce = musig.PubNonce(pubnonces[case["nonce_indices"][signer]])
                secnonce = _secnonce_from_vector(
                    secnonce97=secnonce97,
                    seckey=seckey,
                    pubkey=signer_pubkey,
                    pubnonce=pubnonce,
                )
                partial_sig = musig.partial_sign(
                    secnonce=secnonce,
                    seckey=seckey,
                    keyagg_cache=cache,
                    session=session,
                )
                self.assertEqual(
                    bytes.fromhex(case["expected"]), partial_sig.to_bytes()
                )
        for case in data["error_test_cases"]:
            with self.assertRaises(ValueError):
                cache = musig.KeyAggCache.from_pubkeys(
                    [pubkeys[i] for i in case["key_indices"]]
                )
                _apply_vector_tweaks(cache, data, case)

    def test_bip327_signature_aggregation_vectors(self):
        data = _vectors("sig_agg_vectors.json")
        pubkeys = [bytes.fromhex(value) for value in data["pubkeys"]]
        partial_sigs = [bytes.fromhex(value) for value in data["psigs"]]
        msg32 = bytes.fromhex(data["msg"])
        for case in data["valid_test_cases"]:
            with self.subTest(case=case):
                cache = musig.KeyAggCache.from_pubkeys(
                    [pubkeys[i] for i in case["key_indices"]]
                )
                _apply_vector_tweaks(cache, data, case)
                session = musig.nonce_process(
                    aggnonce=musig.AggNonce(bytes.fromhex(case["aggnonce"])),
                    msg32=msg32,
                    keyagg_cache=cache,
                )
                signature = musig.partial_sig_agg(
                    session=session,
                    partial_sigs=[
                        musig.PartialSig(partial_sigs[i]) for i in case["psig_indices"]
                    ],
                )
                self.assertEqual(bytes.fromhex(case["expected"]), signature)
                aggregate = ECPubkey(b"\x02" + cache.aggregate_xonly_pubkey())
                self.assertTrue(aggregate.schnorr_verify(signature, msg32))
        for case in data["error_test_cases"]:
            with self.assertRaises(ValueError):
                [musig.PartialSig(partial_sigs[i]) for i in case["psig_indices"]]


class TestMuSigAvailability(unittest.TestCase):
    def test_missing_module_fails_cleanly(self):
        with mock.patch.object(ecc_fast, "HAS_MUSIG", False):
            with self.assertRaises(ecc_fast.LibModuleMissing):
                musig.KeyAggCache.from_pubkeys([bytes(33)])
