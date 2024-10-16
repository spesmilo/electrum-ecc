import unittest

import electrum_ecc as ecc
from electrum_ecc.util import sha256


bfh = bytes.fromhex

class TestBasics(unittest.TestCase):

    def test_ecc_sanity(self):
        G = ecc.GENERATOR
        n = G.order()
        self.assertEqual(ecc.CURVE_ORDER, n)
        inf = n * G
        self.assertEqual(ecc.POINT_AT_INFINITY, inf)
        self.assertTrue(inf.is_at_infinity())
        self.assertFalse(G.is_at_infinity())
        self.assertEqual(11 * G, 7 * G + 4 * G)
        self.assertEqual((n + 2) * G, 2 * G)
        self.assertEqual((n - 2) * G, -2 * G)
        A = (n - 2) * G
        B = (n - 1) * G
        C = n * G
        D = (n + 1) * G
        self.assertFalse(A.is_at_infinity())
        self.assertFalse(B.is_at_infinity())
        self.assertTrue(C.is_at_infinity())
        self.assertTrue((C * 5).is_at_infinity())
        self.assertFalse(D.is_at_infinity())
        self.assertEqual(inf, C)
        self.assertEqual(inf, A + 2 * G)
        self.assertEqual(inf, D + (-1) * G)
        self.assertNotEqual(A, B)
        self.assertEqual(2 * G, inf + 2 * G)
        self.assertEqual(inf, 3 * G + (-3 * G))

    def test_ecdh(self):
        def ecdh(privkey: ecc.ECPrivkey, pubkey: ecc.ECPubkey) -> bytes:
            pt = (privkey.secret_scalar * pubkey)
            return sha256(pt.get_public_key_bytes(compressed=True))

        # Alice's perspective:
        a = ecc.ECPrivkey.from_secret_scalar(11)
        B = ecc.ECPubkey(bfh("022b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c"))
        dh_secret_1 = ecdh(a, B)
        # Bob's perspective:
        A = ecc.ECPubkey(bfh("03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb"))
        b = ecc.ECPrivkey.from_secret_scalar(19)
        dh_secret_2 = ecdh(b, A)

        self.assertEqual(dh_secret_1, dh_secret_2)
        self.assertEqual("739a9fccc559f41588003e0d44812950ddb9ce23d2d2077e426be4dea5d8d2b4", dh_secret_1.hex())
