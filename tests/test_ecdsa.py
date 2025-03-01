import unittest

import electrum_ecc as ecc
from electrum_ecc import ECPubkey, ECPrivkey
from electrum_ecc import _libsecp256k1
from electrum_ecc.util import sha256


bfh = bytes.fromhex


class TestEcdsa(unittest.TestCase):

    def test_verify_enforces_low_s(self):
        # privkey = ecc.ECPrivkey(bytes.fromhex("d473e2ec218dca8e3508798f01cdfde0135fc79d95526b12e3537fe57e479ac1"))
        # r, low_s = privkey.ecdsa_sign(msg32, sigencode=lambda x, y: (x,y))
        # pubkey = ecc.ECPubkey(privkey.get_public_key_bytes())
        pubkey = ecc.ECPubkey(bytes.fromhex("03befe4f7c92eaed73fb8eddac28c6191c87c6a3546bf8dc09643e1e10bc6f5ab0"))
        msg32 = sha256(b"hello there")
        r = 29658118546717807188148256874354333643324863178937517286987684851194094232509
        # low-S
        low_s = 9695211969150896589566136599751503273246834163278279637071703776634378000266
        sig64_low_s = (
            int.to_bytes(r, length=32, byteorder="big") +
            int.to_bytes(low_s, length=32, byteorder="big"))
        self.assertTrue(pubkey.ecdsa_verify(sig64_low_s, msg32))
        # high-S
        high_s = ecc.CURVE_ORDER - low_s
        sig64_high_s = (
            int.to_bytes(r, length=32, byteorder="big") +
            int.to_bytes(high_s, length=32, byteorder="big"))
        self.assertFalse(pubkey.ecdsa_verify(sig64_high_s, msg32))
        self.assertTrue(pubkey.ecdsa_verify(sig64_high_s, msg32, enforce_low_s=False))

    def test_ecdsa_sign(self):
        eckey1 = ecc.ECPrivkey(bfh('7e1255fddb52db1729fc3ceb21a46f95b8d9fe94cc83425e936a6c5223bb679d'))
        sig1 = eckey1.ecdsa_sign(bfh('5a548b12369a53faaa7e51b5081829474ebdd9c924b3a8230b69aa0be254cd94'),
                                 sigencode=ecc.ecdsa_der_sig_from_r_and_s)
        self.assertEqual('3044022066e7d6a954006cce78a223f5edece8aaedcf3607142e9677acef1cfcb91cfdde022065cb0b5401bf16959ce7b785ea7fd408be5e4cb7d8f1b1a32c78eac6f73678d9', sig1.hex())

        eckey2 = ecc.ECPrivkey(bfh('c7ce8c1462c311eec24dff9e2532ac6241e50ae57e7d1833af21942136972f23'))
        sig2 = eckey2.ecdsa_sign(bfh('642a2e66332f507c92bda910158dfe46fc10afbf72218764899d3af99a043fac'),
                                 sigencode=ecc.ecdsa_der_sig_from_r_and_s)
        self.assertEqual('30440220618513f4cfc87dde798ce5febae7634c23e7b9254a1eabf486be820f6a7c2c4702204fef459393a2b931f949e63ced06888f35e286e446dc46feb24b5b5f81c6ed52', sig2.hex())

    def test_ecdsa_sign_without_r_value_grinding(self):
        eckey1 = ecc.ECPrivkey(bfh('7e1255fddb52db1729fc3ceb21a46f95b8d9fe94cc83425e936a6c5223bb679d'))
        sig1 = eckey1.ecdsa_sign(
            bfh('5a548b12369a53faaa7e51b5081829474ebdd9c924b3a8230b69aa0be254cd94'),
            sigencode=ecc.ecdsa_der_sig_from_r_and_s, grind_r_value=False,
        )
        self.assertEqual('3045022100902a288b98392254cd23c0e9a49ac6d7920f171b8249a48e484b998f1874a2010220723d844826828f092cf400cb210c4fa0b8cd1b9d1a7f21590e78e022ff6476b9', sig1.hex())

    def test_ecdsa_verify_der_sig(self):
        eckey1 = ecc.ECPrivkey.from_secret_scalar(10877953613094898331777953037035807584681004899710037363338258839373864549145)
        msg32 = bytes(32)
        der_sig = bfh('3045022100cfd454a1215fdea463201a7a32c146c1cec54b60b12d47e118a2add41366cec602203e7875d23cc80f958e45298bb8369d4422acfbc1c317353eebe02c89206b3e73')
        # der sig must be converted for ecdsa_verify:
        sig64 = ecc.ecdsa_sig64_from_der_sig(der_sig)
        self.assertTrue(eckey1.ecdsa_verify(sig64, msg32))
        # so this won't work:
        self.assertFalse(eckey1.ecdsa_verify(der_sig, msg32))

        fake_msg = sha256(b"satoshi")
        self.assertFalse(eckey1.ecdsa_verify(sig64, fake_msg))
