from .keys import *
from .ecdsa_sigformat import *
from .util import *
from .ecc_fast import _libsecp256k1


__version__ = '0.0.8'


# Some unit tests need to create ECDSA sigs without grinding the R value (and just use RFC6979).
# see https://github.com/bitcoin/bitcoin/pull/13666
ENABLE_ECDSA_R_VALUE_GRINDING = True


# Ensure that asserts are enabled. For sanity and paranoia, we require this.
# Code *should not rely* on asserts being enabled. In particular, safety and security checks should
# always explicitly raise exceptions. However, this rule is mistakenly broken occasionally...
try:
    assert False  # noqa: B011
except AssertionError:
    pass
else:
    raise ImportError("Running with asserts disabled. Refusing to continue. Exiting...")
