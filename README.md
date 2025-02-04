# electrum-ecc

```
Licence: MIT Licence
Author: The Electrum developers
Language: Python (>= 3.8)
```

[![Latest PyPI package](https://badge.fury.io/py/electrum_ecc.svg)](https://pypi.org/project/electrum-ecc/)
[![Build Status](https://api.cirrus-ci.com/github/spesmilo/electrum-ecc.svg)](https://cirrus-ci.com/github/spesmilo/electrum-ecc)


This package provides a pure python interface to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1).

Unlike Coincurve, it uses ctypes, and has no dependency.


### Tests

```
$ python3 -m unittest discover -s tests -t .
```
Or
```
$ pytest tests -v
```


### Maintainer notes

To build sdist for PyPI,
see [`contrib/sdist/`](contrib/sdist).
