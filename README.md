# electrum-ecc

[![Latest PyPI package](https://badge.fury.io/py/electrum_ecc.svg)](https://pypi.org/project/electrum-ecc/)


This package provides a pure python interface to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1).

Unlike Coincurve, it uses ctypes, and has no dependency.


### Tests

```
$ python3 -m unittest discover -s tests -t .
```
Or
```
$ pytest -v
```


### Maintainer notes

To build sdist for PyPI:
```
$ ./contrib/release.sh
```
