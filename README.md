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

Release checklist:
- bump `__version__` in `__init__.py`
- write changelog?
- `$ git tag -s $VERSION -m "$VERSION"`
- `$ git push "$REMOTE_ORIGIN" tag "$VERSION"`
- build sdist (see [`contrib/sdist/`](contrib/sdist)):
  - `$ ELECBUILD_COMMIT=HEAD ELECBUILD_NOCACHE=1 ./contrib/sdist/build.sh`
- `$ python3 -m twine upload dist/$DISTNAME`
