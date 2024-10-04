# based on https://github.com/ludbb/secp256k1-py/blob/f5e455227bf1e833128adf80de8ee0ebcebf218c/setup.py

import errno
import logging
import os
import os.path
import platform
import shutil
import subprocess

from setuptools import setup
from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
from wheel.bdist_wheel import safer_name, get_platform


_logger = logging.getLogger("electrum_ecc")
MAKE = 'gmake' if platform.system() in ['FreeBSD', 'OpenBSD'] else 'make'


def absolute(*paths):
    op = os.path
    return op.realpath(op.abspath(op.join(op.dirname(__file__), *paths)))


def compile_secp(build_dir: str) -> None:
    if not os.path.exists(absolute('libsecp256k1')):
        raise Exception("missing git submodule secp256k1")

    if not os.path.exists(absolute('libsecp256k1/configure')):
        # configure script hasn't been generated yet
        autogen = absolute('libsecp256k1/autogen.sh')
        os.chmod(absolute(autogen), 0o755)
        subprocess.check_call([autogen], cwd=absolute('libsecp256k1'))

    for filename in [
        'libsecp256k1/configure',
        'libsecp256k1/build-aux/compile',
        'libsecp256k1/build-aux/config.guess',
        'libsecp256k1/build-aux/config.sub',
        'libsecp256k1/build-aux/depcomp',
        'libsecp256k1/build-aux/install-sh',
        'libsecp256k1/build-aux/missing',
        'libsecp256k1/build-aux/test-driver',
    ]:
        try:
            os.chmod(absolute(filename), 0o755)
        except OSError as e:
            # some of these files might not exist depending on autoconf version
            if e.errno != errno.ENOENT:
                # If the error isn't 'No such file or directory' something
                # else is wrong and we want to know about it
                raise

    cmd = [
        absolute('libsecp256k1/configure'),
        '--enable-shared',
        '--disable-static',
        '--disable-dependency-tracking',
        '--with-pic',
        '--prefix',
        os.path.abspath(build_dir),
        '--enable-module-recovery',
        '--enable-module-extrakeys',
        '--enable-module-schnorrsig',
        '--enable-experimental',
        '--enable-module-ecdh',
        '--enable-benchmark=no',
        '--enable-tests=no',
        '--enable-openssl-tests=no',
        '--enable-exhaustive-tests=no',
    ]

    _logger.info('Running configure: {}'.format(' '.join(cmd)))
    subprocess.check_call(cmd, cwd=build_dir)

    subprocess.check_call([MAKE], cwd=build_dir)
    subprocess.check_call([MAKE, 'install'], cwd=build_dir)


class bdist_wheel(_bdist_wheel):

    def finalize_options(self):
        # Inject the platform name, e.g. "linux_x86_64".
        # This will result in the final build artifact being named e.g.
        #   electrum_ecc-0.0.2-py3-none-linux_x86_64.whl
        self.plat_name = get_platform(self.bdist_dir)
        # note: we don't set the python "impl tag" or the "abi tag", as the C lib we build
        #       does not depend on them (it is not a "C extension" as we don't static link cpython).
        _bdist_wheel.finalize_options(self)

    def _build_and_copy_secp_lib(self):
        _build_cmd = self.get_finalized_command('build')
        build_dir = os.path.join(_build_cmd.build_base, "temp_libsecp")
        target_dir = os.path.join(self.bdist_dir, safer_name(self.distribution.get_name()))
        for dir_ in (build_dir, target_dir):
            try:
                os.makedirs(dir_)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise

        compile_secp(build_dir)

        build_temp_libs = os.path.join(build_dir, "lib")
        for fname in os.listdir(build_temp_libs):
            # note: we skip the versioned .so files (e.g. "*.so.2.2.0"), as wheels don't
            #       support symlinks and we would end up with ~3 copies of the same file
            if fname.endswith(".so") or fname.endswith(".dll") or fname.endswith(".dylib"):
                srcpath = os.path.join(build_temp_libs, fname)
                _logger.info(f"copying file {srcpath!r} to {target_dir=}")
                shutil.copy2(srcpath, target_dir)

    def run(self):
        self._build_and_copy_secp_lib()
        _bdist_wheel.run(self)


setup(
    cmdclass={
        'bdist_wheel': bdist_wheel,
    },
)
