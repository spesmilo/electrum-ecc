import sys

from setuptools.build_meta import *  # noqa: F401, F403
from setuptools.build_meta import build_wheel

backend_class = build_wheel.__self__.__class__


class _CustomBuildMetaBackend(backend_class):
    def run_setup(self, setup_script="setup.py"):
        flags = []
        if self.config_settings and "electrum_ecc.dont_compile" in self.config_settings:
            flags.append(
                f"--electrum_ecc.dont_compile={self.config_settings['electrum_ecc.dont_compile']}"
            )
        if flags:
            sys.argv = sys.argv[:1] + ["build_ext"] + flags + sys.argv[1:]
        return super().run_setup(setup_script)

    def build_wheel(
        self, wheel_directory, config_settings=None, metadata_directory=None
    ):
        self.config_settings = config_settings
        return super().build_wheel(wheel_directory, config_settings, metadata_directory)


build_wheel = _CustomBuildMetaBackend().build_wheel
