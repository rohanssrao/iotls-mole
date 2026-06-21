from importlib.metadata import PackageNotFoundError, version

#: Canonical runtime name, used for the CLI banner/prog, the log header, the
#: nftables table, and `show` hints. The packaging name lives in pyproject.toml;
#: this is the one place code refers to it.
APP = "trustfall"

try:
    __version__ = version(APP)
except PackageNotFoundError:  # running from a raw checkout, not installed
    __version__ = "0.0.0+dev"
