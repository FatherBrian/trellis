"""Reef: right-size and pin what your agents can reach over MCP.

    from reef import Reef, load_reef_config
    reef = Reef(trellis, load_reef_config("reef.yaml"))

``reef.server`` serves it over MCP; ``reef serve`` and ``reef demo the-door`` are the CLI.
"""

from importlib.metadata import PackageNotFoundError, version

from reef.config import ReefConfig, ReefConfigError, load_reef_config
from reef.gateway import Reef

try:
    __version__ = version("reef-mcp")
except PackageNotFoundError:  # pragma: no cover - running from a checkout without installing
    __version__ = "0+unknown"

__all__ = ["Reef", "ReefConfig", "ReefConfigError", "__version__", "load_reef_config"]
