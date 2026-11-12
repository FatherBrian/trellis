"""Reef: Trellis enforced at the door of your MCP servers.

    from reef import Reef, load_reef_config
    reef = Reef(trellis, load_reef_config("reef.yaml"))

``reef.server`` serves it over MCP; ``reef serve`` and ``reef demo the-door`` are the CLI.
"""

from reef.config import ReefConfig, ReefConfigError, load_reef_config
from reef.gateway import Reef

__all__ = ["Reef", "ReefConfig", "ReefConfigError", "load_reef_config"]
