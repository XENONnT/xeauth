"""Top-level package for xeauth."""

from .settings import config
from . import admin, github, user, utils

__all__ = ["config", "admin", "github", "user", "utils"]


__author__ = """Yossi Mosbacher"""
__email__ = "joe.mosbacher@gmail.com"
__version__ = "0.2.1"
