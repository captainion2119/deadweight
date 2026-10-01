"""Importing this package registers every collector in base.REGISTRY (order = scan/display order)."""
from . import compute, storage, database, network, security, integration, observability, ai, discovery  # noqa: F401
from .base import FAMILIES, REGISTRY, Ctx, Spec, collector  # noqa: F401
