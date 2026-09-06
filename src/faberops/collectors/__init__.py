"""Change collectors. One per source, all satisfying the same contract (Handoff §5)."""

from .base import BaseCollector, Collector, CollectorResult

__all__ = ["BaseCollector", "Collector", "CollectorResult"]
