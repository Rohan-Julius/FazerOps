"""Alert ingest. Generic webhook, three payload shapes (Idea.md §6)."""

from .alerts import UnrecognisedPayload, normalize_alert

__all__ = ["UnrecognisedPayload", "normalize_alert"]
