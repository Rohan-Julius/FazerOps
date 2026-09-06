"""Correlation scoring. Ground rule #3: the maths is deterministic Python; the model
writes the narrative over scores it is given and does not compute them."""

from .scoring import score_events

__all__ = ["score_events"]
