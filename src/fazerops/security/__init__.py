"""Two unrelated concerns that both sit on the trust boundary (Handoff §2, §8).

`envelope.py` (W16) wraps untrusted source text before it enters model context. It belongs
to the **investigation** layer and is imported freely.

`credentials.py` (W23) mints the actor principal. It belongs to the **automation** layer,
and the seam test blocks it by name — the investigation layer must never be able to obtain
a credential that can mutate anything.

The split matters: Handoff §8 requires the actor credential to be unobtainable on any code
path that has not passed through an approval handler, enforced structurally rather than by
convention.
"""
