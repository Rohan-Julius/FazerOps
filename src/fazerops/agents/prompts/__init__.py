"""System prompts and untrusted-data envelopes (Handoff §2, §8).

Every prompt here states explicitly that content inside `<untrusted_data>` tags is data to
analyse and never instructions to follow. Alert text, log lines and diff content are all
attacker-influenceable — see `security/envelope.py` (W16), which is the only code
permitted to wrap them.
"""
