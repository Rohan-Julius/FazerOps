"""One module per action (Handoff §2).

Ground rule #4: every executor computes its inverse before executing and refuses to run if
it cannot. Ground rule #1: no executor is ever constructed from model output — the model
selects an `action_id` and the catalog resolves it to the import path declared in
`config/actions.yaml`.

An executor is unreachable without an approval-minted credential (`security/credentials.py`,
W23), enforced structurally rather than by convention.
"""
