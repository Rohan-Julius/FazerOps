# Classification fixtures — W13

One alert per `AlertClass`, plus one that deliberately matches nothing.

These are hand-authored, unlike `fixtures/k8s_audit/` which is captured from a real API
server. They are alert *payloads*, not observations: the shapes come from Alertmanager's
documented webhook schema and the wording from the alerting rules a team of this size
would actually write. Nothing downstream of `ingest/` reads them.

`unclassified.json` is the important one. It exists so that `unclassified` is exercised as
a real outcome rather than a branch nothing reaches — the moment a nearest-fit guess is
added to `classify()`, that file is what goes red.

The three payloads in the parent directory are the *same* incident in Alertmanager,
CloudWatch and PagerDuty shapes, and they test ingest parity. These test classification.
