"""A keyed hash chain under the ledger's JSONL files — what makes a rewrite detectable.

`store.py` argues that a ledger which can be rewritten in place is not evidence. Before this
module nothing *detected* a rewrite: an edited line replayed as happily as an honest one. That
mattered once Phase G began trusting the file — the miner reads it, `replay_corpus` checks
demonstrations against it, and `attest_bundle` signs digests of events taken from it, and
`actions/growth/pr.py` says in as many words that none of that proves the ledger is honest.

Each line is `{"prev": <mac of the line before>, "mac": HMAC(key, prev ‖ record), "record": …}`.

**Keyed, not a bare SHA-256 chain.** Anyone able to rewrite a line can recompute every later
hash of an unkeyed chain, so it would catch only accidents. The key is `FAZEROPS_EVIDENCE_KEY`,
the one CI already treats as the ledger's authority, so there is one trust root rather than two.

What it detects: an edited, inserted, removed or reordered line, a line signed with another key,
and unsigned lines mixed into a signed file. What it does **not**: removing lines from the *end*
(the chain has no off-host anchor for its head), or anyone who can read the key — a process on
the ledger's own host that can read `.env` can forge history. Both are stated, not implied away.

**One writer at a time, across processes.** The automation server and the growth job append to
the same file from separate `LedgerStore` instances. Each append takes an exclusive `flock` and
chains from the file's actual last line, never from a mac remembered in memory — a remembered
mac would fork the chain the first time two writers interleaved.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
from enum import Enum
from pathlib import Path
from typing import Any

__all__ = [
    "GENESIS",
    "ChainedLog",
    "Integrity",
    "LedgerIntegrityError",
    "LedgerUntrusted",
    "sign_unsigned",
    "usable_as_evidence",
    "worst",
]

GENESIS = "0" * 64
_TAIL_CHUNK = 65536


class Integrity(str, Enum):
    IN_MEMORY = "in_memory"
    """No file: nothing outside the process could have edited it."""

    VERIFIED = "verified"
    """Every line signed, chained, and checked with the configured key."""

    UNSIGNED = "unsigned"
    """Written without a key. Readable, not evidence."""

    UNVERIFIED = "unverified"
    """Signed, but no key is configured here to check the signatures."""

    BROKEN = "broken"
    """Something in the file was changed after it was written."""


_SEVERITY = [Integrity.IN_MEMORY, Integrity.VERIFIED, Integrity.UNSIGNED, Integrity.UNVERIFIED, Integrity.BROKEN]


def worst(*states: tuple[Integrity, str | None]) -> tuple[Integrity, str | None]:
    return max(states, key=lambda state: _SEVERITY.index(state[0]))


def usable_as_evidence(integrity: Integrity, *, key_configured: bool) -> bool:
    """A broken ledger is never evidence. An unsigned or unverifiable one is tolerated only where
    no key is configured at all — there nothing is attested, so nothing is being vouched for; where
    a key exists, a ledger that could be checked and is not must not be signed on."""
    if integrity is Integrity.BROKEN:
        return False
    if integrity in (Integrity.UNSIGNED, Integrity.UNVERIFIED):
        return not key_configured
    return True


class LedgerIntegrityError(RuntimeError):
    """An append that would silently damage the chain — refused instead."""


class LedgerUntrusted(ValueError):
    """A ledger whose integrity does not allow it to vouch for evidence."""


def sign_unsigned(path: Path, key: bytes) -> Integrity:
    """Sign a ledger that was started without a key, in place. The one way out of UNSIGNED.

    Refuses anything but UNSIGNED: a VERIFIED file needs nothing, and signing a BROKEN or
    UNVERIFIED one would launder an edit into a valid chain. It vouches only that the file had not
    changed *since this call* — whatever happened before it was unsigned is not made evidence
    retroactively, which is why this is an operator's explicit step and never automatic.

    **Run it with the automation server and growth job stopped.** The rewrite replaces the file,
    and a writer already blocked on the old file's lock would append to a file no longer linked.
    """
    if not path.exists():
        return Integrity.VERIFIED
    records, integrity, detail = ChainedLog(path, key).read()
    if integrity is Integrity.VERIFIED:
        return integrity
    if integrity is not Integrity.UNSIGNED:
        raise LedgerUntrusted(f"{path} is {integrity.value} ({detail}); only an unsigned ledger can be signed")

    staging = path.with_name(f".{path.name}.signing")
    staging.unlink(missing_ok=True)
    with path.open("rb") as original:
        fcntl.flock(original.fileno(), fcntl.LOCK_EX)
        try:
            again, still, _ = ChainedLog(path, key).read()
            if still is not Integrity.UNSIGNED or len(again) != len(records):
                raise LedgerIntegrityError(f"{path} changed while it was being signed; stop its writers and retry")
            ChainedLog(staging, key).append(again)
            staging.replace(path)
        finally:
            fcntl.flock(original.fileno(), fcntl.LOCK_UN)
    return ChainedLog(path, key).read()[1]


def _canonical(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _mac(key: bytes, prev: str, payload: Any) -> str:
    return hmac.new(key, prev.encode("ascii") + b"\n" + _canonical(payload), hashlib.sha256).hexdigest()


class ChainedLog:
    def __init__(self, path: Path, key: bytes | None) -> None:
        self.path = path
        self.key = key

    # ----------------------------------------------------------------------------------
    # Reading
    # ----------------------------------------------------------------------------------

    def read(self) -> tuple[list[Any], Integrity, str | None]:
        """Every record in order, with the file's integrity and, when not clean, why.

        A torn *final* line is dropped and does not break the chain — it is what a crash
        mid-append leaves, and the next append truncates it. An unparseable line anywhere
        else is not a crash; it is an edit.
        """
        if not self.path.exists():
            return [], self._empty_state(), None

        raw_lines = self.path.read_bytes().split(b"\n")
        entries: list[tuple[int, Any]] = []
        garbled: str | None = None
        for number, raw in enumerate(raw_lines, start=1):
            if not raw.strip():
                continue
            try:
                entries.append((number, json.loads(raw)))
            except ValueError:
                if garbled is None and any(later.strip() for later in raw_lines[number:]):
                    garbled = f"line {number} is not valid JSON and is not the last line"

        if not entries:
            return [], (Integrity.BROKEN if garbled else self._empty_state()), garbled

        signed = [isinstance(obj, dict) and "record" in obj and bool(obj.get("mac")) for _, obj in entries]
        records = [obj["record"] if isinstance(obj, dict) and "record" in obj else obj for _, obj in entries]

        # The readable lines still load — the store's contract is that a damaged ledger opens
        # and says it is not evidence, rather than hiding everything behind one bad line.
        if garbled is not None:
            return records, Integrity.BROKEN, garbled
        if not any(signed):
            return records, Integrity.UNSIGNED, f"{self.path.name} was written without FAZEROPS_EVIDENCE_KEY"
        if not all(signed):
            number = entries[signed.index(False)][0]
            return records, Integrity.BROKEN, f"line {number} is unsigned in a signed ledger"
        if self.key is None:
            return records, Integrity.UNVERIFIED, f"{self.path.name} is signed, but no key is configured to verify it"

        expected = GENESIS
        for number, obj in entries:
            if obj.get("prev") != expected:
                return records, Integrity.BROKEN, f"line {number} does not follow the line before it (removed, inserted or reordered)"
            if not hmac.compare_digest(str(obj["mac"]), _mac(self.key, expected, obj["record"])):
                return records, Integrity.BROKEN, f"line {number} does not match its signature (edited, or signed with another key)"
            expected = obj["mac"]
        return records, Integrity.VERIFIED, None

    def _empty_state(self) -> Integrity:
        return Integrity.VERIFIED if self.key is not None else Integrity.UNSIGNED

    # ----------------------------------------------------------------------------------
    # Writing
    # ----------------------------------------------------------------------------------

    def append(self, records: list[Any]) -> None:
        if not records:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                tail = self._repair_and_read_tail(handle)
                signed = self._signing_mode(tail)
                prev = (tail["mac"] if tail is not None else GENESIS) if signed else None

                lines = []
                for record in records:
                    if signed:
                        assert self.key is not None and prev is not None
                        mac = _mac(self.key, prev, record)
                        lines.append({"prev": prev, "mac": mac, "record": record})
                        prev = mac
                    else:
                        lines.append({"prev": None, "mac": None, "record": record})
                handle.write(b"".join(json.dumps(line, ensure_ascii=False).encode("utf-8") + b"\n" for line in lines))
                handle.flush()
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _signing_mode(self, tail: dict | None) -> bool:
        """A file keeps the mode it was started in. A signed file never takes an unsigned line
        (that would break it for good); an unsigned file stays unsigned, and says so on read,
        rather than becoming a signed chain over an unverifiable prefix."""
        if tail is None:
            return self.key is not None
        tail_signed = "record" in tail and bool(tail.get("mac"))
        if tail_signed and self.key is None:
            raise LedgerIntegrityError(
                f"{self.path} is a signed ledger and FAZEROPS_EVIDENCE_KEY is not set: an unsigned "
                "append would break its chain permanently, so it is refused"
            )
        return tail_signed

    def _repair_and_read_tail(self, handle: Any) -> dict | None:
        """The last complete line, after truncating a torn one. Called under the lock."""
        size = handle.seek(0, 2)
        if size == 0:
            return None

        handle.seek(size - 1)
        if handle.read(1) != b"\n":
            cut = self._last_newline_before(handle, size)
            handle.truncate(cut)
            size = cut
            if size == 0:
                return None

        start = self._last_newline_before(handle, size - 1)
        handle.seek(start)
        raw = handle.read(size - start).strip()
        try:
            tail = json.loads(raw)
        except ValueError as exc:
            raise LedgerIntegrityError(f"{self.path}'s last complete line is not JSON: the chain cannot be continued") from exc
        return tail if isinstance(tail, dict) else {}

    @staticmethod
    def _last_newline_before(handle: Any, end: int) -> int:
        """Offset just past the last newline strictly before `end`, or 0."""
        position = end
        while position > 0:
            begin = max(0, position - _TAIL_CHUNK)
            handle.seek(begin)
            chunk = handle.read(position - begin)
            index = chunk.rfind(b"\n")
            if index != -1:
                return begin + index + 1
            position = begin
        return 0
