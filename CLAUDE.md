# Project Instructions — secure-p2p-filedrop

P2P encrypted file transfer over a manual (messenger-relayed) handshake. Start here: `docs/context.md` — overview, stack, entry points, handshake→channel→transfer lifecycle traced through actual function names. Then: `docs/architecture.md` (layers, test groups), `docs/concept.md` (protocol/security), `docs/dev-notes.md` (why-notes per module), `docs/testing.md` (manual checklists), `docs/cheet-shit.md` (commands).

## Tests — run only the affected group

Do NOT run the full suite by default. Look up groups in docs/architecture.md (section "Зміна → групи"), then:

    python tests/_groups.py <group> [<group>...]   # e.g. python tests/_groups.py data gui

Groups: handshake, data, profile, nat, transport, gui, cli (aliases: fast, all).
Run `all` only for tuning.py structure, tests/_pathfix.py, tests/_groups.py, bin/run-tests*, requirements.txt changes.
transport is slow/occasionally flaky — rerun once before investigating. gui skips without a display.

## Stack

Python 3.10+, stdlib `tkinter`/`ttk` GUI, stdlib sockets/HMAC/PBKDF2, plus `pyzipper` + `pycryptodomex` (`requirements.txt`) — the only external deps, both deliberate (AES ZIP archives / AES-256-CTR channel).

## Run the app

    python src/secure_file_drop_entry.py [--pswd/-p PASS] [--snd-dir DIR] [--port N]
    bin/secure-file-drop / bin\secure-file-drop.bat   # wrapper scripts

Two instances on one PC for manual testing: different `--port` per instance (see `docs/cheet-shit.md`).

## Code & comment conventions

- UI strings and code comments are in Ukrainian; keep new ones Ukrainian for consistency.
- Docstrings/comments often reference `docs/dev-notes.md` by section name (e.g. "докладніше: dev-notes.md") for the rationale behind a non-obvious choice — check there before assuming something is arbitrary; add a new dev-notes.md section (one section per code location) instead of a long inline comment for new non-obvious decisions.
- All tunable constants/defaults live in `src/tuning.py` (dataclasses, one per module, e.g. `ConnectionTuning`, `TransportTuning`) — never hardcode a magic number elsewhere; add it to `tuning.py` and reference it.
- Layering is strict and import-graph-enforced (see `docs/architecture.md`): `tuning.py` (L0, stdlib only) → L1 domain modules (each imports only `tuning.py`, no L1→L1 imports) → `appearance.py` (L2, GUI) → `secure_file_drop_entry.py` (L3, entry point). Don't introduce cross-L1 imports.
- `src/` is not a package — modules import each other directly (e.g. `from tuning import CONNECTION`); tests add `_pathfix` first line, not `tests/__init__.py`, to get `src/` on `sys.path`.

## Key constraint

Never build or host external infrastructure (relay/TURN, signaling server) — permanent architectural boundary, not a missing feature. A free public STUN service (address discovery only, no hosting) is acceptable. Connection fallback order: UPnP → STUN → LAN-only (fails P2P across strict NAT/CGNAT without UPnP, by design). Handshake data travels only through the user's own messenger channel.

## Working in this repo

- Don't commit unless explicitly asked.
- Docs are terse by design (recently compacted ~40%) — match that when editing them; don't re-add narrative prose.
