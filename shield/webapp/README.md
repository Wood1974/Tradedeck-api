# Shield — standalone client

One HTML file. Open `shield.html` from disk and it works: no server, no build,
no install, no network. That is a requirement rather than a flourish — the
person this is for was handed an evidence package by a party they are in
dispute with, and is as likely to be a claims adjuster with a zip file as a
developer with a terminal.

Standalone in the other sense too: no TradeDeck, no Supabase SDK, no hardcoded
tenant. The service URL is typed in. Shield is a verification primitive several
businesses can point at, not one company's feature.

## What each tab is worth

| Tab | Needs | How far it has been checked |
|---|---|---|
| **Verify a package** | nothing | Differentially tested against `ledger.py`, the implementation that writes production chains, plus driven in a real browser |
| **Price list** | nothing | Reads `GET /shield/public/pricing` |
| **Outcomes** | nothing | Reads `GET /shield/public/results` |
| **Record a job** | a bearer token | **Never run against a live service.** A reference client |

That table is the honest ranking, and the gap between row one and row four is
wide. Read it before relying on either end of it.

## Verify

Drop in the package JSON. The chain is checked in the page — nothing is
uploaded and no request is made, which matters for a reason beyond privacy: a
request at that moment tells somebody you are checking. Turn your network off
first if you would like to confirm it; a browser test asserts the same thing.

**Supply the head hash if you have one.** A chain with entries deleted from the
end verifies perfectly — every remaining link is intact and the package simply
states a shorter head. Nothing inside the package detects that. The only thing
that does is a head hash you already held, from a close-out packet or an email,
before the package in front of you was produced. Without one the page says so
rather than showing a clean result.

Three outcomes are distinguished on purpose:

- **Verified** — every link recomputes, and if you supplied a head, the chain
  ends there.
- **Does not verify** — with the entry number and what went wrong.
- **Cannot be checked here** — a known limit of the format, not a finding
  against anyone. See below.

## The limit you will hit first

`event_data` can hold a whole number, and JSON cannot record whether Python
sealed it as `100` or `100.0`. Those hash differently. The browser verifier
enumerates the readings, and if one of them explains the mismatch it reports
**ambiguous** rather than tampering — because accusing an honest contractor
over a trailing zero is the worst thing this software could do, and a reader
cannot tell that accusation from a real one.

This is not rare. Close-out seals `score` and `coverage_pct`, both from
`round()`, both very often integral — so the single most important entry in a
clean record is the one this cannot confirm. Use `verifier/shield_verify.py`
for those; it reads the original types.

The real fix is a chain format that cannot be read two ways. That is a
`chain_version` bump, so it is the owner's call and not this directory's.

## Build

Sources are separate for reading and testing; `shield.html` is generated.

```
python webapp/build.py
```

Re-run it after changing `page.html`, `styles.css`, `verify.js`, `api.js` or
`app.js`. The `webapp-bundle-current` invariant fails the build if you forget,
because a stale bundle means the file people open is not the code that was
reviewed.

The bundle exists because `<script type="module" src="…">` cannot be loaded
from `file://` — Chromium refuses it as a CORS failure, and the page renders
its markup and then does nothing at all. A browser test caught that; nothing
else would have, since every casual check happens through a dev server.

## Tests

```
python -m pytest tests/test_webapp_verifier.py   # vs ledger.py, needs node
python -m pytest tests/test_webapp_browser.py    # vs a real browser
```

Both skip rather than fail when their tool is missing.

The verifier tests are differential, not example-based, because JavaScript and
Python genuinely disagree about rendering the same value — `40.0` is `"40"` in
one and `"40.0"` in the other; `'é'` is escaped by one and not the other.
Neither difference throws. Each produces a different hash, so a verdict of
BROKEN on an intact package. Hand-picked examples would have passed: real GPS
coordinates round-trip identically, so the realistic payload works while an
integral latitude fails.

## What a verified result does not establish

That a photograph came off a camera sensor rather than a file picker. That
entries were never omitted *before* the chain was written — the chain proves
nothing was changed afterwards, not that everything was recorded. That any
assessment in the record is correct, or that work complies with any code.

See `../SPEC.md` §6, `../audit/accepted-risks.md`, and `../audit/CLAIMS.md`,
which lists what this product has not yet earned the right to say.
