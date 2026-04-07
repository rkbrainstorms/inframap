# Contributing to inframap

Thanks for wanting to contribute. inframap is built for the CTI community and contributions that make it more useful for analysts are very welcome.

---

## Core philosophy

**Zero external dependencies.** All pivot modules must use only Python stdlib (`urllib`, `json`, `hashlib`, `re`, `socket`, etc.). No `requests`, no `beautifulsoup4`, no `pandas`. This keeps inframap runnable on any Python 3.6+ system with zero setup.

If you want to add optional enhancements that use third-party libraries (e.g. `rich` for prettier terminal output), wrap them in a try/except and gracefully fall back to the existing plain output.

---

## How to add a new pivot source

1. Create `inframap/pivots/yoursource.py`
2. Implement a `pivot_yoursource(domain, ip, timeout)` function
3. Always return a dict with at minimum:
   ```python
   {
       "errors": [],      # list of error strings
       "query":  input,   # what was queried
   }
   ```
4. Wire it into `inframap/inframap.py` in `run_pivots()`
5. Add IOC extraction and findings in `inframap/engine/confidence.py`
6. Add a progress message: `_progress("YourSource", args.quiet)`
7. Update the `--skip` choices in `parse_args()`
8. Document it in `README.md` and `CHANGELOG.md`

**Only add sources that are genuinely free with no account required, or free with a simple account signup.** No enterprise tiers, no credit card required.

---

## How to add a new output format

1. Add your export function to `inframap/output/export.py`
2. Add the format name to the `-o` choices in `parse_args()`
3. Handle it in the output block in `main()`

---

## Reporting bugs

Open a GitHub issue with:
- Your Python version (`python3 --version`)
- The exact command you ran (redact any API keys)
- The full error output
- Operating system

---

## Pull request checklist

- [ ] No new external dependencies introduced
- [ ] New pivot sources use only free/no-key APIs
- [ ] Error handling returns errors in the `errors: []` list, never raises uncaught exceptions
- [ ] IOC output is defanged
- [ ] `CHANGELOG.md` updated
- [ ] `README.md` updated if user-facing behaviour changed

---

## Code style

- Python 3.6+ compatible
- No type hints required but welcome
- Functions over classes where possible
- Comments explaining *why*, not *what*
- Keep pivot modules self-contained — minimal imports from other inframap modules

---

## Questions

Open a GitHub issue tagged `question`. 

*Built by the CTI community, for the CTI community.*
