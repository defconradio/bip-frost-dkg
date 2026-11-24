---
applyTo: "python/**"
---
- When writing new examples, model the session flow after `python/example.py` (`hostpubkey_gen` -> `participant_step1` -> `coordinator_step1` -> `participant_step2` -> `coordinator_finalize` -> `participant_finalize`).
- Use realistic participant names (`Alice`, `Bob`, `Peter`) for 2-of-3 threshold scenarios (`t = 2, n = 3`).
- Every new example must include corresponding unit tests covering success, recovery, and faulty-party blame.
