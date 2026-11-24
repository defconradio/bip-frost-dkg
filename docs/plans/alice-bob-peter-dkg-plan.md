# Agent Plan: 2-of-3 ChillDKG Example (Alice, Bob, Peter)

## Goal
Create a runnable educational example demonstrating a 2-of-3 ChillDKG ceremony with Alice, Bob, and Peter, plus unit tests for existing and new code.

## Steps
1. Inspect `.github/workflows/` and `./all.sh` to validate CI workflow syntax and test commands.
2. Add `python/examples/alice_bob_peter_dkg.py` showing:
   - Key generation (`hostpubkey_gen`) for Alice, Bob, and Peter.
   - Happy-path 2-of-3 DKG session and threshold public key agreement.
   - Recovery scenario (`participant_recover`) if Peter loses state.
   - Faulty participant blame scenario (`participant_investigate`).
3. Add `python/tests/test_alice_bob_peter_dkg.py` testing the new example and existing core API functions.
4. Run `./all.sh` and validate GitHub Actions workflow syntax.
5. Open a PR into `master` with risk notes.

## Validation Criteria
- Existing tests and `./all.sh` pass.
- No modifications made to normative `python/chilldkg_ref/` code.
- PR includes risk notes and requires human approval before merge.
