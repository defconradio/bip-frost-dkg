import os
import subprocess
import sys
import unittest
from pathlib import Path

# Ensure `python/` is on sys.path so `examples` and `chilldkg_ref` import cleanly
# PYTHON_DIR = Path(__file__).resolve().parents
PYTHON_DIR = Path(__file__).resolve().parents[1]

if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from chilldkg_ref.chilldkg import (
    DuplicateHostPubkeyError,
    HostSeckeyError,
    RandomnessError,
    SessionParams,
    ThresholdOrCountError,
    hostpubkey_gen,
    participant_step1,
)
from examples.alice_bob_peter_dkg import (
    run_blame_investigation_scenario,
    run_happy_path_ceremony,
    run_peter_recovery_scenario,
    setup_participants,
)


class TestAliceBobPeterDKG(unittest.TestCase):
    def test_example_script_exits_with_status_zero(self) -> None:
        """Verify the standalone example script runs end-to-end and returns exit code 0."""
        script_path = PYTHON_DIR / "examples" / "alice_bob_peter_dkg.py"
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode, 0, f"Script failed with stderr:\n{result.stderr}"
        )
        self.assertIn(
            "All Alice, Bob, and Peter ChillDKG scenarios completed successfully!",
            result.stdout,
        )

    def test_alice_bob_peter_ceremony_and_recovery(self) -> None:
        """Test 2-of-3 DKG ceremony agreement and Peter's device recovery."""
        names, host_seckeys, params = setup_participants()
        results, recovery_data = run_happy_path_ceremony(names, host_seckeys, params)

        # All 3 participants must derive distinct 32-byte secret shares
        secret_shares = [r[0] for r in results]
        self.assertEqual(len(set(secret_shares)), 3)
        self.assertTrue(all(len(share) == 32 for share in secret_shares))

        # Peter (index 2) recovers identical outputs from hostseckey + recovery_data
        run_peter_recovery_scenario(
            peter_seckey=host_seckeys[2],
            expected_result=results[2],
            recovery_data=recovery_data,
        )

    def test_peter_corrupt_share_triggers_blame(self) -> None:
        """Test that a corrupted share aborts and pinpoints Peter (index 2)."""
        names, host_seckeys, params = setup_participants()
        run_blame_investigation_scenario(names, host_seckeys, params)

    def test_existing_chilldkg_guardrails(self) -> None:
        """Unit tests covering existing ChillDKG input validation and error handling."""
        sk1 = os.urandom(32)
        sk2 = os.urandom(32)
        pk1 = hostpubkey_gen(sk1)
        pk2 = hostpubkey_gen(sk2)

        # 1. Invalid host secret key (all zeroes) must fail
        with self.assertRaises(HostSeckeyError):
            hostpubkey_gen(b"\x00" * 32)

        # 2. Duplicate host public keys must fail
        with self.assertRaises(DuplicateHostPubkeyError):
            participant_step1(
                hostseckey=sk1,
                params=SessionParams(hostpubkeys=[pk1, pk1], t=2),
                random=os.urandom(32),
            )

        # 3. Invalid threshold (t > n) must fail
        with self.assertRaises(ThresholdOrCountError):
            participant_step1(
                hostseckey=sk1,
                params=SessionParams(hostpubkeys=[pk1, pk2], t=3),
                random=os.urandom(32),
            )

        # 4. All-zero randomness must raise RandomnessError
        with self.assertRaises(RandomnessError):
            participant_step1(
                hostseckey=sk1,
                params=SessionParams(hostpubkeys=[pk1, pk2], t=2),
                random=b"\x00" * 32,
            )


if __name__ == "__main__":
    unittest.main()
