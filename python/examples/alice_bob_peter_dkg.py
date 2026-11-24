"""
Real-world 2-of-3 ChillDKG walkthrough with Alice, Bob, and Peter.

Run from the repository root:
    python3 python/examples/alice_bob_peter_dkg.py
"""

import os
import sys
from pathlib import Path

# Ensure `python/` is on sys.path so `chilldkg_ref` imports cleanly
REPO_PYTHON_DIR = Path(__file__).resolve().parents[1]
if str(REPO_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_PYTHON_DIR))

from chilldkg_ref.chilldkg import (
    FaultyParticipantOrCoordinatorError,
    SessionParams,
    UnknownFaultyParticipantOrCoordinatorError,
    coordinator_finalize,
    coordinator_investigate,
    coordinator_step1,
    hostpubkey_gen,
    params_hash,
    participant_finalize,
    participant_investigate,
    participant_recover,
    participant_recovery_ack_sign,
    participant_recovery_acks_verify,
    participant_step1,
    participant_step2,
)


def setup_participants():
    """Generate long-term host key pairs for Alice, Bob, and Peter (t = 2, n = 3)."""
    names = ["Alice", "Bob", "Peter"]
    host_seckeys = [os.urandom(32) for _ in names]
    host_pubkeys = [hostpubkey_gen(sk) for sk in host_seckeys]

    # Threshold t = 2 out of n = 3 participants
    params = SessionParams(hostpubkeys=host_pubkeys, t=2)

    # Out-of-band check: all participants compare this 32-byte hash before starting
    session_fingerprint = params_hash(params)
    print(f"Session Parameters Hash (verify out-of-band): {session_fingerprint.hex()}")
    return names, host_seckeys, params


def run_happy_path_ceremony(names, host_seckeys, params):
    """Scenario 1: Complete 2-of-3 DKG ceremony with recovery acknowledgments."""
    print("\n--- Scenario 1: 2-of-3 Happy-Path DKG Ceremony (Alice, Bob, Peter) ---")

    # Step 1: Each participant generates their first protocol message
    p_states1 = []
    p_msgs1 = []
    for name, sk in zip(names, host_seckeys):
        state1, pmsg1 = participant_step1(
            hostseckey=sk,
            params=params,
            random=os.urandom(32),
        )
        p_states1.append(state1)
        p_msgs1.append(pmsg1)
        print(f"  [Step 1] {name} sent pmsg1 ({len(pmsg1)} bytes)")

    # Coordinator aggregates round 1 messages
    coord_state, cmsg1 = coordinator_step1(pmsgs1=p_msgs1, params=params)

    # Step 2: Each participant verifies shares and produces their CertEq signature
    p_states2 = []
    p_msgs2 = []
    for name, sk, state1 in zip(names, host_seckeys, p_states1):
        state2, pmsg2 = participant_step2(
            hostseckey=sk,
            state1=state1,
            cmsg1=cmsg1,
            aux_rand=os.urandom(32),
        )
        p_states2.append(state2)
        p_msgs2.append(pmsg2)
        print(f"  [Step 2] {name} verified shares & signed transcript ({len(pmsg2)} bytes)")

    # Coordinator builds the success certificate
    cmsg2, coord_thresh_info, coord_recovery_data = coordinator_finalize(
        state=coord_state,
        pmsgs2=p_msgs2,
    )

    # Finalize: Each participant verifies the certificate and outputs their secret share
    results = []
    for name, state2 in zip(names, p_states2):
        secshare, thresh_info, recovery_data = participant_finalize(
            state2=state2,
            cmsg2=cmsg2,
        )
        results.append((secshare, thresh_info, recovery_data))
        print(f"  [Final]  {name} derived secret share & threshold pubkey: {thresh_info.thresh_pk.hex()}")

    # Verify all participants and coordinator agree on threshold_info and recovery_data
    assert all(r[1] == coord_thresh_info for r in results)
    assert all(r[2] == coord_recovery_data for r in results)

    # Optional Best Practice: Collect acknowledgment signatures before funding the wallet
    ack_sigs = [
        participant_recovery_ack_sign(
            hostseckey=sk,
            recovery_data=coord_recovery_data,
            params=params,
            aux_rand=os.urandom(32),
        )
        for sk in host_seckeys
    ]
    participant_recovery_acks_verify(
        recovery_data=coord_recovery_data,
        params=params,
        ack_sigs=ack_sigs,
    )
    print("  [Verified] All 3 participants acknowledged recovery data. Safe to fund wallet!")
    return results, coord_recovery_data


def run_peter_recovery_scenario(peter_seckey, expected_result, recovery_data):
    """Scenario 2: Peter's device crashes/reboots and recovers from hostseckey + recovery_data."""
    print("\n--- Scenario 2: Peter Recovers Lost Session State ---")
    expected_secshare, expected_thresh_info, _ = expected_result

    recovered_secshare, recovered_thresh_info, recovered_params = participant_recover(
        hostseckey=peter_seckey,
        recovery_data=recovery_data,
    )

    assert recovered_secshare == expected_secshare
    assert recovered_thresh_info == expected_thresh_info
    print(
        f"  [Recovered] Peter restored secret share ({len(recovered_secshare)} bytes) "
        f"for t={recovered_params.t}-of-{len(recovered_params.hostpubkeys)} wallet."
    )


def run_blame_investigation_scenario(names, host_seckeys, params):
    """Scenario 3: Peter sends a corrupted encrypted share; Alice detects & blames Peter."""
    print("\n--- Scenario 3: Faulty Participant Detection & Blame (Peter Corrupts Share) ---")

    p_states1 = []
    p_msgs1 = []
    for sk in host_seckeys:
        state1, pmsg1 = participant_step1(hostseckey=sk, params=params, random=os.urandom(32))
        p_states1.append(state1)
        p_msgs1.append(pmsg1)

    # In pmsg1 (size 33*t + 32*n + 97), encrypted shares start at offset 33*t + 97.
    # For t = 2, byte 163 is the first byte of the encrypted share intended for Alice (index 0).
    encrypted_share_for_alice_offset = 33 * params.t + 97
    corrupted_pmsg1_peter = bytearray(p_msgs1[2])
    corrupted_pmsg1_peter[encrypted_share_for_alice_offset] ^= 0xFF
    p_msgs1[2] = bytes(corrupted_pmsg1_peter)

    _, cmsg1 = coordinator_step1(pmsgs1=p_msgs1, params=params)

    # Alice (index 0) runs participant_step2 and detects an invalid aggregated secret share
    try:
        participant_step2(
            hostseckey=host_seckeys[0],
            state1=p_states1[0],
            cmsg1=cmsg1,
            aux_rand=os.urandom(32),
        )
        raise AssertionError("Expected Alice to abort due to corrupted share!")
    except UnknownFaultyParticipantOrCoordinatorError as err:
        print("  [Abort] Alice detected an invalid share, running investigation...")
        # Coordinator generates investigation messages for all participants
        cinvs = coordinator_investigate(pmsgs=p_msgs1, params=params)
        try:
            participant_investigate(error=err, cinv=cinvs[0])
        except FaultyParticipantOrCoordinatorError as blame_err:
            suspected_name = names[blame_err.participant_id]
            print(f"  [Blame] Alice pinpointed faulty participant ID {blame_err.participant_id}: {suspected_name}!")
            assert suspected_name == "Peter"


def main():
    names, host_seckeys, params = setup_participants()
    results, recovery_data = run_happy_path_ceremony(names, host_seckeys, params)
    run_peter_recovery_scenario(
        peter_seckey=host_seckeys[2],
        expected_result=results[2],
        recovery_data=recovery_data,
    )
    run_blame_investigation_scenario(names, host_seckeys, params)
    print("\nAll Alice, Bob, and Peter ChillDKG scenarios completed successfully!")


if __name__ == "__main__":
    main()

