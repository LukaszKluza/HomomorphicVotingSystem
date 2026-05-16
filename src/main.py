from authority import AuthenticationAuthority, TallyAuthority
from trustee import Trustee
from voter import Voter
from voting_server import VotingServer


def main():
    print("=== INITIALIZING SYSTEM ===")

    auth = AuthenticationAuthority()

    tally = TallyAuthority()

    voting_server = VotingServer(
        auth.public_key,
        tally.paillier_pub,
    )

    trustees = [
        Trustee("TRUSTEE_A", tally.paillier_pub),
        Trustee("TRUSTEE_B", tally.paillier_pub),
        Trustee("TRUSTEE_C", tally.paillier_pub),
    ]

    print("=== CREATING VOTERS ===")

    voters = [
        Voter(
            auth,
            voting_server.public_key,
            tally.paillier_pub,
        )
        for _ in range(10)
    ]

    print("=== CASTING VOTES ===")

    for idx, voter in enumerate(voters):
        vote = idx % 2

        result = voting_server.process_ballot(
            voter.cast_vote(vote)
        )

        print(result)

    result = voting_server.process_ballot(
        voters[1].cast_vote(1)
    )

    print(result)

    result = voting_server.process_ballot(
        voters[0].cast_vote(1)
    )

    print(result)

    print("\n=== BULLETIN BOARD ===")

    _ = voting_server.board.list_ballots()

    print("\n=== ENCRYPTED TALLY ===")

    encrypted_sum = voting_server.encrypted_tally()

    print(encrypted_sum)

    print("\n=== DECRYPTING FINAL RESULT ===")

    result = tally.decrypt_tally(encrypted_sum)

    print(f"\nFINAL RESULT: {result}")

    print(f"BULLETIN BOARD STATS: {voting_server.board.stats}")

    print("\n=== TRUSTEE APPROVALS ===")
    print("(Quorum of 2/3 trustees must approve the tally for it to be accepted)")

    ciphertext = encrypted_sum.ciphertext(be_secure=False)
    proof = tally.chaum_pedersen_prove(ciphertext)

    approved_count = 0
    for trustee in trustees:
        approval = trustee.approve_tally(voting_server.board, proof, ciphertext)
        print(approval)
        if approval["approved"]:
            approved_count += 1

    print(f"\nTRUSTEE APPROVALS: {approved_count}/{len(trustees)}")
    print("TALLY ACCEPTED" if approved_count >= 2 else "TALLY REJECTED")

if __name__ == "__main__":
    main()