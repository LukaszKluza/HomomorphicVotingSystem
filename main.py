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
        Trustee("TRUSTEE_A"),
        Trustee("TRUSTEE_B"),
        Trustee("TRUSTEE_C"),
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

    accepted = 0

    # for idx, voter in enumerate(voters):
    #     vote = idx % 2

    #     result = voting_server.process_ballot(
    #         voter.cast_vote(vote)
    #     )

    #     print(result)

    #     if (
    #         isinstance(result, dict)
    #         and result.get("status") == "ACCEPTED"
    #     ):
    #         accepted += 1

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

    print(f"ACCEPTED BALLOTS: {accepted}")

    print("\n=== TRUSTEE APPROVALS ===")

    for trustee in trustees:
        approval = trustee.approve_tally(
            str(result)
        )

        print(approval)


if __name__ == "__main__":
    main()