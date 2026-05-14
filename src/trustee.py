#TODO Make me pro
class Trustee:
    def __init__(self, trustee_id: str):
        self.trustee_id = trustee_id

    def approve_tally(self, tally_hash: str):
        return {
            "trustee": self.trustee_id,
            "approved": True,
            "tally_hash": tally_hash,
        }