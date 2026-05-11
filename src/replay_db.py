class ReplayProtectionDB:
    def __init__(self):
        self.used_tokens = set()
        self.used_nonces = set()

    def consume_token(self, token: str) -> bool:
        if token in self.used_tokens:
            return False

        self.used_tokens.add(token)
        return True

    def consume_nonce(self, nonce: str) -> bool:
        if nonce in self.used_nonces:
            return False

        self.used_nonces.add(nonce)
        return True