class InvalidVoteException(Exception):
    def __init__(self):
        super().__init__('Invalid vote excepion')
