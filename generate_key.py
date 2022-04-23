import uuid

class GenerateAPIKey:
    def __init__(self) -> None:
        return uuid.uuid4().hex