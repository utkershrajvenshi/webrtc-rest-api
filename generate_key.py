import uuid

# function for generating a randomized UUID key
def generateAPIKey():
    return uuid.uuid4().hex