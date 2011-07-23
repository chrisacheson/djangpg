from random import SystemRandom

def randstring(length):
    """
    Return a random base62 string of the specified length.
    """
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    string = ""
    rng = SystemRandom()

    for i in range(length): string += rng.choice(alphabet)

    return string
