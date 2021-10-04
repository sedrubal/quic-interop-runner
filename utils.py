"""Some utils."""
import random
import string


def random_string(length: int):
    """Generate a random string of fixed length"""
    letters = string.ascii_lowercase

    return "".join(random.choice(letters) for i in range(length))
