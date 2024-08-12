# Mnemonic convertion to seed and to/from bytes (borrowed from embit to optimize mnemonic_to_bytes)
# pylint: disable=W0102

import hashlib

from embit.wordlists.bip39 import WORDLIST

WORDINDEX = {word: i for i, word in enumerate(WORDLIST)}

def mnemonic_to_bytes(mnemonic: str, ignore_checksum: bool = False, wordlist=WORDLIST):
    """optimized replacement for embit.bip39.mnemonic_to_bytes() via an integer accumulator"""
    words = mnemonic.strip().split()
    if len(words) % 3 != 0 or len(words) < 12:
        raise ValueError("Invalid recovery phrase")

    accumulator = 0
    for word in words:
        try:
            if wordlist is WORDLIST:
                accumulator = (accumulator << 11) + WORDINDEX[word]
            else:
                accumulator = (accumulator << 11) + wordlist.index(word)
        except Exception:
            raise ValueError("Word '%s' is not in the dictionary" % word)

    entropy_length_bits = len(words) * 11 // 33 * 32
    checksum_length_bits = len(words) * 11 // 33
    checksum = accumulator & (2**checksum_length_bits - 1)
    accumulator >>= checksum_length_bits
    data = accumulator.to_bytes(entropy_length_bits // 8, "big")
    computed_checksum = hashlib.sha256(data).digest()[0] >> 8 - checksum_length_bits

    if not ignore_checksum and checksum != computed_checksum:
        raise ValueError("Checksum verification failed")
    return data


def mnemonic_is_valid(mnemonic: str, wordlist=WORDLIST):
    """Checks if mnemonic is valid (checksum and words)"""
    try:
        mnemonic_to_bytes(mnemonic, wordlist=wordlist)
        return True
    except Exception:
        return False
