"""
salvatoshi's "A simple backup scheme for wallet accounts", on delving: 16 Apr 2025.

A backup scheme for wallet output descriptors where anyone with full descriptor
can create the backup and any of the cosigners with an xpub can decrypt it.

ref: https://delvingbitcoin.org/t/a-simple-backup-scheme-for-wallet-accounts/1607/5
"""

from embit import bip32
from hashlib import sha256
from Crypto.Cipher import AES
from random import randbytes

def get_descriptor(num_xpubs):
    """a fake descriptor (string w/ one xpub per line)"""
    return "\n".join(
        bip32.HDKey.from_seed(randbytes(64)).to_public().to_base58()
        for x in range(num_xpubs)
    )

def xpubs_from_descriptor(descriptor):
    """fake parsing of a descriptor to return a list of xpub strings"""
    assert isinstance(descriptor, str)
    return descriptor.split("\n")

def pubkey_from_xpub(xpub):
    """from xpub string return compressed pubkey bytestring"""
    assert isinstance(xpub, str)
    return bip32.HDKey.from_string(xpub).get_public_key().serialize()

def decryption_secret(pubkeys):
    """decryption secret is a hash with lexicographically sorted concatenation of pubkeys"""
    assert set([isinstance(x, bytes) for x in pubkeys]) == set([True])
    assert set([len(x) for x in pubkeys]) == set([33])
    return sha256(b"BACKUP_DECRYPTION_SECRET" + b"".join([x for x in sorted(pubkeys)])).digest()

def individual_secret(pubkey):
    """individual secret is a hash with a compressed pubkey, used to hide decryption_secret"""
    assert isinstance(pubkey, bytes) and len(pubkey) == 33 
    return sha256(b"BACKUP_INDIVIDUAL_SECRET" + pubkey).digest()

def xor_bytes(a, b):
    """XOR is used to combine/hide decryption_secret with each individual_secret"""
    assert isinstance(a + b, bytes) and len(a) == len(b)
    return bytes([(x ^ y) for x, y in zip(a, b)])

def aesgcm_encrypt(key, plaintext, nonce):
    """encrypt with AES in mode GCM"""
    assert isinstance(key, bytes) and isinstance(plaintext, str) and isinstance(nonce, bytes)
    cryptor = AES.new(key, AES.MODE_GCM, nonce)
    ciphertext = cryptor.encrypt(plaintext.encode())
    auth_tag = cryptor.digest()
    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "auth_tag": auth_tag
    }

def aesgcm_decrypt(key, payload):
    """decrypt with AES in mode GCM"""
    assert isinstance(key, bytes) and isinstance(payload, dict)
    cryptor = AES.new(key, AES.MODE_GCM, payload["nonce"], mac_len=len(payload["auth_tag"]))
    plaintext = cryptor.decrypt(payload["ciphertext"])
    cryptor.verify(payload["auth_tag"])  # may raise ValueError("MAC check failed")
    return plaintext.decode()

def do_backup(descriptor):
    """create and return a deterministic backup from a 'public' descriptor"""
    assert isinstance(descriptor, str)

    # parse xpubs from a wallet output descriptor
    xpubs = xpubs_from_descriptor(descriptor)
  
    # pubkeys are used to create the shared secret, and individual secrets
    pubkeys = [pubkey_from_xpub(x) for x in xpubs]

    # decryption key is a hash of lexicographically sorted pubkeys
    key = decryption_secret(pubkeys)

    # a plaintext ci for each pubkey (XOR-combined decryption key + individual secret)
    cis = [xor_bytes(key, individual_secret(x)) for x in pubkeys]

    # fake some natural entropy
    nonce = randbytes(16)
    
    # backup is the list of plaintext cis and ciphertext payload
    return {
        "cis": cis,
        "payload": aesgcm_encrypt(key, descriptor, nonce)
    }

def do_restore(backup, xpub):
    """restore a backup from a single xpub"""
    assert isinstance(backup, dict) and isinstance(xpub, str)

    # one of the cis reveals the correct key when combined with xpub's individual secret
    my_secret = individual_secret(pubkey_from_xpub(xpub))

    # attempt each `ci XOR my_secret` result as key to decrypt payload
    decrypted = None
    for ci in backup["cis"]:
        key = xor_bytes(ci, my_secret)
        try:
            decrypted = aesgcm_decrypt(key, backup["payload"])
            break
        except ValueError:  # MAC check failed
            pass
    assert decrypted
    return decrypted
        
def main(num_xpubs=3):
    """create a backup with multiple ci-keys + cipher payload, restore it with each xpub"""
    assert isinstance(num_xpubs, int)

    descriptor = get_descriptor(num_xpubs)

    # create an encrypted backup knowing only the descriptor
    backup = do_backup(descriptor)
    for i, ci in enumerate(backup["cis"]):
        print("c{}: ".format(i), ci.hex())
    print("payload: ", backup["payload"])

    # we'll test that all xpubs can restore backup
    xpubs = xpubs_from_descriptor(descriptor)

    # restore the backup knowing a single xpub
    for xpub in xpubs:
        restored = do_restore(backup, xpub)
        assert restored == descriptor
        print("\nrestored w/", xpub)

if __name__ == "__main__":
    main(num_xpubs=5)
