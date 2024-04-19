import hashlib
import secrets
import ecdsa #0.18.0/0.19.0
from ecdsa import SECP256k1, ellipticcurve


def generate_keys():
    """Generates a private key."""
    private_key = secrets.randbits(256)
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, "big"), SECP256k1)
    sk_int = int.from_bytes(sk.to_string(), "big")
    generator_point = ellipticcurve.Point(SECP256k1.curve, SECP256k1.generator.x(), SECP256k1.generator.y(), SECP256k1.order)
    return sk, generator_point, sk_int


def hash_message(message):
    """Hashes a message using SHA-256."""
    return hashlib.sha256(message.encode('utf-8')).digest()


def sign_message(private_key, message_hash, generator_point, random_key):
    """Signs a message."""
    R = random_key * generator_point
    r = R.x() % SECP256k1.order
    sk_int = int.from_bytes(private_key.to_string(), "big")
    message_hash_int = int.from_bytes(message_hash, "big")
    s = (pow(random_key, -1, SECP256k1.order) * (message_hash_int + sk_int * r)) % SECP256k1.order
    return r, s, message_hash_int


def k_value_extraction(h1, h2, svalue1, svalue2):
    """Extracts the value of k used in ECDSA signing based on two message hashes and corresponding signature values."""
    s_diff_inv = pow((svalue1 - svalue2) % SECP256k1.order, -1, SECP256k1.order)
    return ((h1 - h2) % SECP256k1.order * s_diff_inv) % SECP256k1.order


def sk_value_extraction(rvalue, svalue1, kvalue, h1):
    """Extracts the private key used in ECDSA signing based on signature values, message hash, and the value of k."""
    r_inv = pow(rvalue, -1, SECP256k1.order)
    return ((((svalue1*kvalue) % SECP256k1.order - h1) % SECP256k1.order) * r_inv) % SECP256k1.order


if __name__ == "__main__":

    sk, g, sk_int = generate_keys()
    random_key = secrets.randbelow(SECP256k1.order)
    print(f"Your randomly generated private key:\n{sk.to_string().hex()}")
    print(f"\nThe value k that's it's going to be used in both signing processes:\n{hex(random_key)[2:]}\n")

    message = input("\nEnter the first message to sign: ")
    k_inputed_1 = int(input("Enter the value of k: "), base=16)
    message_hash = hash_message(message)
    r, s, messagehashint1 = sign_message(sk, message_hash, g, k_inputed_1)
    print(f"Signature: (r= {hex(r)[2:]}, s= {hex(s)[2:]})\n")

    message2 = input("\nEnter the second message to sign: ")
    k_inputed_2 = int(input("Enter once more the value of k: "), base=16)
    message_hash2 = hash_message(message2)
    r2, s2, messagehashint2 = sign_message(sk, message_hash2, g, k_inputed_2)
    print(f"Signature: (r= {hex(r2)[2:]}, s= {hex(s2)[2:]})\n")

    print("\nEXTRACTION OF K AND PRIVATE KEY")

    extractedK = k_value_extraction(messagehashint1, messagehashint2, s, s2)
    print("\nThe value of k has been extracted correctly using both signatures and messages" if extractedK == random_key else "NO, they are not equal")
    print(f"Your k value was= {hex(random_key)[2:]}")
    print(f"Extracted k value= {hex(extractedK)[2:]}")

    extractedSk = sk_value_extraction(r, s, extractedK, messagehashint1)
    print("\nThe value of your private key has been extracted correctly" if extractedSk == sk_int else "NO, they are not equal")
    print(f"Your Private Key was= {sk.to_string().hex()}")
    print(f"Extracted Key= {hex(extractedSk)[2:]}")

    print("\nAND THAT'S WHY YOU SHOULD NEVER USE TWICE THE SAME K VALUE" if extractedSk == sk_int else "")
