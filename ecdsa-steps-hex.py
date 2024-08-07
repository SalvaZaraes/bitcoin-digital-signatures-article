import hashlib
import secrets
import ecdsa #0.18.0/0.19.0
from ecdsa import SECP256k1, ellipticcurve


def generate_keys():
    """Generates a private and public key pair."""
    # Generate a random 256-bit integer as a private key
    private_key = secrets.randbits(256)
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, byteorder="big"), curve=SECP256k1)
    sk_int = int.from_bytes(sk.to_string(), byteorder="big")

    # Calculate the public key using the private key
    generator_point = ellipticcurve.Point(SECP256k1.curve, SECP256k1.generator.x(), SECP256k1.generator.y(), SECP256k1.order)
    pk = generator_point * sk_int
    public_key = ecdsa.VerifyingKey.from_public_point(pk, curve=SECP256k1)

    return sk, public_key, generator_point


def hash_message(message):
    """Hashes a message using double SHA-256."""
    return hashlib.sha256(hashlib.sha256(message.encode('utf-8')).digest()).digest()

def print_keys(key):
    """Changes the format of a key to print it in Hexadecimal"""
    printable_key = key.to_string().hex()
    return printable_key


def sign_message(private_key, message_hash, generator_point, random_key):
    """Signs a message."""
    R = random_key * generator_point
    r = R.x() % SECP256k1.order
    sk_int = int.from_bytes(private_key.to_string(), byteorder="big")
    message_hash_int = int.from_bytes(message_hash, byteorder="big")
    s = (pow(random_key, -1, SECP256k1.order) * (message_hash_int + sk_int * r)) % SECP256k1.order

    return r, s


def verify_signature(public_key, r_input, s_input, generator_point, verification_message):
    """Verifies a signature."""
    # Convert the public key input from decimal to a point on the elliptic curve
    pk_x = int(public_key[:64], 16)
    pk_y = int(public_key[64:], 16)

    # Check if the point is on the curve
    if not SECP256k1.curve.contains_point(pk_x, pk_y):
        print("The provided public key does not correspond to a valid point on the SECP256k1 curve.")
        return

    public_key_point = ellipticcurve.Point(SECP256k1.curve, pk_x, pk_y, SECP256k1.order)
    public_key2 = ecdsa.VerifyingKey.from_public_point(public_key_point, curve=SECP256k1)

    # Hash the message
    verification_hash = hash_message(verification_message)

    # Continue with verification as before
    message_hash_int = int.from_bytes(verification_hash, byteorder="big")
    c = pow(s_input, -1, SECP256k1.order)
    u1 = (message_hash_int * c) % SECP256k1.order
    u2 = (r_input * c) % SECP256k1.order
    u1G = u1 * generator_point
    u2PK = u2 * public_key2.pubkey.point
    v = (u1G + u2PK).x() % SECP256k1.order

    return v


if __name__ == "__main__":
    print("\nProcess: Generating Keys\n")
    sk, public_key, g = generate_keys()
    print(f"Keys:\nPrivateKey= {print_keys(sk)}\nPublicKey= {print_keys(public_key)}\n\n")

    print("\nProcess: Signing\n")
    message = input("Enter the message to sign: ")
    message_hash = hash_message(message)
    random_key = secrets.randbelow(SECP256k1.order)
    r, s = sign_message(sk, message_hash, g, random_key)
    print(f"\nSignature: (r= {hex(r)[2:]}, s= {hex(s)[2:]})\n\n")

    print("\nProcess: Verifying\n")
    public_key_input = input("Enter the public key: ")
    r_input = int(input("Enter the value of r: "), base=16)
    s_input = int(input("Enter the value of s: "), base=16)
    verification_message = input("Enter the message for verification: ")

    v = verify_signature(public_key_input, r_input, s_input, g, verification_message)
    print(f'\nThe value of v= {hex(v)[2:]}')

    # Print verification result
    print("\nThe signature is valid, v is equal to r. Therefore, the private key used to derive the public key is the same one that was used to sign the message." if v == r_input else "\nThe signature is not valid, v is not equal to r")
    
