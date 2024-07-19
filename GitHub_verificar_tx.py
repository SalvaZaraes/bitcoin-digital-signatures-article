import binascii
import hashlib
from bitcoin.core import b2x, COutPoint, CTransaction, CTxIn
from bitcoin.core.script import CScript, OP_CHECKSIG, OP_DUP, OP_HASH160, OP_EQUALVERIFY
import base58
import ecdsa
from ecdsa import SECP256k1, ellipticcurve

def extract_data(tx_data):
    """
    Extracts the data from the transaction the user passes.

    Args:
        tx_data (str): The transaction data in hexadecimal format.

    Returns:
        - r (str): The r component of the signature in hexadecimal format.
        - r_int (int): The r component of the signature as an integer.
        - s (str): The s component of the signature in hexadecimal format.
        - s_int (int): The s component of the signature as an integer.
        - sighash (str): The sighash flag of the signature in hexadecimal format.
        - pub (str): The public key in hexadecimal format.
    """
    tx = CTransaction.deserialize(bytes.fromhex(tx_data))
    script_sig_hex = b2x(tx.vin[0].scriptSig)

    sig_len = int(script_sig_hex[0:2], 16) * 2
    signature = script_sig_hex[2:2 + sig_len]

    r_len = int(signature[6:8], 16) * 2
    r = signature[8:8 + r_len]
    r_int = int(r, 16)

    s_len = int(signature[8 + r_len + 2:8 + r_len + 4], 16) * 2
    s = signature[8 + r_len + 4:8 + r_len + 4 + s_len]
    s_int = int(s, 16)

    sighash = signature[sig_len-2:sig_len]

    pub_len = int(script_sig_hex[2+sig_len:2+sig_len+2], 16) * 2
    pub = script_sig_hex[2+sig_len+2:2+sig_len+2+pub_len]

    return r, r_int, s, s_int, sighash, pub


def hash160(pk):
    """
    Hashes the public key provided in the Unlocking Script, obtaining the PubKeyHash.

    Args:
        pk (str): The public key in hexadecimal format.

    Returns:
        str: The resulting PubKeyHash in hexadecimal format.
    """
    sha256 = hashlib.sha256(bytes.fromhex(pk)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)

    return ripemd160.hexdigest()


def decode_base58(addr):
    """
    Decodes the address, obtaining the PubKeyHash.

    Args:
        addr (str): The Bitcoin address in Base58 format.

    Returns:
        tuple: A tuple containing:
            - pubkey_hash (bytes): The PubKeyHash in bytes.
            - pubkey_hash.hex() (str): The PubKeyHash in hexadecimal format.
    """
    n = base58.b58decode(addr)
    pubkey_hash = n[1:-4]

    return pubkey_hash, pubkey_hash.hex()


def double_sha256(data):
    """
    Double hashes the input data with SHA256.

    Args:
        data (bytes): The data to be hashed.

    Returns:
        bytes: The double SHA256 hash of the input data.
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def create_proto_tx(tx_data, pkh, sh):
    """
    Rebuilds the Proto-transaction used originally for signing.

    Args:
        tx_data (str): The transaction data in hexadecimal format.
        pkh (str): The PubKeyHash in hexadecimal format.
        sh (str): The sighash flag in hexadecimal format.

    Returns:
        tuple: A tuple containing:
            - proto_tx (bytes): The serialized proto-transaction.
            - proto_tx_double_hashed (bytes): The double SHA256 hash of the proto-transaction.
    """
    tx = CTransaction.deserialize(bytes.fromhex(tx_data))
    script_pubkey = CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])
    txin = CTxIn(COutPoint(tx.vin[0].prevout.hash, tx.vin[0].prevout.n), script_pubkey)
    txout = tx.vout[0]

    sighash_bytes = bytes.fromhex(sh)
    sighash_bytes = sighash_bytes[:4].ljust(4, b'\x00')

    new_tx = CTransaction([txin], [txout])

    proto_tx = new_tx.serialize() + sighash_bytes
    proto_tx_double_hashed = double_sha256(proto_tx)

    return proto_tx, proto_tx_double_hashed


def decompress_pubkey(pk):
    """
    Decompresses the Public Key provided in the Unlocking Script if needed.

    Args:
        pk (bytes): The compressed public key in bytes.

    Returns:
        bytes: The decompressed public key in bytes.
    """
    # ADAPTED FROM AVA CHOW'S CODE FOR UNCOMPRESSING PUBLIC KEYS PUBLISHED HERE: https://bitcoin.stackexchange.com/a/86239
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x = int.from_bytes(pk[1:], byteorder='big')
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y % 2 != pk[0] % 2:
        y = p - y
    y = y.to_bytes(32, byteorder='big')

    return pk[1:] + y


def verify_signature(public_key, r_input, s_input, message_hash_int):
    """
    Verifies the signature.

    Args:
        public_key (str): The public key in hexadecimal format.
        r_input (int): The r component of the signature.
        s_input (int): The s component of the signature.
        message_hash_int (int): The message hash as an integer.

    Returns:
        int: The v component of the ECDSA verification.
    """
    generator_point = ellipticcurve.Point(SECP256k1.curve, SECP256k1.generator.x(), SECP256k1.generator.y(), SECP256k1.order)

    pk_x = int(public_key[:64], 16)
    pk_y = int(public_key[64:], 16)

    if not SECP256k1.curve.contains_point(pk_x, pk_y):
        print("The provided public key does not correspond to a valid point on the SECP256k1 curve.")
        return

    public_key_point = ellipticcurve.Point(SECP256k1.curve, pk_x, pk_y, SECP256k1.order)
    public_key2 = ecdsa.VerifyingKey.from_public_point(public_key_point, curve=SECP256k1)

    c = pow(s_input, -1, SECP256k1.order)
    u1 = (message_hash_int * c) % SECP256k1.order
    u2 = (r_input * c) % SECP256k1.order
    u1G = u1 * generator_point
    u2PK = u2 * public_key2.pubkey.point
    v = (u1G + u2PK).x() % SECP256k1.order

    return v


if __name__ == "__main__":
    tx_hex = input("Input the TX in hex format: \n")
    input_address = input("\nInput the P2PKH address where the funds are being spent from: \n")

    #SOME EXAMPLES YOU CAN TRY.
    #02 means Public Key is compressed and the y coordinate is positive.
    #03 means Public Key is compressed and the y coordinate is negative.
    #04 means Public Key is uncompressed and contains both coordinates.

    #02
    #https://mempool.space/tx/b6f5cb50a8ec7017202efd3744a94c43a4898545ac82725b6cfbd7d89ba344a2
    #tx_hex = "01000000012a0113029e78de5a243b205e2ed2cf4f214015ba95221047774832f7059c04ba000000006b483045022100d79836dbd86162e3c3a38bbf31f6547c3600e4f52330a8d55aa591e8896d61900220332331d6d5c2c63db6174465aba6b848a4230ce943cffcf77ffdc02a30a8fbd70121020ce5eb2757373d469b59c971a498df4cf2484d52ef875024f1d924d22a0cc17cffffffff01a4180500000000001976a9142279f73d5766231f005e826577854decdce8d34688ac00000000"
    #03
    #https://mempool.space/tx/600b65de2e41849d3fbf22d94426b7b78edd305f3e600fafc2c91a597e53ffad
    #tx_hex = "010000000192bd56e01017e35ee18aac54b5e614a42122d0c127f4e365ff50ff6241d2d7e9000000006a47304402205a47e67b438d2982327f421a7bbeaff659a0ed5af5847bde3d967ca906e2da2d02203a70994c2aa0c6c1e59c5cdad073f22ef9abf38418b49d58515c53aac561754a0121035e9aaf7f03659fb14f3c2a3c4961130d5a823e741e797bcb508d57abb09ee944ffffffff012f1aa300000000001976a9140e6caf3974e72a33c33579f440e6a7b5447601ba88ac00000000"
    #04
    #https://mempool.space/tx/b691e6a8634a634a06b392a1e07dc593be5866692cfda77840f810330a79e848
    #tx_hex = "01000000010ea48b15d90ec59b85bf286f7a4a074fc9cacc1d3923203ea0e2daa065174660990200008a47304402205201c26a75f3f82292d44bda2b501be7291365f72cdaeb680f343a0da7d1ce4402205330000fba871073e5b3ff4947b95115f1292bc9fd31137ed84ff32c8fac5535014104fcf07bb1222f7925f2b7cc15183a40443c578e62ea17100aa3b44ba66905c95d4980aec4cd2f6eb426d1b1ec45d76724f26901099416b9265b76ba67c8b0b73dffffffff014a910100000000001976a914ad3ae74eb6e5e4d2fb4af733e306d9a2b8bfe4f088ac00000000"

    #02
    #input_address = "19rCYAVvroJXe5VuvzjBUgx4TSmBqjtAp9"
    #03
    #input_address = "1Pqef6VovhHmqBgeBEKAcNErKjnJLYRSLG"
    #04
    #input_address = "1Po1oWkD2LmodfkBYiAktwh76vkF93LKnh"

    r_extracted, r_extracted_int, s_extracted, s_extracted_int, sighash_extracted, pub_extracted = extract_data(tx_hex)
    print(f"\nr: {r_extracted}")
    print(f"s: {s_extracted}")
    print(f"Public Key: {pub_extracted}")
    print(f"SigHash: {sighash_extracted}")

    pubkeyhash_from_pubkey = hash160(pub_extracted)
    print(f"\nPublicKeyHash from Public Key: {pubkeyhash_from_pubkey}")

    pubkeyhash_from_address, pubkeyhash_from_addresshex = decode_base58(input_address)
    print(f"PublicKeyHash from Address: {pubkeyhash_from_addresshex}")
    print("OP_EQUALVERIFY: Are the same" if pubkeyhash_from_pubkey == pubkeyhash_from_addresshex else "Not the same\n")

    proto_tx, proto_tx_double_hashed = create_proto_tx(tx_hex, pubkeyhash_from_address, sighash_extracted)
    proto_tx_hash_int = int(proto_tx_double_hashed.hex(), 16)
    print(f"\nProto-transaction (HashPreimage): {proto_tx.hex()}")
    print(f"Hash of the ProtoTx: {proto_tx_double_hashed.hex()}\n")

    if pub_extracted[0:2] == "02" or pub_extracted[0:2] == "03":
        uncompressed = (binascii.hexlify(decompress_pubkey(binascii.unhexlify(pub_extracted))).decode())
        print(f"The PubKey has been uncompressed: {uncompressed}")
    else:
        uncompressed = pub_extracted[2:]
        print(f"The PubKey was already uncompressed: {uncompressed}")

    v_int = verify_signature(uncompressed, r_extracted_int, s_extracted_int, proto_tx_hash_int)
    print("\nOP_CHECKSIG: The signature is valid, v is equal to r. Therefore, the private key used to derive the public key (where the funds are being spent from) is the same one that was used to sign the transaction." if v_int == r_extracted_int else "Invalid Transaction")
