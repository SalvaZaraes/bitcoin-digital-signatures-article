import binascii
import hashlib
from bitcoin.core import b2x, COutPoint, CTransaction, CTxIn, CTxOut
from bitcoin.core.script import CScript, OP_CHECKSIG, OP_DUP, OP_HASH160, OP_EQUALVERIFY
import ecdsa
from ecdsa import SECP256k1, ellipticcurve
from enum import Enum

class InputType(Enum):
    """Enumeration representing the types of compatible Bitcoin input scripts."""
    P2PK = "P2PK"     # Pay-to-PublicKey
    P2PKH = "P2PKH"   # Pay-to-PublicKey-Hash
    SegWit = "SegWit" # Pay-to-Witness-

class Transaction:
    """
    Represents a Bitcoin transaction, with methods for accessing transaction details,
    computing preimages, and verifying signatures.
    """

    def __init__(self, hex_str):
        """
        Initializes a Transaction instance by deserializing a hexadecimal transaction string.

        Args:
            hex_str (str): The hexadecimal string of the transaction.
        """
        self.tx = CTransaction.deserialize(bytes.fromhex(hex_str))
        self.values = self.getValues()

    def getDHash(self, data):
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def getlocktime(self):
        """Returns the lock time of the transaction."""
        return self.tx.nLockTime

    def getnversion(self):
        """Returns the nVersion of the transaction."""
        return self.tx.nVersion

    def getNSequence(self, index):
        """Returns the nSequence of the input."""
        return self.tx.vin[index].nSequence

    def getNumberInputs(self):
        """Returns the number of inputs in the transaction."""
        return len(self.tx.vin)

    def getNumberOutputs(self):
        """Returns the number of outputs in the transaction."""
        return len(self.tx.vout)

    def getValues(self):
        """
        Extract cryptographic values (r, s, sighash, pubkey) from each input's unlocking data.
        For legacy inputs (P2PKH, P2PK), data comes from scriptSig.
        For SegWit inputs (P2WPKH, etc.), data comes from the witness field.

        Returns:
            list[tuple]: (r, s, sighash, pubkey) for each input.
        """
        inputs_data = []
        
        for i in range(self.getNumberInputs()):
            input_type = self.getInputType(i)

            # --------------------
            # LEGACY: P2PKH or P2PK
            # --------------------
            if input_type in (InputType.P2PKH, InputType.P2PK):
                script_sig_hex = b2x(self.tx.vin[i].scriptSig)
                
                # Signature
                sig_len = int(script_sig_hex[0:2], 16) * 2
                signature = script_sig_hex[2:2 + sig_len]
                
                # r
                r_len = int(signature[6:8], 16) * 2
                r = signature[8:8 + r_len]
                
                # s
                s_len = int(signature[8 + r_len + 2:8 + r_len + 4], 16) * 2
                s = signature[8 + r_len + 4:8 + r_len + 4 + s_len]
                
                # sighash
                sighash = signature[sig_len - 2:sig_len]

                # Public key
                if input_type == InputType.P2PKH:
                    pub_len = int(script_sig_hex[2 + sig_len:2 + sig_len + 2], 16) * 2
                    pub = script_sig_hex[2 + sig_len + 2:2 + sig_len + 2 + pub_len]
                else:  # P2PK
                    pub = input(f"Please input the public key of input {i}: ")

                inputs_data.append((r, s, sighash, pub))

            # --------------------
            # SEGWIT: Witness inputs (P2WPKH)
            # --------------------
            elif input_type == InputType.SegWit:
                txin_witness = self.tx.wit.vtxinwit[i]
                stack_items = txin_witness.scriptWitness.stack
                sig_wit = b2x(stack_items[0])
                
                r_len = int(sig_wit[6:8], 16) * 2
                r = sig_wit[8:8 + r_len]

                s_len = int(sig_wit[8 + r_len + 2:8 + r_len + 4], 16) * 2
                s = sig_wit[8 + r_len + 4:8 + r_len + 4 + s_len]

                sighash = sig_wit[-2:]

                pub_wit = b2x(stack_items[1])

                inputs_data.append((r, s, sighash, pub_wit))


        return inputs_data

    def getR(self, index):
        """Returns the 'r' value of the signature for a specific input."""
        return self.values[index][0]

    def getRInt(self, index):
        """Returns the integer representation of 'r' for a specific input."""
        return int(self.getR(index), 16)

    def getS(self, index):
        """Returns the 's' value of the signature for a specific input."""
        return self.values[index][1]

    def getSInt(self, index):
        """Returns the integer representation of 's' for a specific input."""
        return int(self.getS(index), 16)

    def getSigHash(self, index):
        """Returns the sighash type of the signature for a specific input."""
        return self.values[index][2]

    def getPk(self, index):
        """Returns the public key for a specific input."""
        return self.values[index][3]

    def getPkHash(self, index):
        """
        Calculates the RIPEMD-160 hash of the SHA-256 hash of the public key.

        Args:
            index (int): Index of the input in the transaction.

        Returns:
            str: Public key hash in hexadecimal format.
        """
        sha256 = hashlib.sha256(bytes.fromhex(self.getPk(index))).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256)
        return ripemd160.hexdigest()

    def getPkUncompressed(self, pktouncompress):
        """
        Uncompresses a compressed public key.  ADAPTED FROM AVA CHOW'S CODE FOR UNCOMPRESSING PUBLIC KEYS PUBLISHED HERE: https://bitcoin.stackexchange.com/a/86239

        Args:
            pktouncompress (bytes): Compressed public key.

        Returns:
            bytes: Uncompressed public key.
        """
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        x = int.from_bytes(pktouncompress[1:], byteorder='big')
        y_sq = (pow(x, 3, p) + 7) % p
        y = pow(y_sq, (p + 1) // 4, p)
        if y % 2 != pktouncompress[0] % 2:
            y = p - y
        y = y.to_bytes(32, byteorder='big')
        return pktouncompress[1:] + y

    def getPkVerify(self, index):
        """
        Verifies and returns the public key as an ECDSA VerifyingKey.

        Args:
            index (int): Index of the input in the transaction.

        Returns:
            ecdsa.VerifyingKey or None: The VerifyingKey if the public key is valid, otherwise None.
        """
        pub_extracted = self.getPk(index)
        if pub_extracted[0:2] == "02" or pub_extracted[0:2] == "03":
            uncompressed = binascii.hexlify(self.getPkUncompressed(binascii.unhexlify(pub_extracted))).decode()
        else:
            uncompressed = pub_extracted[2:]

        pk_x = int(uncompressed[:64], 16)
        pk_y = int(uncompressed[64:], 16)

        if not SECP256k1.curve.contains_point(pk_x, pk_y):
            print("The provided public key does not correspond to a valid point on the SECP256k1 curve.")
            return None

        public_key_point = ellipticcurve.Point(SECP256k1.curve, pk_x, pk_y, SECP256k1.order)
        return ecdsa.VerifyingKey.from_public_point(public_key_point, curve=SECP256k1)

    def getInputType(self, index):
        """
        Determines the input type based on the unlocking script.

        Args:
            index (int): Index of the input in the transaction.

        Returns:
            InputType: Enum value representing the input type.
        """
        script_sig_hex = b2x(self.tx.vin[index].scriptSig)
        if len(script_sig_hex) == 0:
            return InputType.SegWit
        else:
            if len(script_sig_hex) <= 160:
                return InputType.P2PK
            else:
                return InputType.P2PKH

    def getPreimage(self, index):
        """
        Generates the preimage of a certain input of the transaction for the signature verification.

        Args:
            index (int): Index of the input in the transaction.

        Returns:
            bytes: Serialized preimage.
        """
        # --------------------
        # LEGACY: P2PKH or P2PK
        # --------------------
        if self.getInputType(index) in (InputType.P2PKH, InputType.P2PK):

            if self.getInputType(index) == InputType.P2PKH:
                script_pubkey = CScript([OP_DUP, OP_HASH160, bytes.fromhex(self.getPkHash(index)), OP_EQUALVERIFY, OP_CHECKSIG])

            if self.getInputType(index) == InputType.P2PK:
                script_pubkey = CScript([bytes.fromhex(self.getPk(index)), OP_CHECKSIG])

            if self.getSigHash(index) in ["01", "02", "03"]:           
                inputs = []
                for i in range(self.getNumberInputs()):
                    if i == index:
                        inputs.append(CTxIn(COutPoint(self.tx.vin[index].prevout.hash, self.tx.vin[index].prevout.n), script_pubkey, nSequence=self.getNSequence(index)))
                    else:
                        if self.getSigHash(index) == "01":
                            inputs.append(CTxIn(COutPoint(self.tx.vin[i].prevout.hash, self.tx.vin[i].prevout.n), nSequence=self.getNSequence(index)))
                        elif self.getSigHash(index) in {"02", "03"}:
                            inputs.append(CTxIn(COutPoint(self.tx.vin[i].prevout.hash, self.tx.vin[i].prevout.n), nSequence=0))

                if self.getSigHash(index) == "01": # ALL
                    outputs = [self.tx.vout[i] for i in range(self.getNumberOutputs())]
                    preimage = CTransaction(inputs, outputs, nLockTime=self.getlocktime(), nVersion=self.getnversion())
                if self.getSigHash(index) == "02": # NONE
                    preimage = CTransaction(inputs, nLockTime=self.getlocktime(), nVersion=self.getnversion())
                if self.getSigHash(index) == "03": # SINGLE
                    
                    if index == 0:
                        outputs = [self.tx.vout[index]]

                    if index > 0:
                        outputs = []
                        for i in range(len(self.tx.vout)):

                            if i == index and index < len(self.tx.vout):  # Si hay un output correspondiente
                                outputs.append(self.tx.vout[i])

                            if i != index and index < len(self.tx.vout):  # Si no hay más outputs disponibles, añadir un dummy output
                                outputs.append(CTxOut()) 

                            if i != index and index >= len(self.tx.vout):  # Caso especial SINGLE nIn > nOut
                                return int.from_bytes(b'\x01' + b'\x00' * 31, byteorder='big')
                                
                    preimage = CTransaction(inputs, outputs, nLockTime=self.getlocktime(), nVersion=self.getnversion())

            if self.getSigHash(index) in ["81", "82", "83"]:
                inputs = [CTxIn(COutPoint(self.tx.vin[index].prevout.hash, self.tx.vin[index].prevout.n), script_pubkey, nSequence=self.getNSequence(index))]

                if self.getSigHash(index) == "81": # ALL | ANYONECANPAY
                    outputs = [self.tx.vout[i] for i in range(self.getNumberOutputs())]
                    preimage = CTransaction(inputs, outputs, nLockTime=self.getlocktime(), nVersion=self.getnversion())
                if self.getSigHash(index) == "82": # NONE | ANYONECANPAY
                    preimage = CTransaction(inputs, nLockTime=self.getlocktime(), nVersion=self.getnversion())
                if self.getSigHash(index) == "83": # SINGLE | ANYONECANPAY
                    
                    if index == 0:
                        outputs = [self.tx.vout[index]]

                    if index > 0:
                        outputs = []
                        for i in range(len(self.tx.vout)):

                            if i == index and index < len(self.tx.vout):  # Si hay un output correspondiente
                                outputs.append(self.tx.vout[i])

                            if i != index and index < len(self.tx.vout):  # Si no hay más outputs disponibles, añadir un dummy output
                                outputs.append(CTxOut()) 

                            if i != index and index >= len(self.tx.vout):  # Caso especial SINGLE nIn > nOut
                                return int.from_bytes(b'\x01' + b'\x00' * 31, byteorder='big')
                                
                    preimage = CTransaction(inputs, outputs, nLockTime=self.getlocktime(), nVersion=self.getnversion())

            sighash_bytes = bytes.fromhex(self.getSigHash(index))
            sighash_bytes = sighash_bytes[:4].ljust(4, b'\x00')
            
            return preimage.serialize() + sighash_bytes
    
        # --------------------
        # SEGWIT: Witness inputs (P2WPKH)
        # --------------------
        elif self.getInputType(index) == InputType.SegWit:

            script_pubkey = CScript([OP_DUP, OP_HASH160, bytes.fromhex(self.getPkHash(index)), OP_EQUALVERIFY, OP_CHECKSIG])

            prevOutputValue = int(input(f"Enter input {index}'s amount in Sats: ")).to_bytes(8, "little")

            nVersion = self.getnversion().to_bytes(4, "little")

            nLockTime = self.getlocktime().to_bytes(4, "little")

            if self.getSigHash(index) in ["01", "02", "03"]:
                prevouts = []
                for i in range(self.getNumberInputs()):
                    prevouts.append(self.tx.vin[i].prevout.hash)
                    prevouts.append(self.tx.vin[i].prevout.n.to_bytes(4, "little"))
                hashPrevouts = self.getDHash(b"".join(prevouts))

            elif self.getSigHash(index) in ["81", "82", "83"]:
                hashPrevouts = b'\x00' * 32

            txin = [
                self.tx.vin[index].prevout.hash,
                self.tx.vin[index].prevout.n.to_bytes(4, "little"),
                b'\x19',
                script_pubkey,
                prevOutputValue,
                self.getNSequence(index).to_bytes(4, "little")
            ]
                
            txin_bytes = b''.join(txin)

            if self.getSigHash(index) in {"02", "03", "81", "82", "83"}:
                hashSequences = b'\x00' * 32
            else: #SigHash "01"
                sequences = []
                for i in range(self.getNumberInputs()):
                    sequences.append(self.getNSequence(i).to_bytes(4, "little"))
                hashSequences = self.getDHash(b"".join(sequences))

            if self.getSigHash(index) in {"01", "81"}:

                outputs = []
                for i in range(self.getNumberOutputs()):
                    outputs.append(self.tx.vout[i])
                hashOutputs = self.getDHash(b"".join([o.serialize() for o in outputs]))
    

            elif self.getSigHash(index) in {"02", "03", "82", "83"}:

                if self.getSigHash(index) in {"02", "82"}:
                    hashOutputs = b'\x00' * 32
                elif self.getSigHash(index) in {"03", "83"}:
                    if index <= len(self.tx.vout):
                        outputs = self.tx.vout[index]
                        hashOutputs = self.getDHash(outputs.serialize())
                    elif index >= len(self.tx.vout):
                        hashOutputs = b'\x00' * 32

            preimage = b"".join([nVersion, hashPrevouts, hashSequences, txin_bytes, hashOutputs, nLockTime])

            sighash_bytes = bytes.fromhex(self.getSigHash(index))
            sighash_bytes = sighash_bytes[:4].ljust(4, b'\x00')

            return preimage + sighash_bytes
            

    def getTxidPreimage(self, index):
        """
        Computes the double SHA-256 hash of the preimage.

        Args:
            index (int): Index of the input in the transaction.

        Returns:
            bytes: Double SHA-256 hash.
        """
        data = self.getPreimage(index)
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def getTxidPreimageInt(self, index):
        """
        Returns the integer representation of the preimage hash.

        Args:
            index (int): Index of the input in the transaction.

        Returns:
            int: Integer representation of the hash / SigHash Single Peculiarity (nIn > nOut).
        """
        # Verificar si es un caso especial (SINGLE o SINGLE | ANYONECANPAY) donde hay más entradas que salidas.

        if self.getSigHash(index) in {"83", "03"} and index >= len(self.tx.vout): #Caso Especial
            return int.from_bytes(b'\x01' + b'\x00' * 31, byteorder='big')

        else:
            # Caso general: Calcular el doble SHA256 del Preimage
            return int(self.getTxidPreimage(index).hex(), 16)

    def verify_signature(self, index):
        """
        Verifies the ECDSA signature for a given input.

        Args:
            index (int): Index of the input to verify.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        r = self.getRInt(index)
        s = self.getSInt(index)
        hash = self.getTxidPreimageInt(index)
        pkverify = self.getPkVerify(index)

        generator_point = ellipticcurve.Point(SECP256k1.curve, SECP256k1.generator.x(), SECP256k1.generator.y(), SECP256k1.order)
        c = pow(s, -1, SECP256k1.order)
        u1 = (hash * c) % SECP256k1.order
        u2 = (r * c) % SECP256k1.order
        u1G = u1 * generator_point
        u2PK = u2 * pkverify.pubkey.point
        v = (u1G + u2PK).x() % SECP256k1.order

        return True if v == r else False

    def verify_transaction(self):
        """Verifies signatures for all inputs in the transaction and prints verification results."""
        for i in range(self.getNumberInputs()):
            try:
                if self.verify_signature(i):
                    print(f"Input {i}: Signature is valid")
                else:
                    print(f"Input {i}: Signature is not valid")
            except Exception as e:
                print(f"Input {i}: Error verifying signature - {e}")

tx = Transaction("")

tx.verify_transaction()








