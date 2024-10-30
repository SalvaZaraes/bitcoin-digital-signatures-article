import binascii
import hashlib
from bitcoin.core import b2x, COutPoint, CTransaction, CTxIn
from bitcoin.core.script import CScript, OP_CHECKSIG, OP_DUP, OP_HASH160, OP_EQUALVERIFY
import ecdsa
from ecdsa import SECP256k1, ellipticcurve

class Transaction:
    def __init__(self, hex_str):

        self.tx = CTransaction.deserialize(bytes.fromhex(hex_str))
        self.values = self.get4values()

    def getlocktime(self):
        return self.tx.nLockTime

    def getNSequence(self, index):
        return self.tx.vin[index].nSequence

    def getNumberInputs(self):
        return len(self.tx.vin)

    def getNumberOutputs(self):
        return len(self.tx.vout)

    def get4values(self):

        inputs_data = []

        for i, vin in enumerate(self.tx.vin):
            script_sig_hex = b2x(vin.scriptSig)
            sig_len = int(script_sig_hex[0:2], 16) * 2
            signature = script_sig_hex[2:2 + sig_len]

            r_len = int(signature[6:8], 16) * 2
            r = signature[8:8 + r_len]

            s_len = int(signature[8 + r_len + 2:8 + r_len + 4], 16) * 2
            s = signature[8 + r_len + 4:8 + r_len + 4 + s_len]

            sighash = signature[sig_len - 2:sig_len]
            pub_len = int(script_sig_hex[2 + sig_len:2 + sig_len + 2], 16) * 2
            pub = script_sig_hex[2 + sig_len + 2:2 + sig_len + 2 + pub_len]

            inputs_data.append((r, s, sighash, pub))

        return inputs_data

    def getR(self, index):
        return self.values[index][0]

    def getRInt(self, index):
        return int(self.getR(index), 16)

    def getS(self, index):
        return self.values[index][1]

    def getSInt(self, index):
        return int(self.getS(index), 16)

    def getSigHash(self, index):
        return self.values[index][2]

    def getPk(self, index):
        return self.values[index][3]

    def getPkHash(self, index):

        sha256 = hashlib.sha256(bytes.fromhex(self.getPk(index))).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256)

        return ripemd160.hexdigest()

    def getPkUncompressed(self, pktouncompress):

        # ADAPTED FROM AVA CHOW'S CODE FOR UNCOMPRESSING PUBLIC KEYS PUBLISHED HERE: https://bitcoin.stackexchange.com/a/86239
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        x = int.from_bytes(pktouncompress[1:], byteorder='big')
        y_sq = (pow(x, 3, p) + 7) % p
        y = pow(y_sq, (p + 1) // 4, p)
        if y % 2 != pktouncompress[0] % 2:
            y = p - y
        y = y.to_bytes(32, byteorder='big')

        return pktouncompress[1:] + y


    def getPkVerify(self, index):

        pub_extracted = self.getPk(index)

        if pub_extracted[0:2] == "02" or pub_extracted[0:2] == "03":
            uncompressed = binascii.hexlify(self.getPkUncompressed(binascii.unhexlify(pub_extracted))).decode()
        else:
            uncompressed = pub_extracted[2:]

        generator_point = ellipticcurve.Point(SECP256k1.curve, SECP256k1.generator.x(), SECP256k1.generator.y(), SECP256k1.order)

        pk_x = int(uncompressed[:64], 16)
        pk_y = int(uncompressed[64:], 16)

        if not SECP256k1.curve.contains_point(pk_x, pk_y):
            print("The provided public key does not correspond to a valid point on the SECP256k1 curve.")
            return

        public_key_point = ellipticcurve.Point(SECP256k1.curve, pk_x, pk_y, SECP256k1.order)
        return ecdsa.VerifyingKey.from_public_point(public_key_point, curve=SECP256k1)

    def getPreimage(self, index):

        script_pubkey = CScript([OP_DUP, OP_HASH160, bytes.fromhex(self.getPkHash(index)), OP_EQUALVERIFY, OP_CHECKSIG]) # SI ESTO LO EXTERNALIZO TAMBIEN PODRA CON P2PK

        inputs = []
        for i in range(self.getNumberInputs()):
            if i == index:
                inputs.append(CTxIn(COutPoint(self.tx.vin[index].prevout.hash, self.tx.vin[index].prevout.n), script_pubkey))
            else:
                inputs.append(CTxIn(COutPoint(self.tx.vin[i].prevout.hash, self.tx.vin[i].prevout.n)))

        outputs = []
        for i in range(self.getNumberOutputs()):
            outputs.append(self.tx.vout[i])

        sighash_bytes = bytes.fromhex(self.getSigHash(index))
        sighash_bytes = sighash_bytes[:4].ljust(4, b'\x00')

        new_tx = CTransaction(inputs, outputs, nLockTime=self.getlocktime())

        proto_tx = new_tx.serialize() + sighash_bytes

        return proto_tx

    def getTxidPreimage(self, index):

        data = self.getPreimage(index)

        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def getTxidPreimageInt(self, index):
        return int(self.getTxidPreimage(index).hex(), 16)

    def verify_signature(self, index):

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

        for i in range(self.getNumberInputs()):
            if self.verify_signature(i):
                print(f"Input {i}: Signature is valid")
            else:
                print(f"Input {i}: Signature is not valid")


tx = Transaction("010000000586c62cd602d219bb60edb14a3e204de0705176f9022fe49a538054fb14abb49e010000008c493046022100f2bc2aba2534becbdf062eb993853a42bbbc282083d0daf9b4b585bd401aa8c9022100b1d7fd7ee0b95600db8535bbf331b19eed8d961f7a8e54159c53675d5f69df8c014104462e76fd4067b3a0aa42070082dcb0bf2f388b6495cf33d789904f07d0f55c40fbd4b82963c69b3dc31895d0c772c812b1d5fbcade15312ef1c0e8ebbb12dcd4ffffffff03ad0e58ccdac3df9dc28a218bcf6f1997b0a93306faaa4b3a28ae83447b2179010000008b483045022100be12b2937179da88599e27bb31c3525097a07cdb52422d165b3ca2f2020ffcf702200971b51f853a53d644ebae9ec8f3512e442b1bcb6c315a5b491d119d10624c83014104462e76fd4067b3a0aa42070082dcb0bf2f388b6495cf33d789904f07d0f55c40fbd4b82963c69b3dc31895d0c772c812b1d5fbcade15312ef1c0e8ebbb12dcd4ffffffff2acfcab629bbc8685792603762c921580030ba144af553d271716a95089e107b010000008b483045022100fa579a840ac258871365dd48cd7552f96c8eea69bd00d84f05b283a0dab311e102207e3c0ee9234814cfbb1b659b83671618f45abc1326b9edcc77d552a4f2a805c0014104462e76fd4067b3a0aa42070082dcb0bf2f388b6495cf33d789904f07d0f55c40fbd4b82963c69b3dc31895d0c772c812b1d5fbcade15312ef1c0e8ebbb12dcd4ffffffffdcdc6023bbc9944a658ddc588e61eacb737ddf0a3cd24f113b5a8634c517fcd2000000008b4830450221008d6df731df5d32267954bd7d2dda2302b74c6c2a6aa5c0ca64ecbabc1af03c75022010e55c571d65da7701ae2da1956c442df81bbf076cdbac25133f99d98a9ed34c014104462e76fd4067b3a0aa42070082dcb0bf2f388b6495cf33d789904f07d0f55c40fbd4b82963c69b3dc31895d0c772c812b1d5fbcade15312ef1c0e8ebbb12dcd4ffffffffe15557cd5ce258f479dfd6dc6514edf6d7ed5b21fcfa4a038fd69f06b83ac76e010000008b483045022023b3e0ab071eb11de2eb1cc3a67261b866f86bf6867d4558165f7c8c8aca2d86022100dc6e1f53a91de3efe8f63512850811f26284b62f850c70ca73ed5de8771fb451014104462e76fd4067b3a0aa42070082dcb0bf2f388b6495cf33d789904f07d0f55c40fbd4b82963c69b3dc31895d0c772c812b1d5fbcade15312ef1c0e8ebbb12dcd4ffffffff01404b4c00000000001976a9142b6ba7c9d796b75eef7942fc9288edd37c32f5c388ac00000000")

# https://mempool.space/es/tx/21d2eb195736af2a40d42107e6abd59c97eb6cffd4a5a7a7709e86590ae61987 Consolidacion

# https://mempool.space/es/tx/220ebc64e21abece964927322cba69180ed853bb187fbc6923bac7d010b9d87a Output P2PK

#print(tx.get4values())

#print(tx.getNumberInputs())

#print(tx.getPreimage(3).hex())

#print(tx.getTxidPreimage(1).hex())

#print(tx.getTxidPreimageInt(1))

#print(tx.verify_signature(2))

#print(tx.getPk(1))

tx.verify_transaction()
