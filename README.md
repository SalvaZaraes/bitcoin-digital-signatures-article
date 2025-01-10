# "Digital Signatures in Bitcoin" Article Python Codes

Bitcoin is a decentralized digital currency that enables online payments between parties without going through a central authority like a bank or government. Created by Satoshi Nakamoto in 2008.

This repository includes Python scripts demonstrating how digital signatures work in Bitcoin, following the explanations of this article: https://estudiobitcoin.com/firmas-digitales-en-bitcoin/
Bitcoin is the money of the future.

Bitcoin is today's hope.

***

Besides the Python codes, I have also written several articles related to Bitcoin:

1. Elliptic Curve in Bitcoin

  > #### English Version: https://estudiobitcoin.com/elliptic-curve-in-bitcoin/
  > #### Spanish Version: https://estudiobitcoin.com/curva-eliptica-en-bitcoin/

2. Digital Signatures in Bitcoin

  > #### English Version: 
  > #### Spanish Version: https://estudiobitcoin.com/firmas-digitales-en-bitcoin/

3. Malleability in Bitcoin

  > #### English Version: 
  > #### Spanish Version: 

***

## Verify Tx with Any Number of Inputs, Any Number of Outputs and Any Type of SigHash Flag (Only Compatible with P2PK and P2PKH scripts.)
[VerifyTx-nIn-nOut-anySigHash.py](https://github.com/SalvaZaraes/bitcoin-digital-signatures-article/blob/main/VerifyTx-nIn-nOut-anySigHash.py)

In addition to prior versions of this code, now it can handle any type of SigHash flag, allowing the user to verify and dive into more transactions.
One of the main functions in the code is getPreimage() which returns the Hash-Preimage of the designated input. This function was the main improvement in the code when compared to previous versions.

## Tx & HashPreimage Breakdown / Desglose
[Tx & HashPreimage Breakdown.md](https://github.com/SalvaZaraes/bitcoin-digital-signatures-article/blob/main/Tx%20%26%20HashPreimage%20Breakdown.md)

[Tx & HashPreimage Desglose.md](https://github.com/SalvaZaraes/bitcoin-digital-signatures-article/blob/main/Tx%20%26%20HashPreimage%20Desglose.md)

Both Markdown format text documents divide a transaction and its hash-preimage in every part of it, with the corresponding explanations; avaliable in English and Spanish.

## ECDSA Steps Hex
[ecdsa-steps-hex.py](https://github.com/SalvaZaraes/bitcoin-digital-signatures-article/blob/main/ecdsa-steps-hex.py)

This Python script demonstrates how digital signatures work. After the keys are created, the user inputs a message to be signed. The script outputs the r and s values of the signature. Later, the user will need to input the message once again, the public key and values r and s to verify that the signature is correct.
Inside the code, ECDSA mathematics are used to sign and verify.

## k Value Reuse
[k-value-reuse.py](https://github.com/SalvaZaraes/bitcoin-digital-signatures-article/blob/main/k-value-reuse.py)

This Python script demonstrates how the k value reuse attack/vulnerability is performed. After the keys are created, the user inputs two messages: both are going to be signed with the same k value. The script outputs the signatures of each message and the attack is performed directly by the script: first it extracts the k value, later the private key that was initially employed to sign.

## Verify P2PKH Tx
[verify-p2pkh-tx.py](https://github.com/SalvaZaraes/bitcoin-digital-signatures-article/blob/main/verify-p2pkh-tx.py)

This Python script demonstrates the steps a Bitcoin node follows to verify a transaction with one P2PKH input and one P2PKH output. It extracts the signature values (r, s), validates that the hashed public key matches the PubKeyHash from which funds are being spent, and finally verifies the signature by reconstructing the original proto-transaction. The script then double-hashes this proto-transaction and checks, with the signature, if the calculated v value from the ECDSA process matches the r value, ensuring that the signature is valid and that the transaction was signed by the correct private key.

## Verify Tx with Multiple Inputs and Outputs
[verify-tx-n-inputs-n-outputs.py](https://github.com/SalvaZaraes/bitcoin-digital-signatures-article/blob/main/verify-tx-n-inputs-n-outputs.py)

This Python script provides a comprehensive approach to verifying Bitcoin transactions with multiple inputs (P2PKH and/or P2PK) and outputs by reconstructing preimages tailored to each input. It offers functions to extract key transaction components, such as getlocktime() for locktime, getValues() for parsing signature data (r, s, SigHash and Public Key), and getPreimage() to generate the unique preimage for each input. With verify_transaction(), it validates that each input's signature was signed by the corresponding private key.

## Images (under MIT License)
[Cover Image](https://github.com/SalvaZaraes/bitcoin-digital-signatures-article/blob/main/cover_image.png)
[Visual 1](https://github.com/SalvaZaraes/bitcoin-digital-signatures-article/blob/main/visual1.png)
[Visual 2](https://github.com/SalvaZaraes/bitcoin-digital-signatures-article/blob/main/visual2.png)

