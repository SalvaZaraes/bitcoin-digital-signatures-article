**_Chosen P2PKH Transaction:_**
[https://mempool.space/tx/b6f5cb50a8ec7017202efd3744a94c43a4898545ac82725b6cfbd7d89ba344a2](https://mempool.space/tx/b6f5cb50a8ec7017202efd3744a94c43a4898545ac82725b6cfbd7d89ba344a2)

### **_TRANSACTION:_**

Transaction HEX:

01000000012a0113029e78de5a243b205e2ed2cf4f214015ba95221047774832f7059c04ba000000006b483045022100d79836dbd86162e3c3a38bbf31f6547c3600e4f52330a8d55aa591e8896d61900220332331d6d5c2c63db6174465aba6b848a4230ce943cffcf77ffdc02a30a8fbd70121020ce5eb2757373d469b59c971a498df4cf2484d52ef875024f1d924d22a0cc17cffffffff01a4180500000000001976a9142279f73d5766231f005e826577854decdce8d34688ac00000000

**_TRANSACTION BREAKDOWN:_**

- 01000000 - Version

- 01 – Number of Inputs

- 2a0113029e78de5a243b205e2ed2cf4f214015ba95221047774832f7059c04ba – Tx-ID of the previous tx (in Little endian format)

- 00000000 – Input to be spent, in this case the Input at position 0.

- ScriptSig - Unlocking Script
    - 6b – Length of the ScriptSig (214 characters)
    - 48 – Length of the signature within the ScriptSig (144 characters)
    - 30 – Indicates that the signature encoding is DER (ASN.1)
    - 45 – Length of the Signature values (138 characters)
    - 02 – Indicates that r is an integer value
    - 21 – Length of r (66 characters)
    - 00d79836dbd86162e3c3a38bbf31f6547c3600e4f52330a8d55aa591e8896d6190 – r
    - 02 – Indicates that s is an integer value
    - 20 – Length of s (64 characters)
    - 332331d6d5c2c63db6174465aba6b848a4230ce943cffcf77ffdc02a30a8fbd7 – s
    - 01 – HashType, in this case SIGHASH ALL
    - 21 – Length of the Public Key (66 characters)
    - 020ce5eb2757373d469b59c971a498df4cf2484d52ef875024f1d924d22a0cc17c – Compressed Public Key

- ffffffff – Sequence

- 01 – Number of Outputs

- a418050000000000 – Amount of Satoshis sent to the next output (in Little endian format)

- ScriptPubKey – Locking Script where the funds are locked at the receiving address.
    - 19 – Length of the ScriptPubKey (50 characters)
    - 76 – OP_DUP
    - a9 – OP_HASH160
    - 14 – OP_PUSH20 (Pushes the next 40 characters)
    - 2279f73d5766231f005e826577854decdce8d346 (Public Key Hash, address where the funds we are spending are arriving: 149J5rV5seYAuJnN2NuPt88aaT3LTK6miQ)
    - 88 – OP_EQUALVERIFY
    - ac – OP_CHECKSIG

- 00000000 – Locktime

### **_PROTO-TRANSACTION_**

Proto-Transaction HEX:

01000000012a0113029e78de5a243b205e2ed2cf4f214015ba95221047774832f7059c04ba000000001976a914610f04edfac91d244149203e48a5a089991a2ac188acffffffff01a4180500000000001976a9142279f73d5766231f005e826577854decdce8d34688ac0000000001000000

**_PROTO-TRANSACTION BREAKDOWN:_**

- 01000000 - Version

- 01 – Number of Inputs

- 2a0113029e78de5a243b205e2ed2cf4f214015ba95221047774832f7059c04ba – Tx-ID of the previous tx (in Little endian format)

- 00000000 – Input to be spent, in this case the Input at position 0.

- ScriptPubKey - Locking Script to be unlocked to make the transaction
    - 19 – Length of the ScriptPubKey (50 characters)
    - 76 – OP_DUP
    - a9 – OP_HASH160
    - 14 – OP_PUSH20 (Pushes the next 40 characters)
    - 610f04edfac91d244149203e48a5a089991a2ac1 (Public Key Hash, address where the funds we are spending were: 19rCYAVvroJXe5VuvzjBUgx4TSmBqjtAp9)
    - 88 – OP_EQUALVERIFY
    - ac – OP_CHECKSIG

- ffffffff – Sequence

- 01 – Number of Outputs

- a418050000000000 – Amount of Satoshis sent to the next output (in Little endian format)

- ScriptPubKey – Locking Script where the funds are locked at the receiving address.
    - 19 – Length of the ScriptPubKey (50 characters)
    - 76 – OP_DUP
    - a9 – OP_HASH160
    - 14 – OP_PUSH20 (Pushes the next 40 characters)
    - 2279f73d5766231f005e826577854decdce8d346 (Public Key Hash, address where the funds we are spending are arriving: 149J5rV5seYAuJnN2NuPt88aaT3LTK6miQ)
    - 88 – OP_EQUALVERIFY
    - ac – OP_CHECKSIG

- 00000000 – Locktime

- 01000000 - HashType, in this case SIGHASH ALL