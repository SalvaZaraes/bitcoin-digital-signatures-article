**_Transacción P2PKH elegida:_**
[https://mempool.space/tx/b6f5cb50a8ec7017202efd3744a94c43a4898545ac82725b6cfbd7d89ba344a2](https://mempool.space/tx/b6f5cb50a8ec7017202efd3744a94c43a4898545ac82725b6cfbd7d89ba344a2)

### **_TRANSACCIÓN:_**

Transacción HEX:

01000000012a0113029e78de5a243b205e2ed2cf4f214015ba95221047774832f7059c04ba000000006b483045022100d79836dbd86162e3c3a38bbf31f6547c3600e4f52330a8d55aa591e8896d61900220332331d6d5c2c63db6174465aba6b848a4230ce943cffcf77ffdc02a30a8fbd70121020ce5eb2757373d469b59c971a498df4cf2484d52ef875024f1d924d22a0cc17cffffffff01a4180500000000001976a9142279f73d5766231f005e826577854decdce8d34688ac00000000

**_DESGLOSE TRANSACCIÓN:_**

- 01000000 - Versión

- 01 – Número de Inputs

- 2a0113029e78de5a243b205e2ed2cf4f214015ba95221047774832f7059c04ba – Tx-ID de la tx anterior (en formato Little endian)

- 00000000 – Input que va a ser gastado, en este caso el Input con en la posición 0.

- ScriptSig - Unlocking Script
	- 6b – Longitud del ScriptSig (214 caracteres)
	- 48 – Longitud de la firma dentro del ScriptSig (144 caracteres) - OP_PUSH72
	- 30 – Indica que la codificación de la firma es DER (ASN.1)
	- 45 – Longitud de los valores de la Firma (138 caracteres)
	- 02 – Indica que r es un valor entero
	- 21 – Longitud de r (66 caracteres)
	- 00d79836dbd86162e3c3a38bbf31f6547c3600e4f52330a8d55aa591e8896d6190 – r  
	- 02 – Indica que s es un valor entero
	- 20 – Longitud de s (64 caracteres)
	- 332331d6d5c2c63db6174465aba6b848a4230ce943cffcf77ffdc02a30a8fbd7 – s
	- 01 – HashType, en este caso SIGHASH ALL
	- 21 – Longitud de la Clave Pública (66 caracteres) - OP_PUSH33
	- 020ce5eb2757373d469b59c971a498df4cf2484d52ef875024f1d924d22a0cc17c – Clave Pública comprimida

- ffffffff – Secuencia

- 01 – Número de Outputs

- a418050000000000 – Cantidad de Satoshis enviados al siguiente output (en formato Little endian)

- ScriptPubKey – Locking Script donde se van bloquear los fondos en la dirección de llegada.
	- 19 – Longitud del ScriptPubKey (50 caracteres)
	- 76 – OP_DUP
	- a9 – OP_HASH160
	- 14 – OP_PUSH20 (Empuja los siguientes 40 caracteres)
	- 2279f73d5766231f005e826577854decdce8d346 (Public Key Hash, dirección donde llegan los fondos que estamos gastando: 149J5rV5seYAuJnN2NuPt88aaT3LTK6miQ )
	- 88 – OP_EQUALVERIFY
	- ac – OP_CHECKSIG

- 00000000 – Locktime

### **_PROTO-TRANSACCIÓN_**

Proto-Transacción HEX:

01000000012a0113029e78de5a243b205e2ed2cf4f214015ba95221047774832f7059c04ba000000001976a914610f04edfac91d244149203e48a5a089991a2ac188acffffffff01a4180500000000001976a9142279f73d5766231f005e826577854decdce8d34688ac0000000001000000

**_DESGLOSE PROTO-TRANSACCIÓN:_**

- 01000000 - Versión

- 01 – Número de Inputs

- 2a0113029e78de5a243b205e2ed2cf4f214015ba95221047774832f7059c04ba – Tx-ID de la tx anterior (en formato Little endian)

- 00000000 – Input que va a ser gastado, en este caso el Input con en la posición 0.

- ScriptPubKey - Locking Script a desbloquear para poder realizar la transacción
	- 19 – Longitud del ScriptPubKey (50 caracteres)
	- 76 – OP_DUP
	- a9 – OP_HASH160
	- 14 – OP_PUSH20 (Empuja los siguientes 40 caracteres)
	- 610f04edfac91d244149203e48a5a089991a2ac1 (Public Key Hash, dirección donde estaban los fondos que estamos gastando: 19rCYAVvroJXe5VuvzjBUgx4TSmBqjtAp9 )
	- 88 – OP_EQUALVERIFY
	- ac – OP_CHECKSIG

- ffffffff – Secuencia

- 01 – Número de Outputs

- a418050000000000 – Cantidad de Satoshis enviados al siguiente output (en formato Little endian)

- ScriptPubKey – Locking Script donde se van bloquear los fondos en la dirección de llegada.
	- 19 – Longitud del ScriptPubKey (50 caracteres)
	- 76 – OP_DUP
	- a9 – OP_HASH160
	- 14 – OP_PUSH20 (Empuja los siguientes 40 caracteres)
	- 2279f73d5766231f005e826577854decdce8d346 (Public Key Hash, dirección donde llegan los fondos que estamos gastando: 149J5rV5seYAuJnN2NuPt88aaT3LTK6miQ )
	- 88 – OP_EQUALVERIFY
	- ac – OP_CHECKSIG

- 00000000 – Locktime

- 01000000 - HashType, en este caso SIGHASH ALL
