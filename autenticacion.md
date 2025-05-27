Dada la implementación planteada:
- CriptoAsym: 	ECDH
- CriptoSym:  	ChaCha20
- Lenguaje:		C++

Se requiere garantizar la autenticación. Propuestas:
1) Luego de implementar ECDH ambos dispositivos tendrán una llave
	simétrica mediante KDF (_Key Derivation Function_)
	- `llave = HKDF(ECDH_llave_compartida`
	- Con Chacha20 se obtiene Confidencialidad (cifrado) e Integridad;
		de manera que si el mensaje es alterado o el emisor no tiene
		la clave, el mensaje fallará la verificación
	- El SWCH debe almacenar la clave pública del servidor
	- El servidor, debe registrar la llave pública del SWCH (_vg: ID\_dispo_)

2) Autenticación mutua explícita
	- El servidor envía un _nonce_ al SWCH
	- el SWCH responde firmando el _nonce_ con su llave privada
	- El servidor verifica la firma usando llave pública (precargada) del SWCH
	- Puede implementarse en ambos sentidos para que funciones como una
		autenticación mutua
