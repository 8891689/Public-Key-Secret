default:
	gcc key_homomorphism.c libsecp256k1.a -Wall -Wextra -O3 -o kh
	gcc calculator.c -lgmp -O3 -o c
	gcc pubkey_calculator.c -march=native libsecp256k1.a -lgmp -O3 -o pc
	gcc pubkey_cloning.c random.c bitrange.c -march=native libsecp256k1.a -lgmp -Wall -Wextra -O3 -o p
	gcc pubkey_homomorphism.c libsecp256k1.a -lgmp -Wall -Wextra -O3 -o ph
	gcc pkconvert.c -O3 -march=native libsecp256k1.a -o pkconvert
	#gcc pubkey_reduce.c bitrange.c -march=native libsecp256k1.a -lgmp -Wall -Wextra -O3 -o pr
	

clean:
	rm -f kh
	rm -f c
	rm -f p
	rm -f pc
	rm -f ph
	rm -f pkconvert
	#rm -f pr
