gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0

#            Systems and Security PLH519
#           
#       Topics: DH Key Exchange, RSA algorithm
#
#       Author: Nikolaos Papoutsakis 2019030206



In this assignment we implimented two important algorithms

First, diffie hellman key exchange is a very popular algorithm that helps us securely exchange
cryptographic keys over a public network.

dh_assign_1.h
	This file contains all the important functions that helped us build the dh_key_exchange
	algorithm
	It consists of 7 functions:			
		      name					use
		1. saveToFile   	      --> stores in the output file the given form <public key A>, <public key B>, <shared secret>
		2. calculateKey		      --> calculates the key for alice and bob (base^exp mod n) (public and private)
		3. printArgs		      --> prints args (helped me assign an arg to a variable)
		4. checkIfPrimeHelper	      --> tests if an number is prime
		5. primalityTest	      --> uses the above function and also a printf command
		6. keyLessThan		      --> checks if the private keys created are less than the prime number p
		7. checkSecretKey	      --> check if both alice and bob have the same key

dh_assign_1.c 
	This file contains the basic implementation of the above functions.
	Comments are included so that it's easy to understand.


Second, rsa algorithm is a cryptosystem that helps 2 clients communicate safely.
The algorithm generates 2 keys, private and public. The main idea is to encrypt
the message with the public key and then the recipient has to decrypt it using
his own private key. (Works like the post-office)

rsa_assign_1.h
	This file contains all the important functions that helped us build the rsa algorithm.
	It consists of 3 functins:
		      name					use
		1. keyGeneration	      --> creates a private and a public key randomly
		2. encryptData		      --> encrypts the plaintext given and stores the output in the file given
		3. decryptData  	      --> decrypts the ciphertext and stores the decrypted message in the file given
		
		
rsa_assign_1.c
	This file contains the basic implementation of the above functions.
	Comments are included so that it's easy to understand.	
	
	keyGeneration(): at first, 2 random primes are selected using mpz_urandomm and mpz_nextprime and then by theory we calculate the appropriate e variable
			 the public key is represented by the pair (n, e), where n=p*q; and e is the appropriate prime number that satisfies the condition in line 371
			 the private key is represented by the pair (n, d), where n=p*q; and d is the modular inverse of (e, lambda).
			 then we store them (size_t bytes so that we succesfully gain them upon read) in the files public.key and private.key respectively.
	
	
	encryptData(char const *inputfile, char const *keyfile, char const *output):
			 reads from file the pair of keys
			 reads the plaintext given in inputfile arg and using a for-loop, 1 byte(char) at a time is encrypted to an 8-byte variable using mpz_powm and the given key
			 mpz_pown performs the encryprion
			 mpz_export help us convert the mpz_t var to a size_t var
			 then, using fwrite we write in file the encrypted text
	
	decryptData(char const *inputfile, char const *keyfile, char const *output):
			the opposite of encryption.
			reads from file the pair of keys
			reads the encrypted inputfile arg and using a for-loop, 8 byte(size_t) at a time is decrypted to an 1-byte variable(char) using mpz_powm and the given key
			If the public key was applied to the encryption, then the private key decrypts the file and vice versa
			mpz_pown performs the decryption
			mpz_export help us convert the mpz_t var to a 1 byte var
			then, using fwrite we write in file the decrypted text
			
			
Makefile:
	it consists all important files so that we can compile and run the executables
	use the command 'make' to compile the files
	use the command 'make clean' to delete link files and .txt generated
	
	

Commands to test:
	DH:
		./dh_assign_1 -o output.txt -p 23 -g 5 -a 6 -b 15
		./dh_assign_1 -o output.txt -p 23 -g 9 -a 15 -b 2
	
	RSA:	
		./rsa_assign_1 -g
		./rsa_assign_1 -i plaintext.txt -o ciphertext.txt -k public.key -e
		./rsa_assign_1 -i ciphertext.txt -o decrypted.txt -k private.key -d
			