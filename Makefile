all: dh_assign_1.o rsa_assign_1.o dh_assign_1 rsa_assign_1

rsa_assign_1: rsa_assign_1.o
	gcc rsa_assign_1.c -o rsa_assign_1 -lm -lgmp

dh_assign_1: dh_assign_1.o
	gcc dh_assign_1.c -o dh_assign_1 -lm -lgmp

rsa_assign_1.o: rsa_assign_1.c
	gcc -c rsa_assign_1.c -lm -lgmp

dh_assign_1.o: dh_assign_1.c
	gcc -c dh_assign_1.c -lgmp -lm

clean:
	rm -f dh_assign_1 *.o rsa_assign_1 *.key decrypted.txt ciphertext.txt output.txt