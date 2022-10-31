// 
//	Systems and Services Security PLH519
// 		Diffie-Hellman Key Exchange
// 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <tgmath.h>
#include "dh_assign_1.h"

int main(int argc, char const *argv[])
{
   	//p-> prime number, g-> base, next primitive root
	long long unsigned int p;
	long long unsigned int g;
	
	//Private Keys
	long int alice_private_key;
	long int bob_private_key;

	//Will be saved in output.txt
	//Public Keys
	long long unsigned int alice_public_key;
	long long unsigned int bob_public_key;

	//The shared secret
	int shared_secret_key;

	//Initialize variables and check if primes	
	p = atoi(argv[4]);
	primalityTest(p);

	g = atoi(argv[6]);
	// primalityTest(g);

	//Initialize the private keys, check the inequality pk < p
	alice_private_key = atoi(argv[8]);
	keyLessThan(alice_private_key, p);

	bob_private_key = atoi(argv[10]);
	keyLessThan(bob_private_key, p);

	//Public keys generation
	alice_public_key = calculateKey(g, alice_private_key, p);
	bob_public_key = calculateKey(g, bob_private_key, p);

	// printf("Alice Public Key is %llu\n", alice_public_key);
	// printf("Bob Public Key is %llu\n\n", bob_public_key);

	//After the swap, Alice and Bob compute the secret key
	//Alice computes:
	long long unsigned int alice_secret = calculateKey(bob_public_key, alice_private_key, p);

	//Bob computes:
	long long unsigned int bob_secret = calculateKey(alice_public_key, bob_private_key, p);

	//Checking if the key is valid
	// printf("Alice secret key is %llu\n", alice_secret);
	// printf("Bob secret key is %llu\n", bob_secret);
	checkSecretKey(alice_secret, bob_secret);
	shared_secret_key = alice_secret;

	saveToFile(argv[2], alice_public_key, bob_public_key, shared_secret_key);
	
	// printf("Done!\n");

	return 0;
}

void checkSecretKey(long long int alice_key, long long int bob_key){
	if(alice_key != bob_key){
		printf("Something went wrong, keys dont match!\n");
		exit(1);
	}
	else
		return;
}

long long unsigned int calculateKey(long double base, long double key, long double prime){
	// g^(prKey) mod p;
    return fmodl(powl(base, key), prime);
}

void keyLessThan(int private_key, int p){

	if(private_key >= p){
		printf("Private keys should be less than p! Try again!\n");
		exit(1);
	}

	return;
}

void saveToFile(char const *filename, int a, int b, int secret){

	FILE *file = NULL;
	
	file = fopen(filename, "a+");
	
	//Check if name is correct
	if(file == NULL){
      printf("Error!\n");
      exit(1);             
  	}

	fprintf(file, "<%d>, <%d>, <%d>\n", a, b, secret);

	fclose(file);
	
	return;
}

void printArgs(int args, char const **argv){
 	for (int i = 0; i < args; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
	return;
}

void primalityTest(int number){
	int result = checkIfPrimeHelper(number);
	if(result == 0){
		printf("%d is not a prime number...Try again!\n", number);
		exit(1);
	}
	else
		return;
}

int checkIfPrimeHelper(int number){
    
	if (number <= 1){
		return 0;
	}
	else if(number <= 3){
		return 0;
	}
	else if((number%2==0) || (number%3 == 0)){
		return 0;
	}

	int i = 5;

	while (i*i <= number){
		if((number%i == 0) || number%(i+2)==0){
			return 0;
		}
		i = i + 6;
	}

	return 1;
}