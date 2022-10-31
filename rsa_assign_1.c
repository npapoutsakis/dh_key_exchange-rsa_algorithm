// 
//  Systems and Services Security PLH519
//         RSA Algorithm
// 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include <getopt.h>
#include "rsa_assign_1.h"

#define rand_max 10000

int main(int argc, char *argv[])
{   
    char const *inputFile;
    char const *keyFile;
    char const *outputFile; 
    
    int option_val = 0;
    while((option_val = getopt(argc, argv, "i:o:k:gdeh")) != -1){
        
        switch(option_val) {
            case 'i':
                inputFile = optarg;
                break;
            
            case 'o':
                outputFile = optarg;
                break;
            
            case 'k':
                keyFile = optarg;
                break;
            
            case 'g':
                if(argc > 2){
                    printf("Invalid Arguments. Try again!\n");
                    exit(1);
                }
                keyGeneration();
                return 0;

            case 'd':
                //total args when enc or dec
                if(argc != 8){
                    printf("Invalid Arguments. Try again!\n");
                    exit(1);
                }
                decryptData(inputFile, keyFile, outputFile);
                break;
            
            case 'e':
                //total args when enc or dec
                if(argc != 8){
                    printf("Invalid Arguments. Try again!\n");
                    exit(1);
                }
                encryptData(inputFile, keyFile, outputFile);
                break;
        
        }

    }

    return 0;
}

void decryptData(char const *inputfile, char const *keyfile, char const *output){

    //Import public key     
    mpz_t key_n;
    mpz_t key_exponent;

    mpz_init(key_n);
    mpz_init(key_exponent);

    //Size of 8 bytes each
    size_t keyBuffer[2]; 

    //Open file for reading 
    FILE *keyDir = fopen(keyfile, "r");

    if(keyDir == NULL){
        printf("File directory does not exist!\n");
        exit(1); 
    }

    fread(&keyBuffer[0], sizeof(size_t), 1, keyDir);
    fread(&keyBuffer[1], sizeof(size_t), 1, keyDir);

    fclose(keyDir);

    //File read finished, import to mpz_t variables
    mpz_import(key_n, 1, 1, sizeof(size_t), 0, 0, &keyBuffer[0]);
    mpz_import(key_exponent, 1, 1, sizeof(size_t), 0, 0, &keyBuffer[1]);

    //We have successfully gained the key from file!
    
    //Decryption begins
    //ciphertext.txt
    FILE *input = fopen(inputfile, "r");

    //we need to know the lenght of the plaintext -> specifically the number of bytes
    if(input == NULL){
        printf("File directory does not exist!\n");
        exit(1); 
    }

    //Seek the end of the file
    fseek(input, 0, SEEK_END);
    size_t len = ftell(input);
    fseek(input, 0, SEEK_SET);

    //Read each character from the file and store it the buffer
    size_t bufferRead[len/sizeof(size_t)];
    for(int j = 0; j < len/sizeof(size_t); j++){
        fread(&bufferRead[j], sizeof(size_t), 1, input);
        //printf("%lu\n", bufferRead[j]);
    }

    fclose(input);

    // printf("Lenght of file is %lu\n", len);

    FILE *decrypted_file = fopen(output, "w+");
    if(decrypted_file == NULL){
        printf("File directory does not exist!\n");
        exit(1); 
    }

    //Buffer that will contain the decrypted text
    char plaintext[len/sizeof(size_t)]; 
    
    int i = 0;
    while(i < len/sizeof(size_t)){
        
        mpz_t temp_char; 
        mpz_init(temp_char);
        
        //Import the 1 byte character into mpz_t variable
        mpz_import(temp_char, 1, 1, sizeof(size_t), 0, 0, &bufferRead[i]);

        mpz_t encrypted_var;
        mpz_init(encrypted_var);
        
        //Perform the encryption
        mpz_powm(encrypted_var, temp_char, key_exponent, key_n);

        // gmp_printf("%Zd\n", encrypted_var);

        //Store the decrypted byte in plaintext buffer
        mpz_export(&plaintext[i], NULL, 1, sizeof(char), 0, 0, encrypted_var);

        // printf("%ld\n", ciphertext[i]);

        //Write the encrypted text in file
        fwrite(&plaintext[i], sizeof(char), 1, decrypted_file);

        i++;

        mpz_clears(temp_char, encrypted_var, NULL);
    }

    mpz_clears(key_exponent, key_n, NULL);
    fclose(decrypted_file);
    return;
}

void encryptData(char const *inputfile, char const *keyfile, char const *output){

    //Import public key     
    mpz_t key_n;
    mpz_t key_exponent;

    mpz_init(key_n);
    mpz_init(key_exponent);

    //Size of 8 bytes each
    size_t keyBuffer[2]; 

    //Open file for reading 
    FILE *keyDir = fopen(keyfile, "r");

    if(keyDir == NULL){
        printf("File directory does not exist!\n");
        exit(1); 
    }

    fread(&keyBuffer[0], sizeof(size_t), 1, keyDir);
    fread(&keyBuffer[1], sizeof(size_t), 1, keyDir);

    fclose(keyDir);

    //File read finished, import to mpz_t variables
    mpz_import(key_n, 1, 1, sizeof(size_t), 0, 0, &keyBuffer[0]);
    mpz_import(key_exponent, 1, 1, sizeof(size_t), 0, 0, &keyBuffer[1]);

    //We have successfully gained the key from file!

    //Encryption begins
    //plaintext.txt
    FILE *input = fopen(inputfile, "r");

    //we need to know the lenght of the plaintext -> specifically the number of bytes
    if(input == NULL){
        printf("File directory does not exist!\n");
        exit(1); 
    }

    //Seek the end of the file
    fseek(input, 0, SEEK_END);
    size_t len = ftell(input);

    //Return to the start
    fseek(input, 0, SEEK_SET);

    //Read each character from the file and store it the buffer
    char bufferRead[len];
    for(int j = 0; j < len; j++){
        fread(&bufferRead[j], 1, 1, input);
        // printf("%c\n", bufferRead[j]);
    }

    fclose(input);

    // printf("Lenght of file is %lu\n", len);

    FILE *encrypted_file = fopen(output, "w+");
    if(encrypted_file == NULL){
        printf("File directory does not exist!\n");
        exit(1); 
    }

    //Buffer that will contain the encrypted text
    size_t ciphertext[len]; 

    // printf("Size of size_t array %ld\n", sizeof(ciphertext[0]));
    
    int i = 0;
    while(i < len){
        
        mpz_t temp_char; 
        mpz_init(temp_char);
        
        //Import the 1 byte character into mpz_t variable
        mpz_import(temp_char, 1, 1, sizeof(char), 0, 0, &bufferRead[i]);

        mpz_t encrypted_var;
        mpz_init(encrypted_var);
        
        //Perform the encryption
        mpz_powm(encrypted_var, temp_char, key_exponent, key_n);

        //Store the encrypted byte in ciphertext buffer
        mpz_export(&ciphertext[i], NULL, 1, sizeof(size_t), 0, 0, encrypted_var);

        //Write the encrypted text in file
        fwrite(&ciphertext[i], sizeof(size_t), 1, encrypted_file);

        //Increment
        i++;

        mpz_clears(temp_char, encrypted_var, NULL);
    }

    mpz_clears(key_exponent, key_n, NULL);
    fclose(encrypted_file);
    return;
}

void keyGeneration(void){
    
    //prime numbers
    mpz_t p, q;
    
    //n = p*q
    mpz_t n;

    //lamda = (p-1)*(q-1);
    mpz_t lamda;

    //prime 1 < e < lamda(n)
    mpz_t e;

    //Inverse modulo of (e, lamda(n))
    mpz_t d;

    //Files to store the keys
    FILE *file_public = fopen("public.key", "w+");
    FILE *file_private= fopen("private.key", "w+");

    //At first, choose a prime randomly
    //Random int generator 
    srand(time(NULL));
    unsigned long int r = rand();

    //r is a random number, we ll use mpz_nextprime to find a prime
    mpz_t temp;
    mpz_init_set_ui(temp, r);

    //Initialize p and set its value the next prime from temp
    mpz_init(p);
    mpz_nextprime(p, temp);

    //Now calculate the next prime q (p+1 is the offset)
    mpz_init(q);
    mpz_add_ui(temp, p, 1);  // temp = p + 1
    mpz_nextprime(q, temp);

    // gmp_printf("p = %Zd and q = %Zd\n", p, q);
    
    //Next we compute n = p * q;
    mpz_init(n);
    mpz_mul(n, p, q);
    // gmp_printf("n = p*q = %Zd\n", n);

    //Next, calculate lanmda(n)
    mpz_init(lamda);
    mpz_sub_ui(p, p, 1);   //p = p-1 
    mpz_sub_ui(q, q, 1);   //q = q-1
    // gmp_printf("p-1 = %Zd and q-1 = %Zd\n", p, q);
    
    //lamda(n) = (p-1)*(q-1)
    mpz_mul(lamda, p, q);
    // gmp_printf("lamda(n) = %Zd\n", lamda);

    //Next calculate e
    mpz_init(e);
    
    //Initialize the rand_state
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, rand());
    
    //Start a while loop until we find the appropriate e
    while(1){
        
        //Declare a temp variable 
        mpz_t rand;
        mpz_init(rand);
        mpz_urandomm(rand, state, lamda);    //from 0 to lamda - 1
        mpz_nextprime(rand, rand);           //set rand the next prime number after rand

        // gmp_printf("rand = %Zd\n", rand);

        //After choosing a random number, we find the next prime
        //We have to check if the prime is bigger than lamba
        //if so, skip the current loop
        if(mpz_cmp(rand, lamda) > 0){
            printf("The random prime e, passed lamda(n)\n");
            continue;
        }

        //Calculating conditions
        mpz_t tmp; 
        mpz_init(tmp);
        
        //temp = rand % lamda
        mpz_mod(tmp, rand, lamda);
        int result_modulo = mpz_cmp_ui(tmp, 0);
        // printf("%d\n", result_modulo);

        mpz_gcd(tmp, rand, lamda);
        int result_gcd = mpz_cmp_si(tmp, 1);    
        // printf("%d\n", result_gcd);

        // 1 < e < lamda(n)
        if((result_modulo != 0) && (result_gcd == 0)){
            mpz_init_set(e, rand);
            mpz_clears(rand, tmp, NULL);
            break;
        }

    }

    //Next, we calculate d (inverse mod of (e, lamda(n)))
    mpz_init(d);
    mpz_invert(d, e, lamda);

    //Now we have the public and private key (n, e) & (n, d) -> from wiki
    //Storing

    //We use a buf so that we can write a constant size
    size_t buf[2]; //8 bytes each

    mpz_export(&buf[0], NULL, 1, sizeof(size_t), 0, 0, n);
    mpz_export(&buf[1], NULL, 1, sizeof(size_t), 0, 0, e);

    // gmp_printf("Public n is %Zd\n", n);
    // gmp_printf("Public e is %Zd\n", e);

    fwrite(buf, sizeof(size_t), 2, file_public);

    mpz_export(buf+1, NULL, 1, sizeof(size_t), 0, 0, d);

    fwrite(buf, sizeof(size_t), 2, file_private);

    //Free space occupied
    fclose(file_private);
    fclose(file_public);
    gmp_randclear(state);
    mpz_clears(p, q, e, d, lamda, n, temp, NULL);
    return;
}