// 
//  Systems and Services Security
//         RSA Algorithm
// 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>

#define rand_max 5000

void keyGeneration(void);
void encryptData(char *inputfile, char *keyfile, char *output);

int main(int argc, char const *argv[])
{   

    if(argc >= 2 && strcmp("-g", argv[1]) == 0){
        keyGeneration();
    }
    else{
        encryptData("plaintext.txt", "public.key", "ciphertext.txt");
    }




    printf("Done!\n");

    return 0;
}

void encryptData(char *inputfile, char *keyfile, char *output){

    //Import public key     
    mpz_t public_n;
    mpz_t public_e;

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
    mpz_import(public_n, 1, 1, sizeof(size_t), 0, 0, &keyBuffer[0]);
    mpz_import(public_e, 1, 1, sizeof(size_t), 0, 0, &keyBuffer[1]);

    //We have successfully gained the public key from file!

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
    fseek(input, 0, SEEK_SET);

    //Read each character from the file and store it the buffer
    char bufferRead[len];
    for(int j = 0; j < len; j++){
        fread(&bufferRead[j], 1, 1, input);
        // printf("%c\n", bufferRead[j]);
    }

    fclose(input);

    printf("Lenght of file is %lu\n", len);

    FILE *encrypted_file = fopen(output, "w+");
    if(encrypted_file == NULL){
        printf("File directory does not exist!\n");
        exit(1); 
    }

    //Buffer that will contain the encrypted text
    size_t ciphertext[len*sizeof(size_t)]; 
    
    int i = 0;
    while(i < len){
        
        mpz_t temp_char; 
        mpz_init(temp_char);
        
        //Import the 1 byte character into mpz_t variable
        mpz_import(temp_char, 1, 1, sizeof(char), 0, 0, &bufferRead[i]);

        mpz_t encrypted_var;
        mpz_init(encrypted_var);
        
        //Perform the encryption
        mpz_powm(encrypted_var, temp_char, public_e, public_n);

        //Store the encrypted byte in ciphertext buffer
        mpz_export(&ciphertext[i], NULL, 1, sizeof(size_t), 0, 0, encrypted_var);

        //Write the encrypted text in file
        fwrite(&ciphertext[i] + i, sizeof(size_t), 1, encrypted_file);

        i++;

        mpz_clears(temp_char, encrypted_var, NULL);

    }

    fclose(encrypted_file);
    mpz_clears(public_e, public_n, NULL);
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
    unsigned long int r = rand() % rand_max;

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

    gmp_printf("Public n is %Zd\n", n);
    gmp_printf("Public e is %Zd\n", e);

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
