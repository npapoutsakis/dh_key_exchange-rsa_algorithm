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

typedef struct key{
    mpz_t n;
    mpz_t exponent;
} key;

int main(int argc, char const *argv[])
{   

    if(argc >= 2 && strcmp("-g", argv[1]) == 0){
        keyGeneration();
    }
    else{
        printf("Invalid selection!\n");
        exit(1);
    }








    printf("Done!\n");

    return 0;
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

    //Key pair
    key publicKey;
    key privateKey;

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
    

    





    //Free space occupied
    fclose(file_private);
    fclose(file_public);
    gmp_randclear(state);
    mpz_clears(p, q, e, d, lamda, n, temp, NULL);
    return;
}
