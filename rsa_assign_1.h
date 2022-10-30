
#ifndef rsa_assign_1
#define rsa_assign_1

void keyGeneration(void);

void encryptData(char const *inputfile, char const *keyfile, char const *output);

void decryptData(char const *inputfile, char const *keyfile, char const *output);

#endif