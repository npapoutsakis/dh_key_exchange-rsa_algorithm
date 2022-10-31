
#ifndef dh_assign_1
#define dh_assign_1

void saveToFile(char const *filename, int a, int b, int secret);

long long unsigned int calculateKey(long double base, long double key, long double prime);

void printArgs(int args, char const **argv);

int checkIfPrimeHelper(int number);

void primalityTest(int number);

void keyLessThan(int private_key, int p);

void checkSecretKey(long long int alice_key, long long int bob_key);

#endif