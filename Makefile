
rsa_assign_1: rsa_assign_1.o
	gcc rsa_assign_1.c -o rsa_assign_1 -lm -lgmp

rsa_assign_1.o: rsa_assign_1.c
	gcc -c rsa_assign_1.c -lm

clean:
	rm -f *.o ; rm -f *.txt ; rm -f rsa_assign_1 ; rm -f *.key