//compile with -lcrypto
#include <openssl/sha.h>
#include <stdio.h>


int main(){

    unsigned char temp[32] = "hi!\n";
    calculate_sha256(temp);

    return 0;
}


int calculate_sha256(unsigned char* temp){

	SHA256_CTX sha256;
	SHA256_Init(&sha256);


    printf ("%s", temp); //optional
    SHA256_Update(&sha256, temp, 4);
    SHA256_Final(temp, &sha256);

    printf("%p\n", temp); //optional

return 0;

}