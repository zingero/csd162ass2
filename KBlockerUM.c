#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
void calculate_sha256(char *string, char outputBuffer[65])
{
    unsigned char hash[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < 32; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
      //  printf("%x\n", hash[i]);
    }

    outputBuffer[64] = 0;
}

/*



*///TODO: add the final functions for exe & ptn scripts


int main()
{

static unsigned char buffer[65];
calculate_sha256("this is an expirement to check the sha!", buffer);
printf("%s\n", buffer);

    return 0;

}