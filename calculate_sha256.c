//compile with -lcrypto
#include <openssl/sha.h>
#include <stdio.h>


int calculate_sha256(unsigned char* temp){

	SHA256_CTX sha256;
	SHA256_Init(&sha256);


    printf ("%s", temp); //optional
    SHA256_Update(&sha256, temp, 4);
    SHA256_Final(temp, &sha256);

    printf("%p\n", temp); //optional
 //   printf("%u\n", (unsigned int)(*temp)); //optional
  //  printf("%c\n", temp); //optional

return 0;

}

//C++ example #1:
/*
string sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int main()
{

    cout << sha256("test") << endl;
    cout << sha256("test2") << endl;

    return 0;

}
*/

int main(){

    unsigned char temp[32] = "hi!\n";
    calculate_sha256(temp);

    return 0;
}