/*
Source: http://stackoverflow.com/questions/3299386/how-to-use-netlink-socket-to-communicate-with-a-kernel-module/3334782#3334782
*/

#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <sys/stat.h>

#define NETLINK_USER 31

#define MAX_PAYLOAD 1024 /* maximum payload size*/
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;
char message[MAX_PAYLOAD] = {0};

char* file_content(FILE* file, int size){
    int  c, i = 0;
    char* buffer = malloc(size);
    
    while((c = fgetc(file)) != EOF){
        buffer[i] = c;
        i++;
    }
    return buffer;
}

void calculate_sha256(char *string, char outputBuffer[65], int size){
    unsigned char hash[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, size);
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < 32; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", (unsigned char)hash[i]);
    }

    outputBuffer[64] = 0;
}

void sha_file()
{
    FILE *fp;
    char *str;
    fp = fopen(message,"r");
    if(fp == NULL) 
    {
        printf("Error in opening file\n");
        return;
    }

    //calculate buffer's size
    struct stat st;
    stat(message, &st);
    int size = st.st_size;

    str = file_content(fp, size);
    fclose(fp);

    //call sha
    static unsigned char buffer[65];
    calculate_sha256(str, buffer, size);
    printf("sha in user = %s\n", buffer);
    strcpy(NLMSG_DATA(nlh), buffer);
}

void init_message(void)
{
    int i = 0;
    for(; i < MAX_PAYLOAD ; ++i)
    {
        message[i] = 0;
    }
}

int main()
{
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
    {
        printf("ERROR: Can not connect to kernel.\n");
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); // self pid 
    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // For Linux Kernel 
    dest_addr.nl_groups = 0; // unicast 

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    
    strcpy(NLMSG_DATA(nlh), "Hello from user");

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // first time calling the kernel the kernel to give pid
    sendmsg(sock_fd, &msg, 0);

    // Read message from kernel 

    while(1)
    {
        recvmsg(sock_fd, &msg, 0);
        strcpy(message, NLMSG_DATA(nlh));
        printf("USER GOT:%s\n", message);
        // sha_file();
        // printf("USER GOT:%s. SHA=%s\n", message, NLMSG_DATA(nlh));
        // init_message();
        if(strncmp(message, "./unload.sh", strlen("./unload.sh")) == 0)
            break;
        sendmsg(sock_fd, &msg, 0);
    }    
    close(sock_fd);
    
}

// this is the data from the kernel: NLMSG_DATA(nlh)
// this is how to change it: strcpy(NLMSG_DATA(nlh), new_string);