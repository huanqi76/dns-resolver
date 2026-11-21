#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>


int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    printf("Socket number: %d\n", fd);

    struct sockaddr_in addr; // defined in netinet/in.h
    memset(&addr, 0, sizeof(addr)); // zero out address
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(5353);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    pritnf("listening on port 5353\n");
    return 0;
}