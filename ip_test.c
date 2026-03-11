#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For gethostname
#include <netdb.h>  // For gethostbyname
#include <arpa/inet.h> // For inet_ntoa

int main() {
    char hostname[256];
    struct hostent *host_entry;
    char *ip_address;

    // Get the hostname
    if (gethostname(hostname, sizeof(hostname)) == -1) {
        perror("gethostname");
        return 1;
    }
    printf("Hostname: %s\n", hostname);

    // Get host information by name
    host_entry = gethostbyname(hostname);
    if (host_entry == NULL) {
        herror("gethostbyname");
        return 1;
    }

    // Convert the IP address to a human-readable string
    ip_address = inet_ntoa(*(struct in_addr *)host_entry->h_addr_list[0]);
    printf("IP Address: %s\n", ip_address);

    return 0;
}