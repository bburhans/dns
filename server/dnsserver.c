/****************************************************************************
FILE   : dnsserver.c
SUBJECT: Implementation of a simple DNS server.

Please send comments or bug reports to

     Peter C. Chapin
     Computer Information Systems
     Vermont Technical College
     Williston, VT 05495
     pchapin@vtc.edu

Modified by
     Ben Burhans
     2021-03-12
     VTC/2021-SP/CIS-3152-TH1/homework03/dns/server/dnsserver.c
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#ifndef S_SPLINT_S    // Workaround for splint.
#include <unistd.h>
#endif

#include <stdint.h>

#define DATAGRAM_BUFFER_SIZE 512

// These buffers hold the datagrams used by the server.
unsigned char query[DATAGRAM_BUFFER_SIZE];
unsigned char reply[DATAGRAM_BUFFER_SIZE];

// Everything is big-endian, both bytewise and bitwise
/* Lengths:
    labels          63, octets or less
    names           255 octets or less
    TTL             positive values of a signed 32 bit number.
    UDP messages    512 octets or less
*/


enum types {
    A = 1, // a host address
    NS = 2, // an authoritative name server
    MD = 3, // a mail destination (Obsolete - use MX)
    MF = 4, // a mail forwarder (Obsolete - use MX)
    CNAME = 5, // the canonical name for an alias
    SOA = 6, // marks the start of a zone of authority
    MB = 7, // a mailbox domain name (EXPERIMENTAL)
    MG = 8, // a mail group member (EXPERIMENTAL)
    MR = 9, // a mail rename domain name (EXPERIMENTAL)
    NUL = 10, // a null RR (EXPERIMENTAL) // actually NULL but that's a reserved token
    WKS = 11, // a well known service description
    PTR = 12, // a domain name pointer
    HINFO = 13, // host information
    MINFO = 14, // mailbox or mail list information
    MX = 15, // mail exchange
    TXT = 16, // text strings
    // TODO: update from a newer RFC, e.g. to support AAAA
};

enum qtypes {
    AXFR = 252, // A request for a transfer of an entire zone
    MAILB = 253, // A request for mailbox-related records (MB, MG or MR)
    MAILA = 254, // A request for mail agent RRs (Obsolete - see MX)
    ALL = 255, // A request for all records // actually * but that's a reserved token
};

enum classes {
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]
};

enum qclasses {
    ANY = 255, // any class
};

enum qr {
    Q = 0, // query
    R = 1, // response
};

enum opcode {
    QUERY = 0, // a standard query
    IQUERY = 1, // an inverse query
    STATUS = 2, // a server status request
};

enum rcode {
                OK=0, /*
                               No error condition */

                FORMAT_ERROR=1, /*
                               Format error - The name server was
                                unable to interpret the query. */

                SERVER_FAILURE=2, /*
                               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server. */

                NAME_ERROR=3, /*
                               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist. */

                NOT_IMPLEMENTED=4, /*
                               Not Implemented - The name server does
                                not support the requested kind of query. */

                REFUSED=5, /*
                               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone
                                transfer) for particular data. */
};

struct rr {
    char * name; //dn
    uint16_t type;
    uint16_t class;
    uint16_t ttl;
    uint16_t rdlength;
    char * rdata; //rr[]
};

struct hinfo {
    char * cpu;
    char * os;
};

struct minfo {
    char * rmailbx;
    char * emailbx;
};

struct mx {
    uint16_t preference;
    char * exchange; //dn
};

struct soa {
    char * mname; //dn
    char * rname; //dn
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
};

struct wks {
    uint32_t address;
    uint8_t protocol;
    char * bitmap;
};

struct header {
    uint16_t id; // copied into the response
    uint16_t qr :1; // query (Q=0) or response (R=1)
    uint16_t opcode :4; // copied into the response
    uint16_t aa :1; // Authoritative Answer
    uint16_t tc :1; // TrunCation
    uint16_t rd :1; // Recursion Desired, copied into the response
    uint16_t ra :1; // Recursion Available
    uint16_t z :3; // Zero, must be zero
    uint16_t rcode :4; // Response code
    uint16_t qdcount; // Number of question entries
    uint16_t ancount; // Number of answer resource records
    uint16_t nscount; // Number of authority name server RRs
    uint16_t arcount; // Number of additional records
};

struct question {
    char * qname;
    uint16_t qtype;
    uint16_t qclass;
};

struct pointer {
    // ignore message compression for this project
    // "Programs are free to avoid using pointers in messages they generate"
};

struct message {
    // Note: inverse queries (opcode = IQUERY) work by populating the answer, not the question! Jeopardy-style. RIP Alex Trebek.
    struct header header;
    struct question * question;
    struct rr * answer;
    struct rr * authority;
    struct rr * additional;
};

unsigned char * install_domain_name(unsigned char *p, char *domain_name)
{
    // From pchapin's dnsclient.c
    // .lemuria.cis.vtc.edu\0
    // 7lemuria3cis3vtc3edu0   Note that the numbers are *NOT* ASCII codes, but binary values.
    *p++ = '.';
    strcpy((char *)p, domain_name);
    p--;

    while (*p != '\0') {
        if (*p == '.') {
            unsigned char *end = p + 1;
            while (*end != '.' && *end != '\0') end++;
            *p = end - p - 1;
        }
        p++;
    }
    return p + 1;
}

// Return -1 on success, or the source offset of the error otherwise
int deserialize(unsigned char * workspace, struct message * message)
{
    memcpy(&message->header, workspace, sizeof(uint16_t) * 6);
    struct header * header = &message->header;
    struct question * question = (struct question *)malloc(sizeof(struct question)
        * ntohs(header->qdcount));
    printf("ID %u\nQR %u\nOPCODE %u\nQDCOUNT %u\n", header->id, header->qr, header->opcode, ntohs(header->qdcount));
    free(question);
    return -1;
}

int main( int argc, char **argv )
{
    // Some socket and "workspace" boilerplate code is from pchapin's dnsclient.c and echoserver.c.

    // +++ Set up the UDP socket
    int socket_handle;
    unsigned short port = argc == 2 ? atoi(argv[1]) : 53;
    if ((socket_handle = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Unable to create socket");
        return EXIT_FAILURE;
    }
    struct sockaddr_in server_address;
    memset( &server_address, 0, sizeof(server_address) );
    server_address.sin_family      = AF_INET;
    server_address.sin_addr.s_addr = htonl( INADDR_ANY );
    server_address.sin_port        = htons( port );
    if( bind( socket_handle, (struct sockaddr *) &server_address, sizeof(server_address) ) < 0 ) {
        perror( "Unable to bind socket" );
        close( socket_handle );
        return EXIT_FAILURE;
    }
    
    unsigned char workspace[512];

    while( 1 ) {
        // +++ Receive a request from a client.
        
        struct sockaddr_in client_address;
        socklen_t client_address_length = sizeof( client_address );
        int rc = recvfrom(
            socket_handle, 
            workspace,
            512,
            0,
            (struct sockaddr *)&client_address,
            &client_address_length
        );
        if (rc < 0) {
            continue;
        }

        // +++ Decode request. Is it valid? If not, ignore it.
        //     Print message to standard output:
        //     - IP address and port number of client.
        //     - If the request is valid or not
        //     - For valid requests, the domain name(s) requested.

        char ipv4_addr[16];
        if (inet_ntop(AF_INET, &client_address.sin_addr, ipv4_addr, 16) <= 0) {
            perror("invalid client IPv4 address");
        }
        uint16_t client_port = ntohs(client_address.sin_port);
        printf("client: %s:%u\n", ipv4_addr, client_port);

        struct message * message = (struct message *)malloc(sizeof(struct message));
        int errorpos = deserialize(workspace, message);
        if (errorpos == -1) {
            printf("message seems valid so far\n");
        }
        else {
            printf("message invalid at position %d\n", errorpos);
        }
        

        // +++ Construct reply. Use an IP address of 127.0.0.1 for all domain names
        //     FUTURE ENHANCEMENT: Look up IP addresses from a database.

        // +++ Send reply to client.
        free(message);
    }

    return EXIT_SUCCESS;
}
