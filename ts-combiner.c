/*
 * Steven Toth <stoth@kernellabs.com>
 * Copyright (c) 2025 Kernel Labs Inc. All Rights Reserved.
 * 
 * Code that demonstrates receiving two transport streams from two seperate
 * distribution paths, creating crc checksums for each packet from
 * each path and attempting to deal with basic loss recovery.
 * The assumption is, path1 is a low latency 200ms internet feed.
 * Path2 is a much higher latency copy of the same feed, but on a much
 * more problematic distribution path.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libltntstools/ltntstools.h>

#define MAX_BUFFER (65536 * 2) /* TODO: This should be a function of bitrate */
#define MAX_SEQUENCE 120
#define CORRELATE_THRESHOLD 64
#define MAX_DELAY_MS 2500
#define MAX_LOOKAHEAD 8

typedef struct
{
    uint64_t hash;
    uint64_t timestamp_ms;
    unsigned char *data;
} Packet;

typedef struct {
    Packet packets[MAX_BUFFER];
    int head, tail;
    int streamNr;
} PacketBuffer;

typedef struct
{
    /* 1 is generally the most trusted leg, likely to have let drops, typically shortest latency with FEC/ARQ. */
    /* 2 is a less reliable leg, likely to have loss but not necessarily, typical long latency with no/minimal/unreliable correction. */
    /* 3 is corrected UDP output stream. */
    int nr; 
    int skt;

    uint64_t lastCounter;

    PacketBuffer *pb;
    PacketBuffer *pb_copy;

    struct sockaddr_in sa;
} Stream;

PacketBuffer *PacketBuffer_alloc(int streamNr)
{
    PacketBuffer *pb = calloc(1, sizeof(*pb));
    if (!pb) {
        return NULL;
    }

    for (int i = 0; i < MAX_BUFFER; i++) {
        pb->packets[i].data = calloc(1, 188);
    }
    pb->streamNr = streamNr;

    return pb;
}

void PacketBuffer_free(PacketBuffer *pb)
{
    if (!pb) {
        return;
    }

    for (int i = 0; i < MAX_BUFFER; i++) {
        if (pb->packets[i].data) {
            free(pb->packets[i].data);
            pb->packets[i].data = NULL;
        }
    }
}

typedef struct
{
    int verbose;
    int corrupt;

    uint64_t last_flush;

    Stream streams[3]; /* input streams 0, 1 and output stream 2 */
} Ctx;

uint64_t current_time_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    return (uint64_t)(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

void packet_push(PacketBuffer *buf, unsigned char *pkt, uint32_t hash, uint64_t ts)
{
    buf->packets[buf->tail].hash = hash;
    buf->packets[buf->tail].timestamp_ms = ts;
    assert(buf->packets[buf->tail].data);
    memcpy(buf->packets[buf->tail].data, pkt, 188);
    buf->tail = (buf->tail + 1) % MAX_BUFFER;

    if (buf->tail == buf->head) {
        buf->head = (buf->head + 1) % MAX_BUFFER; // overwrite oldest
        printf("[OVERFLOW]: Stream #%d\n", buf->streamNr);
        assert(0);
    }
}

int PacketBuffer_size(PacketBuffer *buf)
{
    return (buf->tail + MAX_BUFFER - buf->head) % MAX_BUFFER;
}

/* Remove N items from the list */
void PacketBuffer_advance(PacketBuffer *buf, int count)
{
    buf->head = (buf->head + count) % MAX_BUFFER;
}

/* Shallow copy the entire src packet content to a temporary list of packets.
 * Pointers are copied as-is, not reallocated.
 */
void PacketBuffer_copy(Packet *dst, PacketBuffer *src, int *out_len)
{
    int i = src->head;
    int count = 0;

    while (i != src->tail) {
        /* Shallow copy the packet, including the pointer to data */
        dst[count++] = src->packets[i];
        i = (i + 1) % MAX_BUFFER;
    }

    *out_len = count;
}

/* Essentially, compare two very long packet lists for CORRELATE_THRESHOLD (64) consecurity matching packets.
 * The list are assumpted to NOT be aligned, due to transmission latency.
 */
int correlate_sequences(Packet *a, int a_len, Packet *b, int b_len, int *a_start, int *b_start)
{
    for (int i = 0; i <= a_len - CORRELATE_THRESHOLD; ++i) {

        for (int j = 0; j <= b_len - CORRELATE_THRESHOLD; ++j) {
            int match = 1;
            for (int k = 0; k < CORRELATE_THRESHOLD; ++k) {
                if (a[i + k].hash != b[j + k].hash) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                *a_start = i;
                *b_start = j;
                return 1;
            }
        }

    }
    return 0;
}

int createInputSocket(Stream *stream, const char *addr, int port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&stream->sa, 0, sizeof(stream->sa));
    stream->sa.sin_family = AF_INET;
    stream->sa.sin_port = htons(port);
    stream->sa.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&stream->sa, sizeof(stream->sa)) < 0) {
        perror("bind");
        exit(1);
    }

    /* assume multicast */
    // sudo route add -net 224.0.0.0/4 -interface en0
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(addr);
    mreq.imr_interface.s_addr = INADDR_ANY;

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt mcast");
        exit(1);
    }

    /* Do some socket buffer tuning */
    int size = 0;
    socklen_t optlen = sizeof(size);
    getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, &optlen);
    printf("Receive buffer size: %8d bytes (before)\n", size);

    size = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, &optlen);
    printf("Receive buffer size: %8d bytes (after)\n", size);

    return sock;
}

/* Transmit a packet to UDP network */
void sendOutput(Ctx *ctx, Stream *stream, Packet *pkt)
{
    if (ltntstools_pid(&pkt->data[0]) == 0x32) {
        static uint64_t lastCounter = 0;
        static uint64_t currentCounter = 0;
        if (ltntstools_verifyPacketWith64bCounter(&pkt->data[0], 188, 0x32, lastCounter, &currentCounter) < 0) {
            printf("Stream OUT: counter error wanted %lld got %lld\n", lastCounter + 1, currentCounter);
        }
        lastCounter = currentCounter;  
    }

    sendto(stream->skt, &pkt->data[0], 188, 0, (struct sockaddr*)&stream->sa, sizeof(stream->sa));
}

/* For each TS packet, checksum it, add it to a list, check for any loss (santiy for debug) */
void ingestPackets(Ctx *ctx, Stream *stream, const unsigned char *pkts, int packetCount, uint64_t now)
{
    for (int i = 0; i < packetCount; i++) {
        unsigned char *p = (unsigned char *)&pkts[i * 188];

        if (stream->nr == 2) {
            if (ctx->corrupt++ == 3000) {
                ctx->corrupt = 0;
                p[23] = 0xda;
            }
        }

        if (ltntstools_pid(p) == 0x32) {
            uint64_t currentCounter;
            if (ltntstools_verifyPacketWith64bCounter(p, 188, 0x32, stream->lastCounter, &currentCounter) < 0) {
                printf("Stream %d: counter error wanted %lld got %lld\n", stream->nr, stream->lastCounter + 1, currentCounter);
            }
            stream->lastCounter = currentCounter;  
        }

        uint32_t val;
        ltntstools_getCRC32(p, 188, &val);

        packet_push(stream->pb, p, ntohl(val), now);
    }
}

/* Every period of time, go looking for matching sequences
 * and flush the payload to output the socket.
 */
void periodicProcess(Ctx *ctx)
{
    int alen = 0, blen = 0;
    PacketBuffer_copy(ctx->streams[0].pb_copy->packets, ctx->streams[0].pb, &alen);
    PacketBuffer_copy(ctx->streams[1].pb_copy->packets, ctx->streams[1].pb, &blen);

    int ai = 0, bi = 0;
    if (ctx->verbose) {
        printf("checking alen %d blen %d!\n", alen, blen);
    }

    if (correlate_sequences(ctx->streams[0].pb_copy->packets, alen, ctx->streams[1].pb_copy->packets, blen, &ai, &bi)) {
        int common = (alen - ai) < (blen - bi) ? (alen - ai) : (blen - bi);

        if (ctx->verbose) {
            printf("tada %d count, at ai %d bi %d!\n", common, ai, bi);
        }

        int i = 0;
        while (i < common) {
            uint32_t va = ctx->streams[0].pb_copy->packets[ai + i].hash;
            uint32_t vb = ctx->streams[1].pb_copy->packets[bi + i].hash;

            if (va == vb) {
                /* Send stream 1 to output */
                sendOutput(ctx, &ctx->streams[2], &ctx->streams[0].pb_copy->packets[ai + i]);
                i++;
                continue;
            }

            int matched = 0;

            for (int la = 1; la <= MAX_LOOKAHEAD && (i + la) < common; ++la) {
                // stream1 loss recovery
                if (ctx->streams[0].pb_copy->packets[ai + i + la].hash == ctx->streams[1].pb_copy->packets[bi + i].hash) {
                    printf("[RECOVER] stream1 lost %d packets at i=%d\n", la, i);
                    for (int k = 0; k < la; k++) {
                        sendOutput(ctx, &ctx->streams[2], &ctx->streams[1].pb_copy->packets[bi + i + k]);
                    }
                    i += la;
                    matched = 1;
                    break;
                }

                // stream2 loss recovery
                if (ctx->streams[1].pb_copy->packets[bi + i + la].hash == ctx->streams[0].pb_copy->packets[ai + i].hash) {
                    printf("[RECOVER] stream2 lost %d packets at i=%d\n", la, i);
                    for (int k = 0; k < la; k++) {
                        sendOutput(ctx, &ctx->streams[2], &ctx->streams[0].pb_copy->packets[ai + i + k]);
                    }
                    i += la;
                    matched = 1;
                    break;
                }
            }

            if (!matched) {
                printf("[WARNING] mismatch at i=%d, stream1=0x%08x, stream2=0x%08x, using stream1\n", i, va, vb);
                sendOutput(ctx, &ctx->streams[2], &ctx->streams[0].pb_copy->packets[ai + i]);
                i++;
            }
        }

        PacketBuffer_advance(ctx->streams[0].pb, ai + common);
        PacketBuffer_advance(ctx->streams[1].pb, bi + common);
    }
}

int main()
{
    Ctx *ctx = calloc(1, sizeof(*ctx));
    ctx->verbose = 1;
    ctx->corrupt = 0;

    /* Build a couple of inputs streams */
    ctx->streams[0].nr  = 1;
    ctx->streams[0].pb  = PacketBuffer_alloc(1);
    ctx->streams[0].pb_copy  = PacketBuffer_alloc(3);
    ctx->streams[0].skt = createInputSocket(&ctx->streams[0], "227.1.1.1", 4001); /* 200ms latency */

    ctx->streams[1].nr  = 2;
    ctx->streams[1].pb  = PacketBuffer_alloc(2);
    ctx->streams[1].pb_copy  = PacketBuffer_alloc(4);
    ctx->streams[1].skt = createInputSocket(&ctx->streams[1], "227.1.1.1", 4002); /* 5500ms latency */

    /* Create the UDP output stream */
    ctx->streams[2].nr  = 2;
    ctx->streams[2].pb  = NULL;
    ctx->streams[2].pb_copy  = NULL;
    ctx->streams[2].skt = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ctx->streams[2].sa, 0, sizeof(ctx->streams[2].sa));
    ctx->streams[2].sa.sin_family = AF_INET;
    ctx->streams[2].sa.sin_port = htons(4001);
    ctx->streams[2].sa.sin_addr.s_addr = inet_addr("227.1.1.100");

    ctx->last_flush = current_time_ms();

    /* Setup a transport packet buffer */
    int pktlen = 128 * 188;
    unsigned char *pkts = malloc(pktlen);

    fd_set readfds;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(ctx->streams[0].skt, &readfds);
        FD_SET(ctx->streams[1].skt, &readfds);

        int maxfd = ctx->streams[0].skt > ctx->streams[1].skt ? ctx->streams[0].skt : ctx->streams[1].skt;

        struct timeval tv = {.tv_sec = 0, .tv_usec = 100000}; /* 100ms */
        int ret = select(maxfd + 1, &readfds, NULL, NULL, &tv);

        if (ret > 0) {
            ssize_t len;
            for (int i = 0; i < 2; i++) {
                if (FD_ISSET(ctx->streams[i].skt, &readfds)) {
                    len = recv(ctx->streams[i].skt, pkts, pktlen, 0);
                    if (len > 0) {
                        uint64_t now = current_time_ms();
                        ingestPackets(ctx, &ctx->streams[i], pkts, len / 188, now);
                    }
                }
            }
        }

        /* Periodically, process stream and output packets to UDP. */
        if (current_time_ms() - ctx->last_flush > MAX_DELAY_MS) {
            ctx->last_flush = current_time_ms();
            periodicProcess(ctx);
        }
    }

    close(ctx->streams[0].skt);
    PacketBuffer_free(ctx->streams[0].pb);
    PacketBuffer_free(ctx->streams[0].pb_copy);

    close(ctx->streams[1].skt);
    PacketBuffer_free(ctx->streams[1].pb);
    PacketBuffer_free(ctx->streams[1].pb_copy);

    free(pkts);
    free(ctx);

    return 0;
}

