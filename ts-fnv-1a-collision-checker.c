/*
 * Read a transport file from disk.
 * Produce a hash for each packet.
 * Store the has in a large list and count hashing collisions
 * Produce a report for collisions and uniqueness
 */

/*

A quick look at the effectiveness of FNV-1a vs CRC32 as a hash produce, same stream.
They look close enough to make no difference.

Steven-Toth-MacBook-Pro:ts-recovery stoth$ ./ts-fnv-1a-collision-checker -i c1.ts -a 0
-- 422289 packets
pid 0x0000 has      459 collisions  0.11%
pid 0x0020 has      459 collisions  0.11%
pid 0x0101 has    66103 collisions 15.65%
pid 0x0102 has        8 collisions  0.00%
pid 0x1fff has    57530 collisions 13.62%
Steven-Toth-MacBook-Pro:ts-recovery stoth$ ./ts-fnv-1a-collision-checker -i c1.ts -a 1
-- 400038 packets
pid 0x0000 has      434 collisions  0.11%
pid 0x0020 has      434 collisions  0.11%
pid 0x0101 has    61900 collisions 15.47%
pid 0x0102 has        9 collisions  0.00%
pid 0x1fff has    54595 collisions 13.65%
*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <libltntstools/ltntstools.h>

#include "fnv-1a.h"

typedef struct
{
	uint64_t *data;
	uint64_t maxEntries;
	uint64_t head;
	uint64_t tail;
	uint64_t overflowCount;
} UINT64RingArray;

UINT64RingArray *UINT64RingArray_alloc(uint64_t max)
{
	UINT64RingArray *ra = calloc(1, sizeof(*ra));
	if (ra) {
		ra->data = calloc(1, sizeof(max * sizeof(uint64_t)));
		if (!ra->data) {
			free(ra);
			return NULL;
		}

		ra->maxEntries = max;
	}

	return ra;
}

void UINT64RingArray_free(UINT64RingArray *ra)
{
	if (ra) {
		if (ra->data) {
			free(ra->data);
		}
		free(ra);
	}
}

int UINT64RingArray_count(UINT64RingArray *ra)
{
    return (ra->tail + ra->maxEntries - ra->head) % ra->maxEntries;
}

void UINT64RingArray_dprintf(UINT64RingArray *ra, int fd)
{
    int i = ra->head;
	uint32_t idx = 0;

    while (i != ra->tail) {
		dprintf(fd, "%08ud: %llx\n", idx++, ra->data[i]);
        i = (i + 1) % ra->maxEntries;
    }
	printf("%d entries\n", idx + 1);
}

void UINT64RingArray_append(UINT64RingArray *ra, uint64_t value)
{
	assert(ra);
	ra->data[ra->tail] = value;
    ra->tail = (ra->tail + 1) % ra->maxEntries;

    if (ra->tail == ra->head) {
        ra->head = (ra->head + 1) % ra->maxEntries;
		ra->overflowCount++;
    }
}

struct tool_ctx_s
{
	char *ifn;
	int verbose;
	int hashAlgo; /* 0 = FNV-1a, 1 = crc32 */

	uint64_t packetCount; /* Read from disk / I/O */

	/* List of hashs as they arrive in stream order */
	UINT64RingArray *arrivalArray;

	/* List of hashes sorted ascending */
	uint64_t *array;
	uint64_t arrayCount;

	/* Number of overall hash collisions */
	uint64_t collisions;

	/* Collision count per pid. Typically padding and PSIP */
	uint32_t pid_collisions[8192];
};

int g_running = 1;
void signal_handler(int sig)
{
	g_running = 0;
}

void arrayPrint(struct tool_ctx_s *ctx)
{
	for (uint64_t i = 0; i < ctx->arrayCount; i++) {
		printf("%llx\n", ctx->array[i]);
	}
	printf("%llu collisions\n", ctx->collisions);
}

int arrayFindInsertPosition(struct tool_ctx_s *ctx, uint64_t hash, int *exists)
{
    size_t left = 0, right = ctx->arrayCount;
    *exists = 0;

    while (left < right) {
        size_t mid = left + (right - left) / 2;
        if (ctx->array[mid] == hash) {
            *exists = 1;
            return mid;
        } else if (ctx->array[mid] < hash) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    return left;  // Index where value should be inserted
}

void collisionReport(struct tool_ctx_s *ctx)
{
	printf("-- %llu packets\n", ctx->arrayCount);
	for (int i = 0; i < 8192; i++) {
		if (ctx->pid_collisions[i] > 0) {
			double pct = ((double)ctx->pid_collisions[i] / (double)ctx->packetCount) * 100.0;
			printf("pid 0x%04x has %8d collisions %5.2f%%\n", i, ctx->pid_collisions[i], pct);
		}
	}
}

int arrayAdd(struct tool_ctx_s *ctx, uint64_t hash)
{
	int ret = 0;

	if (ctx->array == NULL) {
		ctx->array = malloc(sizeof(uint64_t));
		ctx->array[0] = hash;
		ctx->arrayCount = 1;
		return 0;
	}

	int exists = 0;
	int pos = arrayFindInsertPosition(ctx, hash, &exists);

	ctx->array = realloc(ctx->array, (ctx->arrayCount + 1) * sizeof(uint64_t));
	if (!ctx->array) {
		return -1;
	}

	memmove(&ctx->array[pos + 1], &ctx->array[pos], (ctx->arrayCount - pos) * sizeof(uint64_t));
    ctx->array[pos] = hash;
    ctx->arrayCount++;

	if (exists) {
		ctx->collisions++;
		ret = 1;
	}

	return ret;
}

void usage()
{
	printf("usage: -i input.ts\n");
	printf("  -a <algo#> -- 0=Algo FNV-1a, 1=crc32 [def: 0]\n");
	printf("  -v increase verbosity\n");
}

int main(int argc, char *argv[])
{
	struct tool_ctx_s *ctx = calloc(1, sizeof(*ctx));

	ctx->arrivalArray = UINT64RingArray_alloc(200000);

	int ch;
	while ((ch = getopt(argc, argv, "?ha:i:v:")) != -1) {
		switch (ch) {
		case 'b':
			break;
		case 'a':
			ctx->hashAlgo = atoi(optarg);
			break;
		case 'i':
			ctx->ifn = strdup(optarg);
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'h':
		case '?':
		default:
			usage();
			exit(1);
		}
	}

	if (ctx->ifn == NULL) {
		usage();
		exit(1);
	}

	signal(SIGINT, signal_handler);

	unsigned char pkt[188];

	time_t lastReport = time(NULL) - 3;
	FILE *ifh = fopen(ctx->ifn, "rb");
	while (!feof(ifh) && g_running) {
		int len = fread(&pkt[0], 1, 188, ifh);
		if (len <= 0) {
			break;
		}
		ctx->packetCount++;
		if (ctx->packetCount > 200000) {
			//break;
		}

		/* push to algo */
		uint64_t h = 0;
		if (ctx->hashAlgo == 0) {
			h = ltntstools_packet_fingerprint64(pkt);
		} else
		if (ctx->hashAlgo == 1) {
			uint32_t val;
			ltntstools_getCRC32(pkt, 188, &val);
			h = val;
		} else {
			printf("bad algo %d, aborting.\n", ctx->hashAlgo);
		}

		/* Push the has onto the arrival list */
		UINT64RingArray_append(ctx->arrivalArray, h);
		//printf("ra %d, overflow %llu\n", UINT64RingArray_count(ctx->arrivalArray), ctx->arrivalArray->overflowCount);

		/* Push the hash into the list, check for collisions etc */
		if (arrayAdd(ctx, h) == 1) {

			uint16_t pid = ltntstools_pid(pkt);
			ctx->pid_collisions[pid]++;

			if (ctx->verbose) {
				printf("pkt #%12llu: Collision on pid 0x%04x %16llx : ", ctx->packetCount, pid, h);
				for (int i = 0; i < 16; i++) {
					printf("%02x ", pkt[i]);
				}
				printf("\n");
			}
		}

		if (time(NULL) >= lastReport + 5) {
			lastReport = time(NULL);
			collisionReport(ctx);
		} 
	}
	fclose(ifh);
	if (ctx->verbose > 2) {
			arrayPrint(ctx);
	}

	printf("Read %llu packets\n", ctx->packetCount);

	collisionReport(ctx);

	UINT64RingArray_free(ctx->arrivalArray);
	free(ctx->ifn);
	free(ctx);
	return 0;
}
