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

fnv-1a performing a couple of collisions better for a 30mbps encoded stream
Steven-Toth-MacBook-Pro:ts-recovery stoth$ ./ts-fnv-1a-collision-checker -i c2-short-200000.ts -a 0
Read 200000 packets
-- 200000 packets
pid 0x0000 has       90 collisions  0.04%
pid 0x0030 has       90 collisions  0.04%
pid 0x0033 has        5 collisions  0.00%
pid 0x0034 has        1 collisions  0.00%
pid 0x1fff has    31455 collisions 15.73%
matching seq len 14, matched 5700934, tried 397971000
Steven-Toth-MacBook-Pro:ts-recovery stoth$ ./ts-fnv-1a-collision-checker -i c2-short-200000.ts -a 1
Read 200000 packets
-- 200000 packets
pid 0x0000 has       90 collisions  0.04%
pid 0x0030 has       90 collisions  0.04%
pid 0x0031 has        2 collisions  0.00%
pid 0x0033 has        5 collisions  0.00%
pid 0x0034 has        1 collisions  0.00%
pid 0x1fff has    31455 collisions 15.73%
matching seq len 14, matched 5700934, tried 397971000
*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <libltntstools/ltntstools.h>

#include "fnv-1a.h"
#include "uint64ringarray.c"

struct tool_ctx_s
{
	char *ifn;
	int verbose;
	int hashAlgo; /* 0 = FNV-1a, 1 = crc32 */

	uint64_t packetCount; /* Read from disk / I/O */

	/* Collision count per pid. Typically padding and PSIP */
	uint32_t *pid_collisions;

	/* List of hashs as they arrive in stream order */
	UINT64RingArray *arrivalArray;

	/* List of hashes sorted ascending */
	uint64_t *array;
	uint64_t arrayCount;

	/* Number of overall hash collisions */
	uint64_t collisions;

	int matchingLength;
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

    return left;
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
		ctx->array = calloc(1, sizeof(uint64_t));
		ctx->array[0] = hash;
		ctx->arrayCount = 1;
		return 0;
	}

	int exists = 0;
	int pos = arrayFindInsertPosition(ctx, hash, &exists);

	ctx->array = realloc(ctx->array, (ctx->arrayCount + 1) * sizeof(uint64_t));
	assert(ctx->array);

	memmove(&ctx->array[pos + 1], &ctx->array[pos], (ctx->arrayCount - pos) * sizeof(uint64_t));
    ctx->array[pos] = hash;
    ctx->arrayCount++;

	if (exists) {
		ctx->collisions++;
		ret = 1;
	}

	return ret;
}

void sequenceMatching(struct tool_ctx_s *ctx)
{
	printf("Running sequence match for length %d, may take a while.\n", ctx->matchingLength);
	uint64_t matching = 0;
	uint64_t matched = 0;

	uint64_t *ahash = calloc(ctx->matchingLength, sizeof(uint64_t));
	uint64_t *chash = calloc(ctx->matchingLength, sizeof(uint64_t));

	uint64_t offset = 0; // Important.
//	for (int i = 0; i < UINT64RingArray_count(ctx->arrivalArray) - ctx->matchingLength; i++) {
	for (int i = 0; i < 2000; i++) {
		if (!g_running) {
			break;
		}
		//printf("matching %8d -- ", i);
		/* Get size hashs from the arrival list */
		offset = i;
		for (int j = 0; j < ctx->matchingLength; j++) {
			UINT64RingArray_enum(ctx->arrivalArray, &ahash[j], &offset);
		}

#if 0
		printf("a: ");
		for (int i = 0; i < ctx->matchingLength; i++) {
			printf("%16llx ", ahash[i]);
		}
		printf("\n");
#endif

		for (int j = i + 1; j < UINT64RingArray_count(ctx->arrivalArray) - ctx->matchingLength; j++) {

			matching++;

			/* Now see how many times those N hashes match across the rest of the list */
			uint64_t coffset = j;
			for (int j = 0; j < ctx->matchingLength; j++) {
				UINT64RingArray_enum(ctx->arrivalArray, &chash[j], &coffset);
			}

#if 0
			printf("b: ");
			for (int i = 0; i < ctx->matchingLength; i++) {
				printf("%16llx ", chash[i]);
			}
			printf("\n");
#endif

			if (memcmp(&ahash[0], &chash[0], ctx->matchingLength * sizeof(uint64_t)) == 0) {
				matched++;
#if 0
				printf("matched: ");
				for (int i = 0; i < ctx->matchingLength; i++) {
					printf("%16llx ", chash[i]);
				}
				printf("\n");
#endif
			}

		}
	}
	printf("Complete. Matched %llu, tried %llu\n", matched, matching);

	free(chash);
	free(ahash);
}

void usage()
{
	printf("usage: -i input.ts\n");
	printf("  -a <algo#> -- 0=Algo FNV-1a, 1=crc32 [def: 0]\n");
	printf("  -v increase verbosity\n");
	printf("  -m <number> run a sequence match of N length to see how sequences hashes help [def: disabled. 14 is a good number]\n");
}

int main(int argc, char *argv[])
{
	struct tool_ctx_s *ctx = calloc(1, sizeof(struct tool_ctx_s));

	/* 12 seconds of 240mbps - cache these hashes */
	ctx->arrivalArray = UINT64RingArray_alloc(160000 * 12);

	/* Count each time a hash collision occurs on a specific pid */
	ctx->pid_collisions = calloc(8192, sizeof(uint32_t));
	ctx->matchingLength = -1;

	int ch;
	while ((ch = getopt(argc, argv, "?ha:i:vm:")) != -1) {
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
		case 'm':
			ctx->matchingLength = atoi(optarg);
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

		/* push to algo, get a hash in return */
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
			exit(1);
		}

		/* Push the has onto the arrival list. A list of hashs in the order the packets were received. */
		UINT64RingArray_append(ctx->arrivalArray, h);

		/* Push the hash into a sorted ascending list. Register any collisions. */
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
			/* For long running tests, print the pid collision report periodically. */
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

	if (ctx->matchingLength > 1) {
		sequenceMatching(ctx);
	}

	free(ctx->pid_collisions);
	UINT64RingArray_free(ctx->arrivalArray);
	free(ctx->ifn);
	free(ctx);
	return 0;
}
