/*
 * Read a transport file from disk.
 * Produce a hash for each packet.
 * Store the has in a large list and count hashing collisions
 * Produce a report for collisions and uniqueness
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libltntstools/ltntstools.h>

#include "fnv-1a.h"

struct tool_ctx_s
{
	char *ifn;
	int verbose;

	uint64_t packetCount;

	uint64_t *array;
	uint64_t arrayCount;

	uint64_t collisions;

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
}

int main(int argc, char *argv[])
{
	struct tool_ctx_s *ctx = calloc(1, sizeof(*ctx));

	int ch;
	while ((ch = getopt(argc, argv, "?hi:v")) != -1) {
		switch (ch) {
		case 'b':
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
		uint64_t h = ltntstools_packet_fingerprint64(pkt);
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
	}
	fclose(ifh);
	//arrayPrint(ctx);

	printf("Read %llu packets\n", ctx->packetCount);

	for (int i = 0; i < 8192; i++) {
		if (ctx->pid_collisions[i] > 0) {
			double pct = ((double)ctx->pid_collisions[i] / (double)ctx->packetCount) * 100.0;
			printf("pid 0x%04x has %8d collisions %5.2f%%\n", i, ctx->pid_collisions[i], pct);
		}
	}

	free(ctx->ifn);
	free(ctx);
	return 0;
}
