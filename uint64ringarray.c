
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
		ra->data = calloc(1, max * sizeof(uint64_t));
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

/*
 * uint64_t hash;
 * uint64_t offset = 0; // Important.
 * while(UINT64RingArray_enum(ra, &hash, &offset)) {
 *   printf("hash %llx\n", hash);
 * }
 */
int UINT64RingArray_enum(UINT64RingArray *ra, uint64_t *result, uint64_t *offset)
{
	if (*offset > UINT64RingArray_count(ra)) {
		return 0;
	}

	*result = ra->data[ (ra->head + *offset) % ra->maxEntries ];
	*offset = *offset + 1;
	return 1;
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
	assert(ra->tail < ra->maxEntries);

	ra->data[ra->tail] = value;
    ra->tail = (ra->tail + 1) % ra->maxEntries;

    if (ra->tail == ra->head) {
        ra->head = (ra->head + 1) % ra->maxEntries;
		ra->overflowCount++;
    }
}

