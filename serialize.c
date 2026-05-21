#include "serialize.h"

// CRC functions

uint32_t crc32_table[256];
char crc32_initialized = 0;

void build_crc32_table(void) {
	for(uint32_t i = 0;i < 256;i++) {
		uint32_t ch = i;
		uint32_t crc = 0;
		for(size_t j = 0;j < 8;j++) {
			uint32_t b = (ch ^ crc)&1;
			crc >>= 1;
			if(b) crc = crc ^ 0xEDB88320;
			ch >>= 1;
		}
		crc32_table[i] = crc;
	}
    crc32_initialized = 1;
}

uint32_t crc32_fast(const char *s,size_t n) {
	uint32_t crc = 0xFFFFFFFF;
	
	for(size_t i = 0;i < n;i++) {
		char ch = s[i];
		uint32_t t= (ch ^ crc)&0xFF;
		crc = (crc >> 8) ^ crc32_table[t];
	}
	
	return ~crc;
}


struct serializer
{
    char* buffer;
    size_t size, cursor;
};

struct serializer* serializer_create(size_t initial_size)
{
    struct serializer* s = (struct serializer*)malloc(sizeof(struct serializer));
    s->size = initial_size;
    s->cursor = 0;
    s->buffer = (char*)malloc(initial_size);
    return s;
}

void serializer_close(struct serializer* s)
{
    if (s) {
        free(s->buffer);
        s->buffer = NULL;
        s->size = 0;
        s->cursor = 0;
        free(s);
    }
}

void serializer_write(struct serializer* s, const void* data, size_t size)
{
    if (s->cursor + size > s->size) {
        size_t new_size = s->size * 2;
        while (new_size < s->cursor + size) {
            new_size *= 2;
        }
        char* orig_buffer = s->buffer;
        char* new_buffer = (char*)realloc(s->buffer, new_size);
        if (new_buffer) {
            s->buffer = new_buffer;
            s->size = new_size;
        } else {
            s->buffer = orig_buffer; // restore original buffer on failure
            return; 
        }
    }
    memcpy(s->buffer + s->cursor, data, size);
    s->cursor += size;
}

void serializer_write_block(struct serializer* s, const struct block* b)
{
    if (s == NULL || b == NULL) return;
    serializer_write(s, b->sha, sizeof(b->sha));
    serializer_write(s, &b->header, sizeof(b->header));
    for (size_t i = 0; i < b->data.size; ++i) {
        serializer_write(s, &b->data.t[i], sizeof(struct transaction));
    }
}

bool_t serializer_read_block(struct serializer* s, struct block* b)
{
    if (s == NULL || b == NULL) return 0;
    if (s->cursor < sizeof(b->sha) + sizeof(b->header)) return 0; // Not enough data
    memcpy(b->sha, s->buffer + s->cursor, sizeof(b->sha));
    s->cursor += sizeof(b->sha);
    memcpy(&b->header, s->buffer + s->cursor, sizeof(b->header));
    s->cursor += sizeof(b->header);

    b->data.size = (s->cursor - sizeof(b->sha) - sizeof(b->header)) / sizeof(struct transaction);
    b->data.t = (struct transaction*)malloc(sizeof(struct transaction) * b->data.size);
    for (size_t i = 0; i < b->data.size; ++i) {
        if (s->cursor + sizeof(struct transaction) > s->size) {
            free(b->data.t);
            return 0; // Not enough data for transactions
        }
        memcpy(&b->data.t[i], s->buffer + s->cursor, sizeof(struct transaction));
        s->cursor += sizeof(struct transaction);
    }

    return 1;
}

void serializer_write_packet(struct serializer* s, const struct block* b)
{
    const char* magic = "BLCK\xFF";
    serializer_write(s, magic, 5);
    serializer_write_block(s, b);

    if(!crc32_initialized) {
        build_crc32_table();
    }

    uint32_t crc = crc32_fast(s->buffer, s->cursor);
    serializer_write(s, &crc, sizeof(uint32_t));
}

bool_t serializer_read(struct serializer* s, void* data, size_t size)
{
    if (s->cursor + size > s->size) return 0; // Not enough data
    memcpy(data, s->buffer + s->cursor, size);
    s->cursor += size;
    return 1;
}

bool_t serializer_read_packet(struct serializer* s, struct block* b)
{
    const char* expected_magic = "BLCK\xFF";
    if (s->size < 5) return 0; // Not enough data for magic
    if (memcmp(s->buffer, expected_magic, 5) != 0) return 0; // Magic mismatch

    s->cursor = 5;
    uint32_t stored_crc;
    if(serializer_read_block(s, b) == 0) return 0; // Failed to read block data
    if(serializer_read(s, &stored_crc, sizeof(uint32_t)) == 0) return 0; // Not enough data for CRC

    if(!crc32_initialized) {
        build_crc32_table();
    }

    uint32_t calculated_crc = crc32_fast(s->buffer, s->size - sizeof(uint32_t)); 
    return stored_crc == calculated_crc;
}

struct serializer* serializer_from_buffer(const char* data, size_t size)
{
    struct serializer* s = (struct serializer*)malloc(sizeof(struct serializer));
    s->size = size;
    s->cursor = size;
    s->buffer = (char*)malloc(size);
    memcpy(s->buffer, data, size);
    return s;
}

void serializer_send_buffer(struct serializer* s, void(*callback)(const char* data, size_t size))
{
    if (s == NULL || callback == NULL) return;
    callback(s->buffer, s->cursor);
}

void serializer_send_file(struct serializer* s, const char* filename)
{
    if (s == NULL || filename == NULL) return;
    FILE* f = fopen(filename, "wb");
    if (f) {
        fwrite(s->buffer, 1, s->cursor, f);
        fclose(f);
    }
}

void serializer_read_file(struct serializer* s, const char* filename)
{
    if (s == NULL || filename == NULL) return;
    FILE* f = fopen(filename, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        size_t file_size = ftell(f);
        fseek(f, 0, SEEK_SET);

        char* buffer = (char*)malloc(file_size);
        if (buffer) {
            fread(buffer, 1, file_size, f);
            fclose(f);

            free(s->buffer);
            s->buffer = buffer;
            s->size = file_size;
            s->cursor = file_size;
        } else {
            fclose(f);
        }
    }
}