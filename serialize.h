#pragma once

#include <stdint.h>
#include <stdlib.h>
#include "block.h"

typedef uint8_t bool_t;
struct serializer;

struct serializer* serializer_create(size_t initial_size);
void serializer_close(struct serializer* s);
void serializer_write(struct serializer* s, const void* data, size_t size);
void serializer_write_block(struct serializer* s, const struct block* b);
void serializer_send_file(struct serializer* s, const char* filename);
void serializer_send_buffer(struct serializer* s, void(*callback)(const char* data, size_t size));
struct serializer* serializer_from_buffer(const char* data, size_t size);
bool_t serializer_read_packet(struct serializer* s, struct block* b);
void serializer_write_packet(struct serializer* s, const struct block* b);
void serializer_read_file(struct serializer* s, const char* filename);