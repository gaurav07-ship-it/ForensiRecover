#ifndef ARRAY_BITMAP_H
#define ARRAY_BITMAP_H

#include "common.h"

/**
 * @brief Block Allocation Bitmap
 * Uses a bit array (uint8_t array) to track whether each block on the virtual disk
 * is allocated (1) or free (0).
 */
typedef struct {
    uint8_t *bits;      /* Array of bytes representing bitmap */
    size_t total_bits;  /* Total number of blocks tracked */
} BlockBitmap;

/* Bitmap Operations */
BlockBitmap* bitmap_create(size_t total_bits);
void bitmap_destroy(BlockBitmap *bm);
void bitmap_set(BlockBitmap *bm, size_t bit_index);
void bitmap_clear(BlockBitmap *bm, size_t bit_index);
bool bitmap_test(const BlockBitmap *bm, size_t bit_index);
int bitmap_find_first_free(const BlockBitmap *bm);
int bitmap_find_next_free(const BlockBitmap *bm, size_t start_index);
size_t bitmap_count_free(const BlockBitmap *bm);
size_t bitmap_count_used(const BlockBitmap *bm);

#endif /* ARRAY_BITMAP_H */
