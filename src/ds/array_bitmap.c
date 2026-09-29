#include "ds/array_bitmap.h"

/**
 * @file array_bitmap.c
 * @brief Block Allocation Bitmap Implementation (Array Data Structure)
 * 
 * In digital storage systems, a bitmap is a compact array where each bit represents
 * the allocation status of a storage block (0 = Free, 1 = Allocated).
 */

BlockBitmap* bitmap_create(size_t total_bits) {
    BlockBitmap *bm = (BlockBitmap*)malloc(sizeof(BlockBitmap));
    if (!bm) return NULL;

    bm->total_bits = total_bits;
    size_t num_bytes = (total_bits + 7) / 8;
    bm->bits = (uint8_t*)calloc(num_bytes, sizeof(uint8_t));
    if (!bm->bits) {
        free(bm);
        return NULL;
    }
    return bm;
}

void bitmap_destroy(BlockBitmap *bm) {
    if (!bm) return;
    if (bm->bits) {
        free(bm->bits);
    }
    free(bm);
}

void bitmap_set(BlockBitmap *bm, size_t bit_index) {
    if (!bm || bit_index >= bm->total_bits) return;
    bm->bits[bit_index / 8] |= (1 << (bit_index % 8));
}

void bitmap_clear(BlockBitmap *bm, size_t bit_index) {
    if (!bm || bit_index >= bm->total_bits) return;
    bm->bits[bit_index / 8] &= ~(1 << (bit_index % 8));
}

bool bitmap_test(const BlockBitmap *bm, size_t bit_index) {
    if (!bm || bit_index >= bm->total_bits) return false;
    return (bm->bits[bit_index / 8] & (1 << (bit_index % 8))) != 0;
}

int bitmap_find_first_free(const BlockBitmap *bm) {
    if (!bm) return -1;
    for (size_t i = 0; i < bm->total_bits; i++) {
        if (!bitmap_test(bm, i)) {
            return (int)i;
        }
    }
    return -1;
}

int bitmap_find_next_free(const BlockBitmap *bm, size_t start_index) {
    if (!bm) return -1;
    for (size_t i = start_index; i < bm->total_bits; i++) {
        if (!bitmap_test(bm, i)) {
            return (int)i;
        }
    }
    return -1;
}

size_t bitmap_count_free(const BlockBitmap *bm) {
    if (!bm) return 0;
    size_t free_count = 0;
    for (size_t i = 0; i < bm->total_bits; i++) {
        if (!bitmap_test(bm, i)) free_count++;
    }
    return free_count;
}

size_t bitmap_count_used(const BlockBitmap *bm) {
    if (!bm) return 0;
    return bm->total_bits - bitmap_count_free(bm);
}
