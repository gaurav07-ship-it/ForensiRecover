#ifndef HEAP_H
#define HEAP_H

#include "common.h"

/**
 * @brief Element in Max-Heap Priority Queue
 */
typedef struct {
    double priority;         /* Recovery Confidence Score (e.g., 0.0 to 100.0) */
    void *data;              /* Pointer to candidate record */
} HeapElement;

/**
 * @brief Max-Heap Priority Queue
 * Used to rank recovered file candidates by confidence score.
 */
typedef struct {
    HeapElement *elements;
    size_t capacity;
    size_t size;
} MaxHeap;

/* Heap Operations */
MaxHeap* heap_create(size_t capacity);
void heap_destroy(MaxHeap *heap, void (*free_data)(void *));
bool heap_insert(MaxHeap *heap, double priority, void *data);
void* heap_extract_max(MaxHeap *heap, double *out_priority);
void* heap_peek_max(const MaxHeap *heap, double *out_priority);
size_t heap_size(const MaxHeap *heap);
bool heap_is_empty(const MaxHeap *heap);

#endif /* HEAP_H */
