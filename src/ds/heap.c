#include "ds/heap.h"

/**
 * @file heap.c
 * @brief Max-Heap Priority Queue Implementation
 * 
 * Used to rank recovered file candidates according to their recovery confidence score
 * (0.0 to 100.0) so the most trustworthy files are processed first.
 */

static void swap_elements(HeapElement *a, HeapElement *b) {
    HeapElement temp = *a;
    *a = *b;
    *b = temp;
}

MaxHeap* heap_create(size_t capacity) {
    if (capacity == 0) capacity = 32;
    MaxHeap *heap = (MaxHeap*)malloc(sizeof(MaxHeap));
    if (!heap) return NULL;

    heap->capacity = capacity;
    heap->size = 0;
    heap->elements = (HeapElement*)malloc(sizeof(HeapElement) * capacity);
    if (!heap->elements) {
        free(heap);
        return NULL;
    }
    return heap;
}

void heap_destroy(MaxHeap *heap, void (*free_data)(void *)) {
    if (!heap) return;
    if (free_data) {
        for (size_t i = 0; i < heap->size; i++) {
            if (heap->elements[i].data) {
                free_data(heap->elements[i].data);
            }
        }
    }
    free(heap->elements);
    free(heap);
}

static void heapify_up(MaxHeap *heap, size_t index) {
    while (index > 0) {
        size_t parent = (index - 1) / 2;
        if (heap->elements[index].priority > heap->elements[parent].priority) {
            swap_elements(&heap->elements[index], &heap->elements[parent]);
            index = parent;
        } else {
            break;
        }
    }
}

static void heapify_down(MaxHeap *heap, size_t index) {
    size_t size = heap->size;
    while (true) {
        size_t largest = index;
        size_t left = 2 * index + 1;
        size_t right = 2 * index + 2;

        if (left < size && heap->elements[left].priority > heap->elements[largest].priority) {
            largest = left;
        }
        if (right < size && heap->elements[right].priority > heap->elements[largest].priority) {
            largest = right;
        }

        if (largest != index) {
            swap_elements(&heap->elements[index], &heap->elements[largest]);
            index = largest;
        } else {
            break;
        }
    }
}

bool heap_insert(MaxHeap *heap, double priority, void *data) {
    if (!heap) return false;

    /* Dynamic resize if capacity reached */
    if (heap->size >= heap->capacity) {
        size_t new_cap = heap->capacity * 2;
        HeapElement *new_elems = (HeapElement*)realloc(heap->elements, sizeof(HeapElement) * new_cap);
        if (!new_elems) return false;
        heap->elements = new_elems;
        heap->capacity = new_cap;
    }

    size_t index = heap->size++;
    heap->elements[index].priority = priority;
    heap->elements[index].data = data;
    heapify_up(heap, index);
    return true;
}

void* heap_extract_max(MaxHeap *heap, double *out_priority) {
    if (!heap || heap->size == 0) return NULL;

    void *root_data = heap->elements[0].data;
    if (out_priority) {
        *out_priority = heap->elements[0].priority;
    }

    heap->elements[0] = heap->elements[--heap->size];
    if (heap->size > 0) {
        heapify_down(heap, 0);
    }
    return root_data;
}

void* heap_peek_max(const MaxHeap *heap, double *out_priority) {
    if (!heap || heap->size == 0) return NULL;
    if (out_priority) {
        *out_priority = heap->elements[0].priority;
    }
    return heap->elements[0].data;
}

size_t heap_size(const MaxHeap *heap) {
    return heap ? heap->size : 0;
}

bool heap_is_empty(const MaxHeap *heap) {
    return !heap || (heap->size == 0);
}
