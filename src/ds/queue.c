#include "ds/queue.h"

/**
 * @file queue.c
 * @brief FIFO Task Queue Implementation
 * 
 * Used for queuing block ranges, carving jobs, and scanning tasks
 * in First-In First-Out order.
 */

Queue* queue_create(void) {
    Queue *q = (Queue*)malloc(sizeof(Queue));
    if (!q) return NULL;
    q->front = NULL;
    q->rear = NULL;
    q->size = 0;
    return q;
}

void queue_destroy(Queue *q, void (*free_data)(void *)) {
    if (!q) return;
    QueueNode *curr = q->front;
    while (curr) {
        QueueNode *next = curr->next;
        if (free_data && curr->data) {
            free_data(curr->data);
        }
        free(curr);
        curr = next;
    }
    free(q);
}

void queue_enqueue(Queue *q, void *data) {
    if (!q) return;
    QueueNode *node = (QueueNode*)malloc(sizeof(QueueNode));
    if (!node) return;
    node->data = data;
    node->next = NULL;

    if (q->rear) {
        q->rear->next = node;
    } else {
        q->front = node;
    }
    q->rear = node;
    q->size++;
}

void* queue_dequeue(Queue *q) {
    if (!q || !q->front) return NULL;
    QueueNode *node = q->front;
    void *data = node->data;

    q->front = node->next;
    if (!q->front) {
        q->rear = NULL;
    }
    free(node);
    q->size--;
    return data;
}

void* queue_peek(const Queue *q) {
    if (!q || !q->front) return NULL;
    return q->front->data;
}

bool queue_is_empty(const Queue *q) {
    return !q || (q->size == 0);
}

size_t queue_size(const Queue *q) {
    return q ? q->size : 0;
}
