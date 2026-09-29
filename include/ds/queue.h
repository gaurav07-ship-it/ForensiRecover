#ifndef QUEUE_H
#define QUEUE_H

#include "common.h"

/**
 * @brief Queue Node
 */
typedef struct QueueNode {
    void *data;
    struct QueueNode *next;
} QueueNode;

/**
 * @brief FIFO Queue
 * Used to manage forensic scanning tasks and block analysis pipelines.
 */
typedef struct Queue {
    QueueNode *front;
    QueueNode *rear;
    size_t size;
} Queue;

/* Queue Operations */
Queue* queue_create(void);
void queue_destroy(Queue *q, void (*free_data)(void *));
void queue_enqueue(Queue *q, void *data);
void* queue_dequeue(Queue *q);
void* queue_peek(const Queue *q);
bool queue_is_empty(const Queue *q);
size_t queue_size(const Queue *q);

#endif /* QUEUE_H */
