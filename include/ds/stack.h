#ifndef STACK_H
#define STACK_H

#include "common.h"

/**
 * @brief Stack Node
 */
typedef struct StackNode {
    void *data;
    struct StackNode *next;
} StackNode;

/**
 * @brief LIFO Stack
 * Used for maintaining operation history, forensic recovery logs, and carving backtrack state.
 */
typedef struct Stack {
    StackNode *top;
    size_t size;
} Stack;

/* Stack Operations */
Stack* stack_create(void);
void stack_destroy(Stack *s, void (*free_data)(void *));
void stack_push(Stack *s, void *data);
void* stack_pop(Stack *s);
void* stack_peek(const Stack *s);
bool stack_is_empty(const Stack *s);
size_t stack_size(const Stack *s);

#endif /* STACK_H */
