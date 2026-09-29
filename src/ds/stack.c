#include "ds/stack.h"

/**
 * @file stack.c
 * @brief LIFO Stack Implementation
 * 
 * Used for maintaining disk operation history, carving backtrack trails,
 * and undo/redo states in forensic workflows.
 */

Stack* stack_create(void) {
    Stack *s = (Stack*)malloc(sizeof(Stack));
    if (!s) return NULL;
    s->top = NULL;
    s->size = 0;
    return s;
}

void stack_destroy(Stack *s, void (*free_data)(void *)) {
    if (!s) return;
    StackNode *curr = s->top;
    while (curr) {
        StackNode *next = curr->next;
        if (free_data && curr->data) {
            free_data(curr->data);
        }
        free(curr);
        curr = next;
    }
    free(s);
}

void stack_push(Stack *s, void *data) {
    if (!s) return;
    StackNode *node = (StackNode*)malloc(sizeof(StackNode));
    if (!node) return;
    node->data = data;
    node->next = s->top;
    s->top = node;
    s->size++;
}

void* stack_pop(Stack *s) {
    if (!s || !s->top) return NULL;
    StackNode *node = s->top;
    void *data = node->data;
    s->top = node->next;
    free(node);
    s->size--;
    return data;
}

void* stack_peek(const Stack *s) {
    if (!s || !s->top) return NULL;
    return s->top->data;
}

bool stack_is_empty(const Stack *s) {
    return !s || (s->size == 0);
}

size_t stack_size(const Stack *s) {
    return s ? s->size : 0;
}
