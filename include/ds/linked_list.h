#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include "common.h"

/**
 * @brief Generic Doubly Linked List Node
 */
typedef struct ListNode {
    void *data;
    struct ListNode *prev;
    struct ListNode *next;
} ListNode;

/**
 * @brief Doubly Linked List Container
 * Used for maintaining active file lists, deleted file remnants, and fragmented block chains.
 */
typedef struct LinkedList {
    ListNode *head;
    ListNode *tail;
    size_t size;
} LinkedList;

/* Linked List Operations */
LinkedList* list_create(void);
void list_destroy(LinkedList *list, void (*free_data)(void *));
void list_push_back(LinkedList *list, void *data);
void list_push_front(LinkedList *list, void *data);
void* list_pop_front(LinkedList *list);
void* list_pop_back(LinkedList *list);
bool list_remove(LinkedList *list, void *data, bool (*compare)(const void *, const void *), void (*free_data)(void *));
void* list_find(const LinkedList *list, const void *key, bool (*compare)(const void *, const void *));
size_t list_size(const LinkedList *list);
bool list_is_empty(const LinkedList *list);

#endif /* LINKED_LIST_H */
