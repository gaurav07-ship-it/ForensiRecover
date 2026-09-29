#include "ds/linked_list.h"

/**
 * @file linked_list.c
 * @brief Doubly Linked List Implementation
 * 
 * Used for maintaining dynamic records such as active filesystem directories,
 * deleted file remnant pools, and unallocated block tracking chains.
 */

LinkedList* list_create(void) {
    LinkedList *list = (LinkedList*)malloc(sizeof(LinkedList));
    if (!list) return NULL;
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
    return list;
}

void list_destroy(LinkedList *list, void (*free_data)(void *)) {
    if (!list) return;
    ListNode *curr = list->head;
    while (curr) {
        ListNode *next = curr->next;
        if (free_data && curr->data) {
            free_data(curr->data);
        }
        free(curr);
        curr = next;
    }
    free(list);
}

void list_push_back(LinkedList *list, void *data) {
    if (!list) return;
    ListNode *node = (ListNode*)malloc(sizeof(ListNode));
    if (!node) return;
    node->data = data;
    node->next = NULL;
    node->prev = list->tail;

    if (list->tail) {
        list->tail->next = node;
    } else {
        list->head = node;
    }
    list->tail = node;
    list->size++;
}

void list_push_front(LinkedList *list, void *data) {
    if (!list) return;
    ListNode *node = (ListNode*)malloc(sizeof(ListNode));
    if (!node) return;
    node->data = data;
    node->prev = NULL;
    node->next = list->head;

    if (list->head) {
        list->head->prev = node;
    } else {
        list->tail = node;
    }
    list->head = node;
    list->size++;
}

void* list_pop_front(LinkedList *list) {
    if (!list || !list->head) return NULL;
    ListNode *node = list->head;
    void *data = node->data;

    list->head = node->next;
    if (list->head) {
        list->head->prev = NULL;
    } else {
        list->tail = NULL;
    }
    free(node);
    list->size--;
    return data;
}

void* list_pop_back(LinkedList *list) {
    if (!list || !list->tail) return NULL;
    ListNode *node = list->tail;
    void *data = node->data;

    list->tail = node->prev;
    if (list->tail) {
        list->tail->next = NULL;
    } else {
        list->head = NULL;
    }
    free(node);
    list->size--;
    return data;
}

bool list_remove(LinkedList *list, void *data, bool (*compare)(const void *, const void *), void (*free_data)(void *)) {
    if (!list || !list->head) return false;
    ListNode *curr = list->head;
    while (curr) {
        bool match = false;
        if (compare) {
            match = compare(curr->data, data);
        } else {
            match = (curr->data == data);
        }

        if (match) {
            if (curr->prev) {
                curr->prev->next = curr->next;
            } else {
                list->head = curr->next;
            }

            if (curr->next) {
                curr->next->prev = curr->prev;
            } else {
                list->tail = curr->prev;
            }

            if (free_data && curr->data) {
                free_data(curr->data);
            }
            free(curr);
            list->size--;
            return true;
        }
        curr = curr->next;
    }
    return false;
}

void* list_find(const LinkedList *list, const void *key, bool (*compare)(const void *, const void *)) {
    if (!list || !compare) return NULL;
    ListNode *curr = list->head;
    while (curr) {
        if (compare(curr->data, key)) {
            return curr->data;
        }
        curr = curr->next;
    }
    return NULL;
}

size_t list_size(const LinkedList *list) {
    return list ? list->size : 0;
}

bool list_is_empty(const LinkedList *list) {
    return !list || (list->size == 0);
}
