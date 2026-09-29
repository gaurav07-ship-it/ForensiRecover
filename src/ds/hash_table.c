#include "ds/hash_table.h"

/**
 * @file hash_table.c
 * @brief Chained Hash Table Implementation
 * 
 * Provides O(1) average-time lookups for file metadata indexed by filename or file hash.
 */

/* DJB2 String Hash Function */
static unsigned long hash_function(const char *str, size_t capacity) {
    unsigned long hash = 5381;
    int c;
    while ((c = (unsigned char)*str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash % capacity;
}

HashTable* ht_create(size_t capacity) {
    if (capacity == 0) capacity = 64;
    HashTable *ht = (HashTable*)malloc(sizeof(HashTable));
    if (!ht) return NULL;

    ht->capacity = capacity;
    ht->size = 0;
    ht->buckets = (HashEntry**)calloc(capacity, sizeof(HashEntry*));
    if (!ht->buckets) {
        free(ht);
        return NULL;
    }
    return ht;
}

void ht_destroy(HashTable *ht, void (*free_value)(void *)) {
    if (!ht) return;
    for (size_t i = 0; i < ht->capacity; i++) {
        HashEntry *entry = ht->buckets[i];
        while (entry) {
            HashEntry *next = entry->next;
            if (entry->key) free(entry->key);
            if (free_value && entry->value) {
                free_value(entry->value);
            }
            free(entry);
            entry = next;
        }
    }
    free(ht->buckets);
    free(ht);
}

bool ht_insert(HashTable *ht, const char *key, void *value) {
    if (!ht || !key) return false;
    unsigned long index = hash_function(key, ht->capacity);

    HashEntry *entry = ht->buckets[index];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            /* Update existing key */
            entry->value = value;
            return true;
        }
        entry = entry->next;
    }

    /* Insert new node at bucket head (chaining) */
    HashEntry *new_entry = (HashEntry*)malloc(sizeof(HashEntry));
    if (!new_entry) return false;

    new_entry->key = (char*)malloc(strlen(key) + 1);
    if (!new_entry->key) {
        free(new_entry);
        return false;
    }
    strcpy(new_entry->key, key);
    new_entry->value = value;
    new_entry->next = ht->buckets[index];
    ht->buckets[index] = new_entry;
    ht->size++;
    return true;
}

void* ht_get(const HashTable *ht, const char *key) {
    if (!ht || !key) return NULL;
    unsigned long index = hash_function(key, ht->capacity);

    HashEntry *entry = ht->buckets[index];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }
    return NULL;
}

bool ht_remove(HashTable *ht, const char *key, void (*free_value)(void *)) {
    if (!ht || !key) return false;
    unsigned long index = hash_function(key, ht->capacity);

    HashEntry *curr = ht->buckets[index];
    HashEntry *prev = NULL;

    while (curr) {
        if (strcmp(curr->key, key) == 0) {
            if (prev) {
                prev->next = curr->next;
            } else {
                ht->buckets[index] = curr->next;
            }

            if (curr->key) free(curr->key);
            if (free_value && curr->value) {
                free_value(curr->value);
            }
            free(curr);
            ht->size--;
            return true;
        }
        prev = curr;
        curr = curr->next;
    }
    return false;
}

bool ht_contains(const HashTable *ht, const char *key) {
    return ht_get(ht, key) != NULL;
}

size_t ht_size(const HashTable *ht) {
    return ht ? ht->size : 0;
}
