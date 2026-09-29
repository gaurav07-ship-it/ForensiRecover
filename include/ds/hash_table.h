#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "common.h"

/**
 * @brief Hash Table Entry (Chaining for collision resolution)
 */
typedef struct HashEntry {
    char *key;
    void *value;
    struct HashEntry *next;
} HashEntry;

/**
 * @brief Hash Table for File Metadata Lookups
 * Provides O(1) average lookup time by filename or file hash.
 */
typedef struct HashTable {
    HashEntry **buckets;
    size_t capacity;
    size_t size;
} HashTable;

/* Hash Table Operations */
HashTable* ht_create(size_t capacity);
void ht_destroy(HashTable *ht, void (*free_value)(void *));
bool ht_insert(HashTable *ht, const char *key, void *value);
void* ht_get(const HashTable *ht, const char *key);
bool ht_remove(HashTable *ht, const char *key, void (*free_value)(void *));
bool ht_contains(const HashTable *ht, const char *key);
size_t ht_size(const HashTable *ht);

#endif /* HASH_TABLE_H */
