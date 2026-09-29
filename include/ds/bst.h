#ifndef BST_H
#define BST_H

#include "common.h"

/**
 * @brief Binary Search Tree Node for Forensic Evidence Records
 */
typedef struct BSTNode {
    uint32_t key;            /* Evidence ID / Block Offset / Timestamp Key */
    void *data;              /* Pointer to Evidence record */
    struct BSTNode *left;
    struct BSTNode *right;
} BSTNode;

/**
 * @brief Binary Search Tree Container
 * Used to organize forensic evidence records hierarchically and provide O(log N) search.
 */
typedef struct BST {
    BSTNode *root;
    size_t size;
} BST;

/* BST Operations */
BST* bst_create(void);
void bst_destroy(BST *tree, void (*free_data)(void *));
bool bst_insert(BST *tree, uint32_t key, void *data);
void* bst_search(const BST *tree, uint32_t key);
bool bst_delete(BST *tree, uint32_t key, void (*free_data)(void *));
void bst_inorder(const BST *tree, void (*visit)(uint32_t key, void *data, void *context), void *context);
size_t bst_size(const BST *tree);

#endif /* BST_H */
