#include "ds/bst.h"

/**
 * @file bst.c
 * @brief Binary Search Tree Implementation for Forensic Evidence
 * 
 * Provides O(log N) average-time insertion, lookup, and in-order traversal
 * for organizing forensic evidence artifacts by unique evidence ID / block offsets.
 */

BST* bst_create(void) {
    BST *tree = (BST*)malloc(sizeof(BST));
    if (!tree) return NULL;
    tree->root = NULL;
    tree->size = 0;
    return tree;
}

static void bst_destroy_node(BSTNode *node, void (*free_data)(void *)) {
    if (!node) return;
    bst_destroy_node(node->left, free_data);
    bst_destroy_node(node->right, free_data);
    if (free_data && node->data) {
        free_data(node->data);
    }
    free(node);
}

void bst_destroy(BST *tree, void (*free_data)(void *)) {
    if (!tree) return;
    bst_destroy_node(tree->root, free_data);
    free(tree);
}

static BSTNode* bst_insert_node(BSTNode *node, uint32_t key, void *data, bool *inserted) {
    if (!node) {
        BSTNode *new_node = (BSTNode*)malloc(sizeof(BSTNode));
        if (!new_node) {
            *inserted = false;
            return NULL;
        }
        new_node->key = key;
        new_node->data = data;
        new_node->left = NULL;
        new_node->right = NULL;
        *inserted = true;
        return new_node;
    }

    if (key < node->key) {
        node->left = bst_insert_node(node->left, key, data, inserted);
    } else if (key > node->key) {
        node->right = bst_insert_node(node->right, key, data, inserted);
    } else {
        /* Duplicate key: update data */
        node->data = data;
        *inserted = true;
    }
    return node;
}

bool bst_insert(BST *tree, uint32_t key, void *data) {
    if (!tree) return false;
    bool inserted = false;
    tree->root = bst_insert_node(tree->root, key, data, &inserted);
    if (inserted) {
        tree->size++;
    }
    return inserted;
}

static BSTNode* bst_search_node(BSTNode *node, uint32_t key) {
    if (!node || node->key == key) return node;
    if (key < node->key) {
        return bst_search_node(node->left, key);
    }
    return bst_search_node(node->right, key);
}

void* bst_search(const BST *tree, uint32_t key) {
    if (!tree) return NULL;
    BSTNode *node = bst_search_node(tree->root, key);
    return node ? node->data : NULL;
}

static BSTNode* bst_min_node(BSTNode *node) {
    BSTNode *curr = node;
    while (curr && curr->left) {
        curr = curr->left;
    }
    return curr;
}

static BSTNode* bst_delete_node(BSTNode *node, uint32_t key, bool *deleted, void (*free_data)(void *)) {
    if (!node) return NULL;

    if (key < node->key) {
        node->left = bst_delete_node(node->left, key, deleted, free_data);
    } else if (key > node->key) {
        node->right = bst_delete_node(node->right, key, deleted, free_data);
    } else {
        *deleted = true;
        /* Node with 0 or 1 child */
        if (!node->left) {
            BSTNode *temp = node->right;
            if (free_data && node->data) free_data(node->data);
            free(node);
            return temp;
        } else if (!node->right) {
            BSTNode *temp = node->left;
            if (free_data && node->data) free_data(node->data);
            free(node);
            return temp;
        }

        /* Node with 2 children: get in-order successor */
        BSTNode *temp = bst_min_node(node->right);
        node->key = temp->key;
        node->data = temp->data;
        node->right = bst_delete_node(node->right, temp->key, deleted, NULL);
    }
    return node;
}

bool bst_delete(BST *tree, uint32_t key, void (*free_data)(void *)) {
    if (!tree) return false;
    bool deleted = false;
    tree->root = bst_delete_node(tree->root, key, &deleted, free_data);
    if (deleted) {
        tree->size--;
    }
    return deleted;
}

static void bst_inorder_node(BSTNode *node, void (*visit)(uint32_t key, void *data, void *context), void *context) {
    if (!node) return;
    bst_inorder_node(node->left, visit, context);
    if (visit) {
        visit(node->key, node->data, context);
    }
    bst_inorder_node(node->right, visit, context);
}

void bst_inorder(const BST *tree, void (*visit)(uint32_t key, void *data, void *context), void *context) {
    if (!tree) return;
    bst_inorder_node(tree->root, visit, context);
}

size_t bst_size(const BST *tree) {
    return tree ? tree->size : 0;
}
