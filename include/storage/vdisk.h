#ifndef VDISK_H
#define VDISK_H

#include "common.h"
#include "inode.h"
#include "ds/array_bitmap.h"
#include "ds/linked_list.h"
#include "ds/hash_table.h"
#include "ds/stack.h"

/**
 * @brief Superblock containing Virtual Disk metadata
 */
typedef struct {
    uint32_t magic;                      /* VDISK_MAGIC identifier */
    uint32_t total_blocks;               /* Total data blocks */
    uint32_t block_size;                 /* Size of block in bytes (512) */
    uint32_t inode_count;                /* Total inodes */
    uint32_t free_blocks;                /* Number of free data blocks */
    uint32_t free_inodes;                /* Number of free inodes */
} Superblock;

/**
 * @brief Virtual Storage Device
 * Represents the entire virtual hard drive in memory.
 */
typedef struct {
    Superblock superblock;
    uint8_t *raw_storage;                /* Contiguous raw storage byte array */
    BlockBitmap *block_bitmap;           /* Bitmap tracking block allocations (Array DS) */
    Inode inode_table[VDISK_MAX_FILES];  /* Inode Table (Array DS) */
    LinkedList *active_files;            /* Active file records (Doubly Linked List DS) */
    LinkedList *deleted_files;           /* Deleted file records (Doubly Linked List DS) */
    HashTable *metadata_index;           /* Hash Table for fast filename -> Inode* lookup (Hash Table DS) */
    Stack *operation_history;            /* LIFO History of disk operations / undo logs (Stack DS) */
} VirtualDisk;

/* Operation Log Entry stored in Stack */
typedef enum {
    OP_CREATE_FILE,
    OP_DELETE_FILE,
    OP_FRAGMENT_FILE,
    OP_OVERWRITE_BLOCK
} OperationType;

typedef struct {
    OperationType type;
    char filename[VDISK_MAX_FILENAME];
    uint32_t inode_id;
    time_t timestamp;
    char details[128];
} DiskOperationRecord;

/* Virtual Disk Operations */
VirtualDisk* vdisk_init(void);
void vdisk_destroy(VirtualDisk *disk);
void vdisk_format(VirtualDisk *disk);

/* File Management */
StatusCode vdisk_create_file(VirtualDisk *disk, const char *filename, const uint8_t *data, size_t size, const char *file_type);
StatusCode vdisk_delete_file(VirtualDisk *disk, const char *filename);
Inode* vdisk_get_file_by_name(VirtualDisk *disk, const char *filename);
Inode* vdisk_get_file_by_inode(VirtualDisk *disk, uint32_t inode_id);

/* Raw Block Access */
uint8_t* vdisk_get_block_ptr(VirtualDisk *disk, int block_index);
StatusCode vdisk_read_block(const VirtualDisk *disk, int block_index, uint8_t *buffer);
StatusCode vdisk_write_block(VirtualDisk *disk, int block_index, const uint8_t *buffer);

/* Status & Visualization */
void vdisk_print_stats(const VirtualDisk *disk);
void vdisk_dump_block_map(const VirtualDisk *disk, size_t max_blocks_to_show);

#endif /* VDISK_H */
