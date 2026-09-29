#ifndef INODE_H
#define INODE_H

#include "common.h"

#define MAX_BLOCKS_PER_FILE 128

typedef enum {
    FILE_STATUS_FREE = 0,
    FILE_STATUS_ACTIVE = 1,
    FILE_STATUS_DELETED = 2,
    FILE_STATUS_FRAGMENTED = 3,
    FILE_STATUS_CORRUPTED = 4
} FileStatus;

/**
 * @brief Inode / File Metadata Record
 * Represents file system metadata stored in the virtual disk inode table.
 */
typedef struct {
    uint32_t inode_id;                   /* Unique Inode identifier */
    char filename[VDISK_MAX_FILENAME];   /* File name */
    size_t file_size;                    /* File size in bytes */
    FileStatus status;                   /* Active, Deleted, Fragmented, etc. */
    time_t created_time;                 /* Creation timestamp */
    time_t deleted_time;                 /* Deletion timestamp (if deleted) */
    uint32_t block_count;                /* Number of blocks used */
    int block_indices[MAX_BLOCKS_PER_FILE]; /* Array of allocated disk block indices */
    uint32_t original_crc32;             /* CRC32 checksum of original file */
    char original_sha256[65];            /* SHA-256 hash string (hex) */
    char file_type[16];                  /* e.g., "PDF", "PNG", "JPEG", "TXT", "ZIP" */
} Inode;

#endif /* INODE_H */
