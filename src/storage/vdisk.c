#include "storage/vdisk.h"
#include "forensics/integrity.h"

/**
 * @file vdisk.c
 * @brief Virtual Storage Device Implementation
 * 
 * Simulates low-level file storage, inode metadata tables, bitmap block allocation,
 * and realistic file deletion (unlinking metadata while preserving raw remnant bytes).
 */

VirtualDisk* vdisk_init(void) {
    VirtualDisk *disk = (VirtualDisk*)malloc(sizeof(VirtualDisk));
    if (!disk) return NULL;

    disk->superblock.magic = VDISK_MAGIC;
    disk->superblock.total_blocks = VDISK_TOTAL_BLOCKS;
    disk->superblock.block_size = VDISK_BLOCK_SIZE;
    disk->superblock.inode_count = VDISK_MAX_FILES;
    disk->superblock.free_blocks = VDISK_TOTAL_BLOCKS;
    disk->superblock.free_inodes = VDISK_MAX_FILES;

    size_t total_bytes = (size_t)VDISK_TOTAL_BLOCKS * VDISK_BLOCK_SIZE;
    disk->raw_storage = (uint8_t*)calloc(total_bytes, sizeof(uint8_t));
    if (!disk->raw_storage) {
        free(disk);
        return NULL;
    }

    disk->block_bitmap = bitmap_create(VDISK_TOTAL_BLOCKS);
    disk->active_files = list_create();
    disk->deleted_files = list_create();
    disk->metadata_index = ht_create(VDISK_MAX_FILES);
    disk->operation_history = stack_create();

    /* Clear Inode table */
    for (int i = 0; i < VDISK_MAX_FILES; i++) {
        memset(&disk->inode_table[i], 0, sizeof(Inode));
        disk->inode_table[i].inode_id = (uint32_t)(i + 1);
        disk->inode_table[i].status = FILE_STATUS_FREE;
    }

    return disk;
}

void vdisk_destroy(VirtualDisk *disk) {
    if (!disk) return;

    if (disk->raw_storage) free(disk->raw_storage);
    if (disk->block_bitmap) bitmap_destroy(disk->block_bitmap);
    if (disk->active_files) list_destroy(disk->active_files, NULL);
    if (disk->deleted_files) list_destroy(disk->deleted_files, NULL);
    if (disk->metadata_index) ht_destroy(disk->metadata_index, NULL);
    if (disk->operation_history) stack_destroy(disk->operation_history, free);

    free(disk);
}

void vdisk_format(VirtualDisk *disk) {
    if (!disk) return;

    size_t total_bytes = (size_t)VDISK_TOTAL_BLOCKS * VDISK_BLOCK_SIZE;
    memset(disk->raw_storage, 0, total_bytes);

    if (disk->block_bitmap) {
        bitmap_destroy(disk->block_bitmap);
        disk->block_bitmap = bitmap_create(VDISK_TOTAL_BLOCKS);
    }
    if (disk->active_files) {
        list_destroy(disk->active_files, NULL);
        disk->active_files = list_create();
    }
    if (disk->deleted_files) {
        list_destroy(disk->deleted_files, NULL);
        disk->deleted_files = list_create();
    }
    if (disk->metadata_index) {
        ht_destroy(disk->metadata_index, NULL);
        disk->metadata_index = ht_create(VDISK_MAX_FILES);
    }
    if (disk->operation_history) {
        stack_destroy(disk->operation_history, free);
        disk->operation_history = stack_create();
    }

    for (int i = 0; i < VDISK_MAX_FILES; i++) {
        memset(&disk->inode_table[i], 0, sizeof(Inode));
        disk->inode_table[i].inode_id = (uint32_t)(i + 1);
        disk->inode_table[i].status = FILE_STATUS_FREE;
    }

    disk->superblock.free_blocks = VDISK_TOTAL_BLOCKS;
    disk->superblock.free_inodes = VDISK_MAX_FILES;
}

static int find_free_inode(VirtualDisk *disk) {
    for (int i = 0; i < VDISK_MAX_FILES; i++) {
        if (disk->inode_table[i].status == FILE_STATUS_FREE) {
            return i;
        }
    }
    return -1;
}

StatusCode vdisk_create_file(VirtualDisk *disk, const char *filename, const uint8_t *data, size_t size, const char *file_type) {
    if (!disk || !filename || !data || size == 0) return STATUS_INVALID_PARAM;

    if (ht_contains(disk->metadata_index, filename)) {
        return STATUS_ERROR; /* File already exists */
    }

    size_t needed_blocks = (size + VDISK_BLOCK_SIZE - 1) / VDISK_BLOCK_SIZE;
    if (needed_blocks > MAX_BLOCKS_PER_FILE) return STATUS_NO_SPACE;
    if (bitmap_count_free(disk->block_bitmap) < needed_blocks) return STATUS_NO_SPACE;

    int inode_idx = find_free_inode(disk);
    if (inode_idx == -1) return STATUS_NO_SPACE;

    Inode *inode = &disk->inode_table[inode_idx];
    strncpy(inode->filename, filename, VDISK_MAX_FILENAME - 1);
    inode->file_size = size;
    inode->status = FILE_STATUS_ACTIVE;
    inode->created_time = time(NULL);
    inode->deleted_time = 0;
    inode->block_count = (uint32_t)needed_blocks;
    if (file_type) {
        strncpy(inode->file_type, file_type, 15);
    } else {
        strcpy(inode->file_type, "BIN");
    }

    /* Compute Cryptographic and Integrity Hashes */
    inode->original_crc32 = integrity_calculate_crc32(data, size);
    integrity_calculate_sha256(data, size, inode->original_sha256);

    /* Allocate blocks and write payload into raw storage */
    size_t bytes_remaining = size;
    const uint8_t *src_ptr = data;

    for (size_t b = 0; b < needed_blocks; b++) {
        int free_block = bitmap_find_first_free(disk->block_bitmap);
        if (free_block == -1) return STATUS_NO_SPACE;

        bitmap_set(disk->block_bitmap, free_block);
        inode->block_indices[b] = free_block;

        uint8_t *dst_block = vdisk_get_block_ptr(disk, free_block);
        memset(dst_block, 0, VDISK_BLOCK_SIZE);

        size_t write_len = (bytes_remaining > VDISK_BLOCK_SIZE) ? VDISK_BLOCK_SIZE : bytes_remaining;
        memcpy(dst_block, src_ptr, write_len);

        src_ptr += write_len;
        bytes_remaining -= write_len;
    }

    /* Update Fast Lookup Hash Table */
    ht_insert(disk->metadata_index, filename, inode);

    /* Insert into Active Files Linked List */
    list_push_back(disk->active_files, inode);

    /* Update Superblock */
    disk->superblock.free_blocks -= needed_blocks;
    disk->superblock.free_inodes--;

    /* Record in Operation Stack */
    DiskOperationRecord *op = (DiskOperationRecord*)malloc(sizeof(DiskOperationRecord));
    if (op) {
        op->type = OP_CREATE_FILE;
        strncpy(op->filename, filename, VDISK_MAX_FILENAME - 1);
        op->inode_id = inode->inode_id;
        op->timestamp = inode->created_time;
        snprintf(op->details, sizeof(op->details), "Created %s (%zu bytes, %u blocks)", filename, size, inode->block_count);
        stack_push(disk->operation_history, op);
    }

    return STATUS_OK;
}

StatusCode vdisk_delete_file(VirtualDisk *disk, const char *filename) {
    if (!disk || !filename) return STATUS_INVALID_PARAM;

    Inode *inode = (Inode*)ht_get(disk->metadata_index, filename);
    if (!inode || inode->status != FILE_STATUS_ACTIVE) {
        return STATUS_NOT_FOUND;
    }

    /* 
     * FORENSIC SIMULATION:
     * In real-world filesystems (FAT, NTFS, ext4), deleting a file:
     * 1. Removes the directory pointer / hash table entry.
     * 2. Marks the Inode / MFT record as deleted/unallocated.
     * 3. Marks block allocation bits in the bitmap as free.
     * 4. BUT LEAVES the actual bytes intact inside raw block storage!
     */

    /* Step 1: Remove from metadata hash table */
    ht_remove(disk->metadata_index, filename, NULL);

    /* Step 2: Remove from active files list */
    list_remove(disk->active_files, inode, NULL, NULL);

    /* Step 3: Mark Inode status as DELETED */
    inode->status = FILE_STATUS_DELETED;
    inode->deleted_time = time(NULL);

    /* Step 4: Release bits in block bitmap (simulating free space for OS) */
    for (uint32_t b = 0; b < inode->block_count; b++) {
        int blk = inode->block_indices[b];
        if (blk >= 0 && blk < VDISK_TOTAL_BLOCKS) {
            bitmap_clear(disk->block_bitmap, blk);
        }
    }

    /* Step 5: Add to Deleted Files Remnant List */
    list_push_back(disk->deleted_files, inode);

    /* Update Superblock */
    disk->superblock.free_blocks += inode->block_count;
    disk->superblock.free_inodes++;

    /* Record in Operation Stack */
    DiskOperationRecord *op = (DiskOperationRecord*)malloc(sizeof(DiskOperationRecord));
    if (op) {
        op->type = OP_DELETE_FILE;
        strncpy(op->filename, filename, VDISK_MAX_FILENAME - 1);
        op->inode_id = inode->inode_id;
        op->timestamp = inode->deleted_time;
        snprintf(op->details, sizeof(op->details), "Deleted %s (raw data remnants preserved in blocks)", filename);
        stack_push(disk->operation_history, op);
    }

    return STATUS_OK;
}

Inode* vdisk_get_file_by_name(VirtualDisk *disk, const char *filename) {
    if (!disk || !filename) return NULL;
    return (Inode*)ht_get(disk->metadata_index, filename);
}

Inode* vdisk_get_file_by_inode(VirtualDisk *disk, uint32_t inode_id) {
    if (!disk || inode_id == 0 || inode_id > VDISK_MAX_FILES) return NULL;
    return &disk->inode_table[inode_id - 1];
}

uint8_t* vdisk_get_block_ptr(VirtualDisk *disk, int block_index) {
    if (!disk || block_index < 0 || block_index >= VDISK_TOTAL_BLOCKS) return NULL;
    return &disk->raw_storage[block_index * VDISK_BLOCK_SIZE];
}

StatusCode vdisk_read_block(const VirtualDisk *disk, int block_index, uint8_t *buffer) {
    if (!disk || !buffer || block_index < 0 || block_index >= VDISK_TOTAL_BLOCKS) {
        return STATUS_INVALID_PARAM;
    }
    memcpy(buffer, &disk->raw_storage[block_index * VDISK_BLOCK_SIZE], VDISK_BLOCK_SIZE);
    return STATUS_OK;
}

StatusCode vdisk_write_block(VirtualDisk *disk, int block_index, const uint8_t *buffer) {
    if (!disk || !buffer || block_index < 0 || block_index >= VDISK_TOTAL_BLOCKS) {
        return STATUS_INVALID_PARAM;
    }
    memcpy(&disk->raw_storage[block_index * VDISK_BLOCK_SIZE], buffer, VDISK_BLOCK_SIZE);
    bitmap_set(disk->block_bitmap, block_index);
    return STATUS_OK;
}

void vdisk_print_stats(const VirtualDisk *disk) {
    if (!disk) return;
    printf("\n" COLOR_CYAN COLOR_BOLD "=== VIRTUAL STORAGE DEVICE STATUS ===" COLOR_RESET "\n");
    printf("  Magic Identifier   : 0x%08X (\"FORE\")\n", disk->superblock.magic);
    printf("  Total Capacity     : %u Blocks (%u KB / %.2f MB)\n", 
           disk->superblock.total_blocks, 
           (disk->superblock.total_blocks * VDISK_BLOCK_SIZE) / 1024,
           (double)(disk->superblock.total_blocks * VDISK_BLOCK_SIZE) / (1024 * 1024));
    printf("  Block Size         : %u Bytes\n", disk->superblock.block_size);
    printf("  Free Data Blocks   : %u / %u (%.1f%% Free)\n", 
           disk->superblock.free_blocks, disk->superblock.total_blocks,
           ((double)disk->superblock.free_blocks / disk->superblock.total_blocks) * 100.0);
    printf("  Active Files       : %zu\n", list_size(disk->active_files));
    printf("  Deleted Remnants   : %zu\n", list_size(disk->deleted_files));
    printf("  Operation Stack    : %zu records logged\n", stack_size(disk->operation_history));
    printf(COLOR_CYAN "======================================" COLOR_RESET "\n\n");
}

void vdisk_dump_block_map(const VirtualDisk *disk, size_t max_blocks_to_show) {
    if (!disk) return;
    if (max_blocks_to_show == 0 || max_blocks_to_show > VDISK_TOTAL_BLOCKS) {
        max_blocks_to_show = 256; /* Default grid preview */
    }

    printf(COLOR_BOLD "--- Visual Storage Block Matrix (First %zu Blocks) ---" COLOR_RESET "\n", max_blocks_to_show);
    printf(COLOR_GREEN "[#]" COLOR_RESET " Allocated | " 
           COLOR_DIM "[.]" COLOR_RESET " Free | " 
           COLOR_RED "[D]" COLOR_RESET " Deleted Data Remnant\n\n");

    for (size_t i = 0; i < max_blocks_to_show; i++) {
        if (i % 32 == 0) {
            printf(COLOR_DIM "Blk %04zu: " COLOR_RESET, i);
        }

        bool is_alloc = bitmap_test(disk->block_bitmap, i);
        if (is_alloc) {
            printf(COLOR_GREEN "[#]" COLOR_RESET);
        } else {
            /* Check if non-zero remnant data exists */
            const uint8_t *blk = &disk->raw_storage[i * VDISK_BLOCK_SIZE];
            bool has_remnant = false;
            for (int k = 0; k < VDISK_BLOCK_SIZE; k++) {
                if (blk[k] != 0) {
                    has_remnant = true;
                    break;
                }
            }
            if (has_remnant) {
                printf(COLOR_RED "[D]" COLOR_RESET);
            } else {
                printf(COLOR_DIM "[.]" COLOR_RESET);
            }
        }

        if ((i + 1) % 32 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}
