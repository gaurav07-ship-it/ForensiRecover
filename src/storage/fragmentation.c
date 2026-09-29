#include "storage/fragmentation.h"

/**
 * @file fragmentation.c
 * @brief Disk Fragmentation Simulation Engine
 * 
 * Simulates real-world file fragmentation by scattering file blocks across
 * non-contiguous clusters on the virtual storage device.
 */

StatusCode vdisk_fragment_file(VirtualDisk *disk, const char *filename, FragStrategy strategy) {
    if (!disk || !filename) return STATUS_INVALID_PARAM;

    Inode *inode = vdisk_get_file_by_name(disk, filename);
    if (!inode) {
        /* Check deleted files list if not active */
        ListNode *curr = disk->deleted_files->head;
        while (curr) {
            Inode *del_in = (Inode*)curr->data;
            if (strcmp(del_in->filename, filename) == 0) {
                inode = del_in;
                break;
            }
            curr = curr->next;
        }
    }

    if (!inode || inode->block_count <= 1) {
        return STATUS_OK; /* Single block file cannot be fragmented */
    }

    int old_blocks[MAX_BLOCKS_PER_FILE];
    uint8_t *temp_data[MAX_BLOCKS_PER_FILE];
    uint32_t count = inode->block_count;

    for (uint32_t i = 0; i < count; i++) {
        old_blocks[i] = inode->block_indices[i];
        temp_data[i] = (uint8_t*)malloc(VDISK_BLOCK_SIZE);
        if (!temp_data[i]) {
            for (uint32_t j = 0; j < i; j++) free(temp_data[j]);
            return STATUS_ERROR;
        }
        memcpy(temp_data[i], vdisk_get_block_ptr(disk, old_blocks[i]), VDISK_BLOCK_SIZE);
        /* Clear old block in raw storage & bitmap */
        memset(vdisk_get_block_ptr(disk, old_blocks[i]), 0, VDISK_BLOCK_SIZE);
        bitmap_clear(disk->block_bitmap, old_blocks[i]);
    }

    int new_blocks[MAX_BLOCKS_PER_FILE];

    if (strategy == FRAG_STRATEGY_SCATTER) {
        /* Scatter blocks with random stepping gaps */
        int current_search = 10 + (rand() % 50);
        for (uint32_t i = 0; i < count; i++) {
            int found = -1;
            for (int attempt = 0; attempt < 50; attempt++) {
                int cand = (current_search + (rand() % 80) + 15) % VDISK_TOTAL_BLOCKS;
                if (!bitmap_test(disk->block_bitmap, cand)) {
                    found = cand;
                    break;
                }
            }
            if (found == -1) {
                found = bitmap_find_first_free(disk->block_bitmap);
            }
            new_blocks[i] = found;
            bitmap_set(disk->block_bitmap, found);
            current_search = found;
        }
    } else if (strategy == FRAG_STRATEGY_SPLIT_HALF) {
        /* Half placed in lower blocks, half in higher blocks */
        uint32_t half = count / 2;
        int low_start = bitmap_find_first_free(disk->block_bitmap);
        for (uint32_t i = 0; i < half; i++) {
            new_blocks[i] = low_start + i;
            bitmap_set(disk->block_bitmap, new_blocks[i]);
        }
        int high_start = bitmap_find_next_free(disk->block_bitmap, low_start + 100);
        if (high_start == -1) high_start = low_start + half;
        for (uint32_t i = half; i < count; i++) {
            new_blocks[i] = high_start + (i - half);
            bitmap_set(disk->block_bitmap, new_blocks[i]);
        }
    } else {
        /* Default scatter fallback */
        for (uint32_t i = 0; i < count; i++) {
            int blk = bitmap_find_first_free(disk->block_bitmap);
            new_blocks[i] = blk;
            bitmap_set(disk->block_bitmap, blk);
        }
    }

    /* Write data back to new scattered blocks */
    for (uint32_t i = 0; i < count; i++) {
        inode->block_indices[i] = new_blocks[i];
        memcpy(vdisk_get_block_ptr(disk, new_blocks[i]), temp_data[i], VDISK_BLOCK_SIZE);
        free(temp_data[i]);
    }

    if (inode->status == FILE_STATUS_ACTIVE) {
        inode->status = FILE_STATUS_FRAGMENTED;
    }

    /* If file was deleted, re-clear bitmap to maintain deleted state simulation */
    if (inode->status == FILE_STATUS_DELETED) {
        for (uint32_t i = 0; i < count; i++) {
            bitmap_clear(disk->block_bitmap, new_blocks[i]);
        }
    }

    /* Record in Stack */
    DiskOperationRecord *op = (DiskOperationRecord*)malloc(sizeof(DiskOperationRecord));
    if (op) {
        op->type = OP_FRAGMENT_FILE;
        strncpy(op->filename, filename, VDISK_MAX_FILENAME - 1);
        op->inode_id = inode->inode_id;
        op->timestamp = time(NULL);
        snprintf(op->details, sizeof(op->details), "Fragmented %s across %u scattered blocks", filename, count);
        stack_push(disk->operation_history, op);
    }

    return STATUS_OK;
}

StatusCode vdisk_simulate_heavy_fragmentation(VirtualDisk *disk) {
    if (!disk) return STATUS_INVALID_PARAM;

    /* Fragment all active files */
    ListNode *curr = disk->active_files->head;
    while (curr) {
        Inode *in = (Inode*)curr->data;
        if (in->block_count > 1) {
            vdisk_fragment_file(disk, in->filename, FRAG_STRATEGY_SCATTER);
        }
        curr = curr->next;
    }

    /* Fragment all deleted file remnants */
    curr = disk->deleted_files->head;
    while (curr) {
        Inode *in = (Inode*)curr->data;
        if (in->block_count > 1) {
            vdisk_fragment_file(disk, in->filename, FRAG_STRATEGY_SCATTER);
        }
        curr = curr->next;
    }

    return STATUS_OK;
}
