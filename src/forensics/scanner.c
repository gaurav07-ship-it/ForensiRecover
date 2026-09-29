#include "forensics/scanner.h"
#include "forensics/signatures.h"
#include "forensics/confidence.h"

/**
 * @file scanner.c
 * @brief Queue-Driven Forensic Deep Disk Scanner
 * 
 * Uses a FIFO Queue to schedule chunked scanning tasks across the virtual storage device.
 * Detects orphan signatures, deleted file remnants, and unallocated block headers.
 */

ForensicScanner* scanner_create(void) {
    ForensicScanner *scanner = (ForensicScanner*)malloc(sizeof(ForensicScanner));
    if (!scanner) return NULL;

    scanner->task_queue = queue_create();
    scanner->discovered_headers = list_create();
    return scanner;
}

static void free_task(void *data) {
    if (data) free(data);
}

static void free_header(void *data) {
    if (data) free(data);
}

void scanner_destroy(ForensicScanner *scanner) {
    if (!scanner) return;
    if (scanner->task_queue) queue_destroy(scanner->task_queue, free_task);
    if (scanner->discovered_headers) list_destroy(scanner->discovered_headers, free_header);
    free(scanner);
}

void scanner_schedule_task(ForensicScanner *scanner, int start_block, int end_block, bool unallocated_only) {
    if (!scanner) return;
    ScanTask *task = (ScanTask*)malloc(sizeof(ScanTask));
    if (!task) return;

    task->start_block = start_block;
    task->end_block = end_block;
    task->scan_unallocated_only = unallocated_only;
    task->deep_inspection = true;

    queue_enqueue(scanner->task_queue, task);
}

size_t scanner_execute_scan(ForensicScanner *scanner, VirtualDisk *disk, EvidenceStore *evidence_store) {
    if (!scanner || !disk) return 0;

    size_t headers_found = 0;

    printf(COLOR_CYAN "  [>] Executing Queue-Scheduled Forensic Scan across %zu tasks...\n" COLOR_RESET, 
           queue_size(scanner->task_queue));

    while (!queue_is_empty(scanner->task_queue)) {
        ScanTask *task = (ScanTask*)queue_dequeue(scanner->task_queue);
        if (!task) continue;

        for (int blk = task->start_block; blk <= task->end_block && blk < (int)disk->superblock.total_blocks; blk++) {
            bool is_allocated = bitmap_test(disk->block_bitmap, blk);
            if (task->scan_unallocated_only && is_allocated) {
                continue; /* Skip active allocated blocks */
            }

            uint8_t *blk_data = vdisk_get_block_ptr(disk, blk);
            if (!blk_data) continue;

            const FileSignature *sig = signatures_find_by_header(blk_data, VDISK_BLOCK_SIZE);
            if (sig) {
                headers_found++;

                DiscoveredHeader *header = (DiscoveredHeader*)malloc(sizeof(DiscoveredHeader));
                if (header) {
                    header->block_index = blk;
                    snprintf(header->file_type, sizeof(header->file_type), "%s", sig->type_name);
                    header->header_offset_in_block = 0;
                    header->has_matching_inode = false;
                    header->matched_inode_id = 0;

                    /* Check if there is an Inode remnant correlation in deleted_files */
                    ListNode *curr = disk->deleted_files->head;
                    while (curr) {
                        Inode *del_in = (Inode*)curr->data;
                        if (del_in->block_count > 0 && del_in->block_indices[0] == blk) {
                            header->has_matching_inode = true;
                            header->matched_inode_id = del_in->inode_id;
                            break;
                        }
                        curr = curr->next;
                    }

                    list_push_back(scanner->discovered_headers, header);

                    /* Register into Evidence BST */
                    if (evidence_store) {
                        EvidenceRecord *ev = evidence_record_create(EVIDENCE_CARVED_HEADER, blk, sig->type_name);
                        if (ev) {
                            if (header->has_matching_inode) {
                                Inode *matched = vdisk_get_file_by_inode(disk, header->matched_inode_id);
                                if (matched) {
                                    snprintf(ev->suggested_name, sizeof(ev->suggested_name), "%s", matched->filename);
                                    ev->estimated_size = matched->file_size;
                                    ev->block_count = matched->block_count;
                                }
                            } else {
                                snprintf(ev->suggested_name, sizeof(ev->suggested_name), "carved_blk%d%s", blk, sig->extension);
                                ev->estimated_size = VDISK_BLOCK_SIZE;
                                ev->block_count = 1;
                            }

                            int dummy_path[1] = { blk };
                            ev->confidence = confidence_evaluate(sig, blk_data, VDISK_BLOCK_SIZE, dummy_path, 1, header->has_matching_inode);
                            snprintf(ev->notes, sizeof(ev->notes), "Discovered %s signature header at Block #%d", sig->type_name, blk);

                            evidence_store_insert(evidence_store, ev);
                        }
                    }
                }
            }
        }
        free(task);
    }

    return headers_found;
}
