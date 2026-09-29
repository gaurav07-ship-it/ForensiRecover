#include "forensics/reconstructor.h"
#include "forensics/integrity.h"

/**
 * @file reconstructor.c
 * @brief Graph-Based File Reconstructor and Max-Heap Priority Recovery Engine
 * 
 * Reconstructs fragmented file segments using graph path traversal and
 * ranks recovery candidates in a Max-Heap by calculated forensic confidence.
 */

FileReconstructor* reconstructor_create(void) {
    FileReconstructor *rec = (FileReconstructor*)malloc(sizeof(FileReconstructor));
    if (!rec) return NULL;

    rec->candidate_heap = heap_create(64);
    rec->fragment_graph = graph_create();
    rec->recovered_list = list_create();
    return rec;
}

static void free_candidate(void *data) {
    if (data) {
        RecoveredCandidate *cand = (RecoveredCandidate*)data;
        if (cand->reconstructed_data) {
            free(cand->reconstructed_data);
        }
        free(cand);
    }
}

void reconstructor_destroy(FileReconstructor *rec) {
    if (!rec) return;
    if (rec->candidate_heap) heap_destroy(rec->candidate_heap, NULL); /* Elements freed in list */
    if (rec->fragment_graph) graph_destroy(rec->fragment_graph);
    if (rec->recovered_list) list_destroy(rec->recovered_list, free_candidate);
    free(rec);
}

RecoveredCandidate* reconstructor_carve_file(FileReconstructor *rec, 
                                            VirtualDisk *disk, 
                                            int start_block, 
                                            const char *file_type) {
    if (!rec || !disk || start_block < 0 || start_block >= (int)disk->superblock.total_blocks) {
        return NULL;
    }

    const FileSignature *sig = signatures_find_by_type(file_type);
    if (!sig) {
        uint8_t *first_blk = vdisk_get_block_ptr(disk, start_block);
        sig = signatures_find_by_header(first_blk, VDISK_BLOCK_SIZE);
    }

    RecoveredCandidate *cand = (RecoveredCandidate*)calloc(1, sizeof(RecoveredCandidate));
    if (!cand) return NULL;

    if (sig) {
        snprintf(cand->file_type, sizeof(cand->file_type), "%s", sig->type_name);
    } else {
        strcpy(cand->file_type, "BIN");
    }

    /* Check for Inode Remnant Clues */
    Inode *matched_inode = NULL;
    ListNode *curr = disk->deleted_files->head;
    while (curr) {
        Inode *del_in = (Inode*)curr->data;
        if (del_in->block_count > 0 && del_in->block_indices[0] == start_block) {
            matched_inode = del_in;
            break;
        }
        curr = curr->next;
    }

    /* Build Block Graph for Defragmentation & Path Reconstruction */
    BlockGraph *local_graph = graph_create();
    graph_add_node(local_graph, start_block, true, false);

    int max_blocks = 16;
    if (matched_inode) {
        max_blocks = matched_inode->block_count;
        cand->matched_inode_id = matched_inode->inode_id;
        snprintf(cand->suggested_name, sizeof(cand->suggested_name), "%s", matched_inode->filename);

        /* Add all inode block nodes & edges to graph */
        for (uint32_t b = 0; b < matched_inode->block_count; b++) {
            int blk = matched_inode->block_indices[b];
            bool is_hdr = (b == 0);
            bool is_ftr = (b == matched_inode->block_count - 1);
            graph_add_node(local_graph, blk, is_hdr, is_ftr);

            if (b > 0) {
                int prev_blk = matched_inode->block_indices[b - 1];
                graph_add_edge(local_graph, prev_blk, blk, 0.95);
            }
        }
    } else {
        /* Heuristic: Scan subsequent unallocated blocks to find footer or data clusters */
        snprintf(cand->suggested_name, sizeof(cand->suggested_name), "recovered_blk%d%s", 
                 start_block, sig ? sig->extension : ".dat");

        int search_limit = (start_block + 32 < (int)disk->superblock.total_blocks) ? start_block + 32 : (int)disk->superblock.total_blocks;
        int prev_node = start_block;

        for (int blk = start_block + 1; blk < search_limit; blk++) {
            uint8_t *blk_data = vdisk_get_block_ptr(disk, blk);
            if (!blk_data) break;

            /* Check if block is all zeros */
            bool is_empty = true;
            for (int k = 0; k < 32; k++) {
                if (blk_data[k] != 0) { is_empty = false; break; }
            }
            if (is_empty) break; /* End of contiguous data cluster */

            bool is_ftr = false;
            if (sig && sig->has_footer) {
                size_t ftr_off = 0;
                if (signatures_check_footer(sig, blk_data, VDISK_BLOCK_SIZE, &ftr_off)) {
                    is_ftr = true;
                }
            }

            graph_add_node(local_graph, blk, false, is_ftr);
            graph_add_edge(local_graph, prev_node, blk, 0.85);
            prev_node = blk;

            if (is_ftr) break;
        }
    }

    /* Trace best block path through Graph */
    int path_len = 0;
    graph_find_best_path(local_graph, start_block, max_blocks, cand->block_path, &path_len);
    cand->block_count = path_len;
    graph_destroy(local_graph);

    if (cand->block_count == 0) {
        cand->block_path[0] = start_block;
        cand->block_count = 1;
    }

    /* Assemble payload bytes */
    size_t raw_size = (size_t)cand->block_count * VDISK_BLOCK_SIZE;
    cand->reconstructed_data = (uint8_t*)malloc(raw_size);
    if (!cand->reconstructed_data) {
        free(cand);
        return NULL;
    }

    for (int b = 0; b < cand->block_count; b++) {
        uint8_t *src = vdisk_get_block_ptr(disk, cand->block_path[b]);
        if (src) {
            memcpy(&cand->reconstructed_data[b * VDISK_BLOCK_SIZE], src, VDISK_BLOCK_SIZE);
        }
    }

    /* Refine exact size */
    if (matched_inode) {
        cand->data_size = matched_inode->file_size;
    } else if (sig && sig->has_footer) {
        size_t ftr_off = 0;
        if (signatures_check_footer(sig, cand->reconstructed_data, raw_size, &ftr_off)) {
            cand->data_size = ftr_off;
        } else {
            cand->data_size = raw_size;
        }
    } else {
        cand->data_size = raw_size;
    }

    /* Calculate Cryptographic Hashes */
    cand->calculated_crc32 = integrity_calculate_crc32(cand->reconstructed_data, cand->data_size);
    integrity_calculate_sha256(cand->reconstructed_data, cand->data_size, cand->calculated_sha256);

    /* Integrity Verification */
    if (matched_inode) {
        cand->is_verified = integrity_verify_match(matched_inode->original_sha256, cand->calculated_sha256);
    } else {
        cand->is_verified = false;
    }

    /* Calculate Recovery Confidence */
    cand->confidence = confidence_evaluate(sig, 
                                           cand->reconstructed_data, 
                                           cand->data_size, 
                                           cand->block_path, 
                                           cand->block_count, 
                                           (matched_inode != NULL));

    return cand;
}

size_t reconstructor_run_all(FileReconstructor *rec, 
                             VirtualDisk *disk, 
                             ForensicScanner *scanner, 
                             EvidenceStore *evidence_store) {
    if (!rec || !disk || !scanner) return 0;

    size_t total_recovered = 0;
    uint32_t candidate_id_counter = 1;

    ListNode *curr = scanner->discovered_headers->head;
    while (curr) {
        DiscoveredHeader *hdr = (DiscoveredHeader*)curr->data;
        if (hdr) {
            RecoveredCandidate *cand = reconstructor_carve_file(rec, disk, hdr->block_index, hdr->file_type);
            if (cand) {
                cand->candidate_id = candidate_id_counter++;

                /* Push into Max-Heap prioritized by total recovery confidence */
                heap_insert(rec->candidate_heap, cand->confidence.total_confidence, cand);

                /* Also retain in master recovered list */
                list_push_back(rec->recovered_list, cand);
                total_recovered++;

                /* Register into Evidence BST */
                if (evidence_store) {
                    EvidenceRecord *ev = evidence_record_create(EVIDENCE_RECONSTRUCTED_FILE, hdr->block_index, cand->file_type);
                    if (ev) {
                        snprintf(ev->suggested_name, sizeof(ev->suggested_name), "%s", cand->suggested_name);
                        ev->estimated_size = cand->data_size;
                        ev->block_count = cand->block_count;
                        ev->confidence = cand->confidence;
                        snprintf(ev->calculated_sha256, sizeof(ev->calculated_sha256), "%s", cand->calculated_sha256);
                        ev->calculated_crc32 = cand->calculated_crc32;
                        ev->is_verified = cand->is_verified;

                        snprintf(ev->notes, sizeof(ev->notes), "Graph-Reconstructed %s from %d blocks. Score: %.1f%% (%s)", 
                                 cand->file_type, cand->block_count, cand->confidence.total_confidence, cand->confidence.confidence_grade);

                        evidence_store_insert(evidence_store, ev);
                    }
                }
            }
        }
        curr = curr->next;
    }

    return total_recovered;
}

StatusCode reconstructor_export_file(const RecoveredCandidate *cand, const char *destination_path) {
    if (!cand || !cand->reconstructed_data || cand->data_size == 0 || !destination_path) {
        return STATUS_INVALID_PARAM;
    }

    FILE *fp = fopen(destination_path, "wb");
    if (!fp) {
        return STATUS_ERROR;
    }

    size_t written = fwrite(cand->reconstructed_data, 1, cand->data_size, fp);
    fclose(fp);

    return (written == cand->data_size) ? STATUS_OK : STATUS_ERROR;
}
