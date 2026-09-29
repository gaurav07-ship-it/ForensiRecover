#include "forensics/report.h"

/**
 * @file report.c
 * @brief Forensic Case Investigation Report Generator
 * 
 * Compiles detected artifacts, reconstructed files, cryptographic integrity checks,
 * and data structure metrics into a formal digital forensics investigation report.
 */

void report_print_terminal_summary(const ForensicReport *rep, const EvidenceStore *store, const FileReconstructor *rec) {
    if (!rep) return;

    char time_buf[64];
    struct tm *tm_info = localtime(&rep->generated_time);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S UTC", tm_info);

    printf("\n" COLOR_GREEN COLOR_BOLD "================================================================================" COLOR_RESET "\n");
    printf(COLOR_GREEN COLOR_BOLD "           FORENSIRECOVER - DIGITAL FORENSIC INVESTIGATION REPORT              " COLOR_RESET "\n");
    printf(COLOR_GREEN COLOR_BOLD "================================================================================" COLOR_RESET "\n");
    printf("  Case ID           : %s\n", rep->case_id);
    printf("  Lead Investigator : %s\n", rep->investigator_name);
    printf("  Generated At      : %s\n", time_buf);
    printf("  Blocks Scanned    : %zu Blocks (%zu KB)\n", rep->total_scanned_blocks, (rep->total_scanned_blocks * VDISK_BLOCK_SIZE) / 1024);
    printf("  Deleted Remnants  : %zu files detected\n", rep->detected_deleted_files);
    printf("  Files Recovered   : %zu files reconstructed\n", rep->successfully_recovered);
    printf("  Verified Hashes   : %zu / %zu (%.1f%%)\n", 
           rep->verified_files, 
           rep->successfully_recovered, 
           rep->successfully_recovered > 0 ? ((double)rep->verified_files / rep->successfully_recovered) * 100.0 : 0.0);
    printf("  Average Confidence: %.2f%%\n", rep->average_confidence);
    printf("--------------------------------------------------------------------------------\n");

    /* Print Priority Queue (Max-Heap) Ranked Recovered Candidates */
    if (rec && rec->recovered_list && list_size(rec->recovered_list) > 0) {
        printf(COLOR_BOLD "  [+] Recovered Candidate Files (Ranked by Recovery Confidence Score):" COLOR_RESET "\n\n");
        printf("  %-4s | %-18s | %-6s | %-8s | %-14s | %-12s\n", 
               "ID", "Suggested Name", "Type", "Size (B)", "Confidence", "Integrity");
        printf("  -----+--------------------+--------+----------+----------------+-------------\n");

        ListNode *curr = rec->recovered_list->head;
        while (curr) {
            RecoveredCandidate *cand = (RecoveredCandidate*)curr->data;
            printf("  %-4u | %-18s | %-6s | %-8zu | %5.1f%% (%-4s) | %s\n",
                   cand->candidate_id,
                   cand->suggested_name,
                   cand->file_type,
                   cand->data_size,
                   cand->confidence.total_confidence,
                   (cand->confidence.total_confidence >= 90.0) ? "HIGH" : (cand->confidence.total_confidence >= 60.0 ? "MED" : "LOW"),
                   cand->is_verified ? COLOR_GREEN "VERIFIED MATCH" COLOR_RESET : COLOR_YELLOW "UNVERIFIED" COLOR_RESET);
            curr = curr->next;
        }
        printf("\n");
    }

    /* Print Evidence BST Summary */
    if (store) {
        evidence_store_print_all(store);
    }
}

static void report_file_evidence_visitor(uint32_t key, void *data, void *context) {
    (void)key;
    FILE *fp = (FILE*)context;
    EvidenceRecord *rec = (EvidenceRecord*)data;
    if (!fp || !rec) return;

    const char *type_str = "UNKNOWN";
    switch (rec->type) {
        case EVIDENCE_DELETED_INODE: type_str = "DELETED_INODE"; break;
        case EVIDENCE_CARVED_HEADER: type_str = "CARVED_HEADER"; break;
        case EVIDENCE_RECONSTRUCTED_FILE: type_str = "RECONSTRUCTED_FILE"; break;
        case EVIDENCE_SUSPICIOUS_BLOCK: type_str = "SUSPICIOUS_BLOCK"; break;
    }

    fprintf(fp, "| #%u | %s | %d | %d | %s | %s | %s |\n",
            rec->evidence_id,
            type_str,
            rec->primary_block,
            rec->block_count,
            rec->file_type,
            rec->suggested_name,
            rec->is_verified ? "PASSED" : "UNVERIFIED");
}

StatusCode report_export_to_file(const ForensicReport *rep, const EvidenceStore *store, const FileReconstructor *rec, const char *filepath) {
    if (!rep || !filepath) return STATUS_INVALID_PARAM;

    FILE *fp = fopen(filepath, "w");
    if (!fp) return STATUS_ERROR;

    char time_buf[64];
    struct tm *tm_info = localtime(&rep->generated_time);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S UTC", tm_info);

    fprintf(fp, "# DIGITAL FORENSICS INVESTIGATION REPORT\n");
    fprintf(fp, "**System:** ForensiRecover v%s\n", FORENSI_VERSION);
    fprintf(fp, "**Case ID:** %s\n", rep->case_id);
    fprintf(fp, "**Lead Investigator:** %s\n", rep->investigator_name);
    fprintf(fp, "**Date:** %s\n\n", time_buf);

    fprintf(fp, "## 1. Executive Summary\n\n");
    fprintf(fp, "| Metric | Value |\n");
    fprintf(fp, "| :--- | :--- |\n");
    fprintf(fp, "| Total Blocks Scanned | %zu blocks (%zu KB) |\n", rep->total_scanned_blocks, (rep->total_scanned_blocks * VDISK_BLOCK_SIZE) / 1024);
    fprintf(fp, "| Detected Deleted Signatures | %zu |\n", rep->detected_deleted_files);
    fprintf(fp, "| Successfully Recovered Files | %zu |\n", rep->successfully_recovered);
    fprintf(fp, "| Cryptographically Verified Files | %zu |\n", rep->verified_files);
    fprintf(fp, "| Average Recovery Confidence | %.2f%% |\n\n", rep->average_confidence);

    fprintf(fp, "## 2. Recovered Files & Cryptographic Verification\n\n");
    fprintf(fp, "| ID | Filename | Type | Size (Bytes) | Confidence | Verification Status | SHA-256 Checksum |\n");
    fprintf(fp, "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

    if (rec && rec->recovered_list) {
        ListNode *curr = rec->recovered_list->head;
        while (curr) {
            RecoveredCandidate *cand = (RecoveredCandidate*)curr->data;
            fprintf(fp, "| %u | %s | %s | %zu | %.1f%% (%s) | %s | `%s` |\n",
                    cand->candidate_id,
                    cand->suggested_name,
                    cand->file_type,
                    cand->data_size,
                    cand->confidence.total_confidence,
                    cand->confidence.confidence_grade,
                    cand->is_verified ? "PASSED (SHA-256 MATCH)" : "UNVERIFIED",
                    cand->calculated_sha256);
            curr = curr->next;
        }
    }
    fprintf(fp, "\n");

    /* Helper to write BST evidence into file */
    fprintf(fp, "## 3. Discovered Forensic Evidence Artifacts (BST Ledger)\n\n");
    fprintf(fp, "| Evidence ID | Type | Primary Block | Blocks | File Type | Suggested Name | Verified |\n");
    fprintf(fp, "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

    if (store && store->tree) {
        bst_inorder(store->tree, report_file_evidence_visitor, fp);
    }
    fprintf(fp, "\n");

    fprintf(fp, "## 4. Data Structure Utilization in Forensic Workflow\n\n");
    fprintf(fp, "- **Array & Bitmap:** Virtual disk block array and bit allocation tracking.\n");
    fprintf(fp, "- **Doubly Linked List:** Dynamic management of active directory inodes and deleted remnants.\n");
    fprintf(fp, "- **Chained Hash Table:** O(1) metadata search indexed by filename and hash.\n");
    fprintf(fp, "- **FIFO Queue:** Chunked scanner pipeline for high-throughput forensic block inspection.\n");
    fprintf(fp, "- **LIFO Stack:** Tracking investigator operations, carving backtrack states, and undo logs.\n");
    fprintf(fp, "- **Binary Search Tree (BST):** O(log N) indexing and in-order hierarchy of forensic evidence artifacts.\n");
    fprintf(fp, "- **Max-Heap Priority Queue:** Prioritizing recovered candidates based on multi-factor recovery confidence score.\n");
    fprintf(fp, "- **Directed Weighted Graph:** Modeling block adjacency and defragmenting scattered cluster paths.\n\n");

    fprintf(fp, "## 5. Conclusion & Certification\n\n");
    fprintf(fp, "The forensic analysis and recovery simulation was performed in accordance with digital forensics standards. All reconstructed artifacts have been preserved and hashed.\n");

    fclose(fp);
    return STATUS_OK;
}
