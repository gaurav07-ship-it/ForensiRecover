#include "forensics/evidence_store.h"

/**
 * @file evidence_store.c
 * @brief Binary Search Tree (BST) Evidence Management Store
 * 
 * Stores discovered forensic artifacts and records in a BST keyed by unique
 * Evidence ID to provide O(log N) fast retrieval and sorted in-order reporting.
 */

EvidenceStore* evidence_store_create(void) {
    EvidenceStore *store = (EvidenceStore*)malloc(sizeof(EvidenceStore));
    if (!store) return NULL;
    store->tree = bst_create();
    store->next_evidence_id = 1001; /* Start evidence IDs at 1001 */
    return store;
}

static void free_evidence_record(void *data) {
    if (data) {
        free(data);
    }
}

void evidence_store_destroy(EvidenceStore *store) {
    if (!store) return;
    if (store->tree) {
        bst_destroy(store->tree, free_evidence_record);
    }
    free(store);
}

EvidenceRecord* evidence_record_create(EvidenceType type, int start_block, const char *file_type) {
    EvidenceRecord *rec = (EvidenceRecord*)calloc(1, sizeof(EvidenceRecord));
    if (!rec) return NULL;

    rec->type = type;
    rec->discovery_time = time(NULL);
    rec->primary_block = start_block;
    rec->block_count = 1;
    if (file_type) {
        strncpy(rec->file_type, file_type, 15);
    } else {
        strcpy(rec->file_type, "UNKNOWN");
    }
    rec->is_verified = false;
    return rec;
}

bool evidence_store_insert(EvidenceStore *store, EvidenceRecord *record) {
    if (!store || !record) return false;
    if (record->evidence_id == 0) {
        record->evidence_id = store->next_evidence_id++;
    }
    return bst_insert(store->tree, record->evidence_id, record);
}

EvidenceRecord* evidence_store_find(const EvidenceStore *store, uint32_t evidence_id) {
    if (!store || !store->tree) return NULL;
    return (EvidenceRecord*)bst_search(store->tree, evidence_id);
}

static void print_evidence_visitor(uint32_t key, void *data, void *context) {
    (void)key;
    (void)context;
    EvidenceRecord *rec = (EvidenceRecord*)data;
    if (!rec) return;

    const char *type_str = "UNKNOWN";
    switch (rec->type) {
        case EVIDENCE_DELETED_INODE: type_str = "DELETED_INODE"; break;
        case EVIDENCE_CARVED_HEADER: type_str = "CARVED_HEADER"; break;
        case EVIDENCE_RECONSTRUCTED_FILE: type_str = "RECONSTRUCTED_FILE"; break;
        case EVIDENCE_SUSPICIOUS_BLOCK: type_str = "SUSPICIOUS_BLOCK"; break;
    }

    char time_buf[32];
    struct tm *tm_info = localtime(&rec->discovery_time);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("  [EVID #%u] %-18s | Blk: %-4d (%d blks) | Type: %-4s | Name: %-18s\n",
           rec->evidence_id, type_str, rec->primary_block, rec->block_count, rec->file_type, rec->suggested_name);
    printf("            Conf: %5.1f%% (%-14s) | Verified: %s | SHA256: %.16s...\n",
           rec->confidence.total_confidence, rec->confidence.confidence_grade,
           rec->is_verified ? COLOR_GREEN "MATCH (PASS)" COLOR_RESET : COLOR_YELLOW "UNVERIFIED" COLOR_RESET,
           rec->calculated_sha256[0] ? rec->calculated_sha256 : "N/A");
    if (rec->notes[0]) {
        printf("            Notes: %s\n", rec->notes);
    }
    printf("  --------------------------------------------------------------------------------\n");
}

void evidence_store_print_all(const EvidenceStore *store) {
    if (!store || !store->tree || bst_size(store->tree) == 0) {
        printf("  [!] No forensic evidence records currently registered in BST.\n");
        return;
    }

    printf("\n" COLOR_CYAN COLOR_BOLD "=== FORENSIC EVIDENCE LEDGER (BST In-Order Traversal) ===" COLOR_RESET "\n");
    printf("  Total Evidence Items in BST: %zu\n", bst_size(store->tree));
    printf("  --------------------------------------------------------------------------------\n");
    bst_inorder(store->tree, print_evidence_visitor, NULL);
    printf(COLOR_CYAN "==========================================================================" COLOR_RESET "\n\n");
}

size_t evidence_store_count(const EvidenceStore *store) {
    return (store && store->tree) ? bst_size(store->tree) : 0;
}
