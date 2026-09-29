#include "ui/demo_scenarios.h"
#include "ui/terminal_ui.h"
#include "forensics/signatures.h"
#include "forensics/scanner.h"
#include "forensics/reconstructor.h"
#include "forensics/evidence_store.h"
#include "forensics/report.h"
#include "storage/fragmentation.h"

/**
 * @file demo_scenarios.c
 * @brief End-to-End 9-Step Forensic Recovery Simulation
 */

/* Synthetic valid file payloads for demonstration */
static const uint8_t SAMPLE_PDF[] = 
    "%PDF-1.4\n"
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
    "4 0 obj\n<< /Length 128 >>\nstream\n"
    "BT /F1 24 Tf 100 700 Td (FORENSIC CONFIDENTIAL REPORT: INCIDENT 2026-X) Tj ET\n"
    "BT /F1 12 Tf 100 650 Td (Classified financial records detected on virtual volume.) Tj ET\n"
    "endstream\nendobj\n"
    "xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000204 00000 n \n"
    "trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n390\n%%EOF\n";

static const uint8_t SAMPLE_PNG[] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, /* PNG Signature */
    0x00, 0x00, 0x00, 0x0D,                         /* IHDR length 13 */
    0x49, 0x48, 0x44, 0x52,                         /* 'IHDR' */
    0x00, 0x00, 0x00, 0x20,                         /* Width 32 */
    0x00, 0x00, 0x00, 0x20,                         /* Height 32 */
    0x08, 0x02, 0x00, 0x00, 0x00,                   /* 8-bit truecolor */
    0x4D, 0x78, 0x2B, 0x8C,                         /* IHDR CRC */
    0x00, 0x00, 0x00, 0x40,                         /* IDAT chunk len 64 */
    0x49, 0x44, 0x41, 0x54,                         /* 'IDAT' */
    0x78, 0x9C, 0x63, 0x60, 0x60, 0x60, 0x60, 0x60, /* Raw image stream payload */
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
    0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00, 0x01, 0x00, /* IDAT CRC */
    0x00, 0x00, 0x00, 0x00,                         /* IEND length 0 */
    0x49, 0x45, 0x4E, 0x44,                         /* 'IEND' */
    0xAE, 0x42, 0x60, 0x82                          /* IEND CRC */
};

static const char SAMPLE_TXT[] = 
    "=== INCIDENT LOG FILE: SUSPECT TRANSACTION RECORDS ===\n"
    "Date: 2026-09-29 10:15:00\n"
    "Target Account: #8849-2910-4491\n"
    "Transferred: $250,000 to Offshore Vault\n"
    "Status: Transaction completed successfully.\n"
    "Agent ID: Alpha-42\n"
    "Evidence Integrity Tag: CRITICAL_EXHIBIT_A\n";

static const uint8_t SAMPLE_ZIP[] = {
    0x50, 0x4B, 0x03, 0x04, /* PK\x03\x04 Local Header */
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, /* Filename len 8 */
    'l', 'o', 'g', 's', '.', 't', 'x', 't',
    'D', 'A', 'T', 'A', '_', 'Z', 'I', 'P',
    0x50, 0x4B, 0x05, 0x06, /* PK\x05\x06 End of Central Directory */
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x36, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x00, 0x00
};

void demo_run_full_simulation(VirtualDisk *disk) {
    ui_clear_screen();
    ui_print_banner();
    ui_print_header("RUNNING FULL 9-STEP FORENSIC SIMULATION WORKFLOW");

    /* =========================================================================
     * STEP 1: CREATE FILES
     * ========================================================================= */
    printf(COLOR_CYAN COLOR_BOLD "[STEP 1/9] CREATE: Initializing Target Case Evidence Files in Memory..." COLOR_RESET "\n");
    printf("  - evidence_document.pdf  (PDF Document, Size: %zu bytes)\n", sizeof(SAMPLE_PDF) - 1);
    printf("  - suspect_photo.png      (PNG Image, Size: %zu bytes)\n", sizeof(SAMPLE_PNG));
    printf("  - transaction_log.txt    (Text Log, Size: %zu bytes)\n", strlen(SAMPLE_TXT));
    printf("  - archive_backup.zip     (ZIP Archive, Size: %zu bytes)\n\n", sizeof(SAMPLE_ZIP));

    /* =========================================================================
     * STEP 2: STORE FILES ON VIRTUAL DISK
     * ========================================================================= */
    printf(COLOR_CYAN COLOR_BOLD "[STEP 2/9] STORE: Allocating Disk Blocks & Building Metadata Structures..." COLOR_RESET "\n");
    printf("  - [Data Structure: Array & Bitmap] Dividing files into 512-byte blocks & marking bits.\n");
    printf("  - [Data Structure: Doubly Linked List] Appending file records to active file list.\n");
    printf("  - [Data Structure: Chained Hash Table] Indexing metadata for O(1) filename lookup.\n");

    vdisk_format(disk);

    vdisk_create_file(disk, "evidence_document.pdf", SAMPLE_PDF, sizeof(SAMPLE_PDF) - 1, "PDF");
    vdisk_create_file(disk, "suspect_photo.png", SAMPLE_PNG, sizeof(SAMPLE_PNG), "PNG");
    vdisk_create_file(disk, "transaction_log.txt", (const uint8_t*)SAMPLE_TXT, strlen(SAMPLE_TXT), "TXT");
    vdisk_create_file(disk, "archive_backup.zip", SAMPLE_ZIP, sizeof(SAMPLE_ZIP), "ZIP");

    printf("  " COLOR_GREEN "[OK] 4 Files successfully written to virtual storage." COLOR_RESET "\n\n");
    vdisk_dump_block_map(disk, 64);

    /* =========================================================================
     * STEP 3: SIMULATE DELETION
     * ========================================================================= */
    printf(COLOR_CYAN COLOR_BOLD "[STEP 3/9] DELETE: Simulating Suspect File Deletion..." COLOR_RESET "\n");
    printf("  - Suspect attempts to destroy incriminating evidence: deleting 'evidence_document.pdf' & 'suspect_photo.png'.\n");
    printf("  - [Forensic Concept] In real filesystems, deletion removes directory pointers and frees bitmap bits,\n");
    printf("    BUT the raw payload bytes remain resident in disk sectors until overwritten!\n");
    printf("  - [Data Structure: Stack] Logging delete actions into LIFO operation history stack.\n");

    vdisk_delete_file(disk, "evidence_document.pdf");
    vdisk_delete_file(disk, "suspect_photo.png");

    printf("  " COLOR_GREEN "[OK] Files unlinked from active directory. Data remnants preserved in storage blocks." COLOR_RESET "\n\n");
    vdisk_dump_block_map(disk, 64);

    /* =========================================================================
     * STEP 4: FRAGMENTATION SIMULATION
     * ========================================================================= */
    printf(COLOR_CYAN COLOR_BOLD "[STEP 4/9] FRAGMENT: Simulating Disk Cluster Fragmentation..." COLOR_RESET "\n");
    printf("  - Scattering file blocks across non-contiguous clusters.\n");
    printf("  - This simulates a realistic fragmented hard drive where file pieces are separated.\n");

    vdisk_fragment_file(disk, "evidence_document.pdf", FRAG_STRATEGY_SCATTER);
    vdisk_fragment_file(disk, "archive_backup.zip", FRAG_STRATEGY_SCATTER);

    printf("  " COLOR_GREEN "[OK] Files successfully fragmented across non-adjacent blocks." COLOR_RESET "\n\n");
    vdisk_dump_block_map(disk, 96);

    /* =========================================================================
     * STEP 5: FORENSIC SCAN
     * ========================================================================= */
    printf(COLOR_CYAN COLOR_BOLD "[STEP 5/9] SCAN: Launching Queue-Driven Deep Forensic Disk Scanner..." COLOR_RESET "\n");
    printf("  - [Data Structure: FIFO Queue] Enqueueing block range scanning tasks [0-2047].\n");
    printf("  - Dequeueing tasks and inspecting every unallocated sector byte-by-byte.\n");

    EvidenceStore *store = evidence_store_create();
    ForensicScanner *scanner = scanner_create();

    /* Schedule 4 quadrant scanning tasks in Queue */
    scanner_schedule_task(scanner, 0, 511, true);
    scanner_schedule_task(scanner, 512, 1023, true);
    scanner_schedule_task(scanner, 1024, 1535, true);
    scanner_schedule_task(scanner, 1536, 2047, true);

    size_t headers_found = scanner_execute_scan(scanner, disk, store);
    printf("  " COLOR_GREEN "[OK] Scan complete. Found %zu signature headers in unallocated space." COLOR_RESET "\n\n", headers_found);

    /* =========================================================================
     * STEP 6: IDENTIFY FILE SIGNATURES
     * ========================================================================= */
    printf(COLOR_CYAN COLOR_BOLD "[STEP 6/9] IDENTIFY: Matching Signatures against Magic Bytes Database..." COLOR_RESET "\n");
    ListNode *hcurr = scanner->discovered_headers->head;
    while (hcurr) {
        DiscoveredHeader *hdr = (DiscoveredHeader*)hcurr->data;
        printf("  - Discovered Signature: " COLOR_YELLOW "[%s]" COLOR_RESET " at Block #%d (Matching Inode Remnant: %s)\n",
               hdr->file_type, hdr->block_index, hdr->has_matching_inode ? "YES" : "NO");
        hcurr = hcurr->next;
    }
    printf("\n");

    /* =========================================================================
     * STEP 7: RECOVER & DEFRAGMENT
     * ========================================================================= */
    printf(COLOR_CYAN COLOR_BOLD "[STEP 7/9] RECOVER: Graph-Based Defragmentation & Max-Heap Candidate Ranking..." COLOR_RESET "\n");
    printf("  - [Data Structure: Directed Weighted Graph] Constructing block transition graph for fragments.\n");
    printf("  - [Algorithm: DFS Path Search] Tracing optimal Header->Body->Footer block paths.\n");
    printf("  - [Data Structure: Max-Heap Priority Queue] Prioritizing candidates by forensic confidence score.\n");

    FileReconstructor *reconstructor = reconstructor_create();
    size_t total_recovered = reconstructor_run_all(reconstructor, disk, scanner, store);

    printf("  " COLOR_GREEN "[OK] Successfully carved & defragmented %zu candidate files." COLOR_RESET "\n\n", total_recovered);

    /* =========================================================================
     * STEP 8: INTEGRITY VERIFICATION
     * ========================================================================= */
    printf(COLOR_CYAN COLOR_BOLD "[STEP 8/9] VERIFY: Cryptographic SHA-256 & CRC-32 Integrity Verification..." COLOR_RESET "\n");
    size_t verified_count = 0;
    double confidence_sum = 0.0;

    ListNode *rcurr = reconstructor->recovered_list->head;
    while (rcurr) {
        RecoveredCandidate *cand = (RecoveredCandidate*)rcurr->data;
        confidence_sum += cand->confidence.total_confidence;
        if (cand->is_verified) verified_count++;

        printf("  - Candidate #%u: %-20s | Size: %4zu B | Score: %5.1f%% | Hash: %.16s... | Status: %s\n",
               cand->candidate_id, cand->suggested_name, cand->data_size,
               cand->confidence.total_confidence, cand->calculated_sha256,
               cand->is_verified ? COLOR_GREEN "MATCH (PASS)" COLOR_RESET : COLOR_YELLOW "UNVERIFIED" COLOR_RESET);
        rcurr = rcurr->next;
    }
    printf("\n");

    /* =========================================================================
     * STEP 9: GENERATE FORENSIC REPORT
     * ========================================================================= */
    printf(COLOR_CYAN COLOR_BOLD "[STEP 9/9] REPORT: Generating Investigation Report & Evidence Ledger (BST)..." COLOR_RESET "\n");
    printf("  - [Data Structure: Binary Search Tree] Organizing evidence artifacts by Evidence ID.\n");
    printf("  - Compiling formal case report with timeline and checksums.\n");

    ForensicReport rep;
    strcpy(rep.case_id, "CASE-2026-FORENSI-01");
    strcpy(rep.investigator_name, "Forensic Unit (Data Structures)");
    rep.generated_time = time(NULL);
    rep.total_scanned_blocks = disk->superblock.total_blocks;
    rep.detected_deleted_files = headers_found;
    rep.successfully_recovered = total_recovered;
    rep.verified_files = verified_count;
    rep.average_confidence = (total_recovered > 0) ? (confidence_sum / total_recovered) : 0.0;

    report_print_terminal_summary(&rep, store, reconstructor);

    const char *report_file = "forensic_investigation_report.md";
    if (report_export_to_file(&rep, store, reconstructor, report_file) == STATUS_OK) {
        printf(COLOR_GREEN "[+] Formal investigation report exported to '%s'" COLOR_RESET "\n", report_file);
    }

    /* Cleanup temporary forensic structures */
    reconstructor_destroy(reconstructor);
    scanner_destroy(scanner);
    evidence_store_destroy(store);

    printf("\n" COLOR_GREEN COLOR_BOLD ">>> Full 9-Step Forensic Recovery Simulation Completed Successfully! <<<" COLOR_RESET "\n");
    ui_pause();
}

void demo_create_sample_files(void) {
    FILE *fp = fopen("sample_evidence.txt", "w");
    if (fp) {
        fprintf(fp, "%s", SAMPLE_TXT);
        fclose(fp);
        printf(COLOR_GREEN "[+] Created 'sample_evidence.txt' on host drive for file injection testing.\n" COLOR_RESET);
    }
}
