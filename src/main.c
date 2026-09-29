#include "common.h"
#include "storage/vdisk.h"
#include "storage/fragmentation.h"
#include "forensics/signatures.h"
#include "forensics/scanner.h"
#include "forensics/reconstructor.h"
#include "forensics/evidence_store.h"
#include "forensics/report.h"
#include "forensics/integrity.h"
#include "ui/terminal_ui.h"
#include "ui/demo_scenarios.h"

/**
 * @file main.c
 * @brief ForensiRecover Main Entrypoint and Interactive Forensic Dashboard
 */

static void handle_view_active_files(VirtualDisk *disk) {
    ui_print_header("ACTIVE DIRECTORY FILES (Doubly Linked List & Hash Table)");
    if (!disk->active_files || list_size(disk->active_files) == 0) {
        printf("  [!] No active files found on virtual storage.\n");
        ui_pause();
        return;
    }

    printf("  %-4s | %-24s | %-6s | %-10s | %-8s | %-12s\n", 
           "ID", "Filename", "Type", "Size (B)", "Blocks", "CRC-32");
    printf("  -----+--------------------------+--------+------------+----------+-------------\n");

    ListNode *curr = disk->active_files->head;
    while (curr) {
        Inode *in = (Inode*)curr->data;
        printf("  %-4u | %-24s | %-6s | %-10zu | %-8u | 0x%08X\n",
               in->inode_id, in->filename, in->file_type, in->file_size, in->block_count, in->original_crc32);
        curr = curr->next;
    }
    ui_pause();
}

static void handle_view_deleted_files(VirtualDisk *disk) {
    ui_print_header("DELETED FILE REMNANTS (Metadata Unlinked, Raw Blocks Preserved)");
    if (!disk->deleted_files || list_size(disk->deleted_files) == 0) {
        printf("  [!] No deleted file remnants registered.\n");
        ui_pause();
        return;
    }

    printf("  %-4s | %-24s | %-6s | %-10s | %-8s | %-12s\n", 
           "ID", "Filename", "Type", "Size (B)", "Blocks", "Original CRC-32");
    printf("  -----+--------------------------+--------+------------+----------+-----------------\n");

    ListNode *curr = disk->deleted_files->head;
    while (curr) {
        Inode *in = (Inode*)curr->data;
        printf("  %-4u | %-24s | %-6s | %-10zu | %-8u | 0x%08X\n",
               in->inode_id, in->filename, in->file_type, in->file_size, in->block_count, in->original_crc32);
        printf("         Initial Block: #%d | Block Chain: [", in->block_indices[0]);
        for (uint32_t b = 0; b < in->block_count; b++) {
            printf("%d%s", in->block_indices[b], (b + 1 < in->block_count) ? ", " : "");
        }
        printf("]\n");
        curr = curr->next;
    }
    ui_pause();
}

static void handle_create_file(VirtualDisk *disk) {
    ui_print_header("CREATE / INJECT FILE INTO VIRTUAL STORAGE");
    char filename[VDISK_MAX_FILENAME];
    char content[2048];
    char type_str[16];

    printf("  Enter file name (e.g. document.txt, note.txt): ");
    if (scanf("%63s", filename) != 1) return;

    printf("  Enter file type (e.g. TXT, PDF, PNG, BIN): ");
    if (scanf("%15s", type_str) != 1) return;

    printf("  Enter file text content: ");
    /* Clear newline */
    getchar();
    if (fgets(content, sizeof(content), stdin) == NULL) return;
    size_t len = strlen(content);
    if (len > 0 && content[len - 1] == '\n') {
        content[len - 1] = '\0';
        len--;
    }

    StatusCode st = vdisk_create_file(disk, filename, (const uint8_t*)content, len, type_str);
    if (st == STATUS_OK) {
        printf(COLOR_GREEN "  [+] File '%s' successfully created and stored in blocks.\n" COLOR_RESET, filename);
    } else {
        printf(COLOR_RED "  [-] Failed to create file (error code %d).\n" COLOR_RESET, st);
    }
    ui_pause();
}

static void handle_delete_file(VirtualDisk *disk) {
    ui_print_header("SIMULATE FILE DELETION");
    char filename[VDISK_MAX_FILENAME];

    printf("  Enter name of file to delete: ");
    if (scanf("%63s", filename) != 1) return;

    StatusCode st = vdisk_delete_file(disk, filename);
    if (st == STATUS_OK) {
        printf(COLOR_GREEN "  [+] File '%s' deleted. Inode unlinked from directory; data remnants preserved.\n" COLOR_RESET, filename);
    } else {
        printf(COLOR_RED "  [-] File not found or deletion failed.\n" COLOR_RESET);
    }
    ui_pause();
}

static void handle_fragment_file(VirtualDisk *disk) {
    ui_print_header("SIMULATE INTENTIONAL DISK FRAGMENTATION");
    char filename[VDISK_MAX_FILENAME];

    printf("  Enter filename to fragment (or 'ALL' for whole disk): ");
    if (scanf("%63s", filename) != 1) return;

    if (strcmp(filename, "ALL") == 0 || strcmp(filename, "all") == 0) {
        vdisk_simulate_heavy_fragmentation(disk);
        printf(COLOR_GREEN "  [+] Heavy fragmentation simulated across virtual disk.\n" COLOR_RESET);
    } else {
        StatusCode st = vdisk_fragment_file(disk, filename, FRAG_STRATEGY_SCATTER);
        if (st == STATUS_OK) {
            printf(COLOR_GREEN "  [+] File '%s' fragmented across non-adjacent block clusters.\n" COLOR_RESET, filename);
        } else {
            printf(COLOR_RED "  [-] Could not fragment file.\n" COLOR_RESET);
        }
    }
    ui_pause();
}

static void handle_view_stack_history(VirtualDisk *disk) {
    ui_print_header("OPERATION HISTORY LOGS (LIFO Stack Data Structure)");
    if (!disk->operation_history || stack_is_empty(disk->operation_history)) {
        printf("  [!] Stack is currently empty (no operations recorded yet).\n");
        ui_pause();
        return;
    }

    printf("  Total Recorded Operations in Stack: %zu\n\n", stack_size(disk->operation_history));
    printf("  %-4s | %-16s | %-24s | %-32s\n", "Idx", "Operation", "Target Filename", "Details");
    printf("  -----+------------------+--------------------------+---------------------------------\n");

    /* Create temporary copy to inspect stack without destroying it */
    StackNode *curr = disk->operation_history->top;
    int idx = 1;
    while (curr) {
        DiskOperationRecord *op = (DiskOperationRecord*)curr->data;
        const char *op_name = "UNKNOWN";
        switch (op->type) {
            case OP_CREATE_FILE: op_name = "OP_CREATE_FILE"; break;
            case OP_DELETE_FILE: op_name = "OP_DELETE_FILE"; break;
            case OP_FRAGMENT_FILE: op_name = "OP_FRAGMENT"; break;
            case OP_OVERWRITE_BLOCK: op_name = "OP_OVERWRITE"; break;
        }
        printf("  %-4d | %-16s | %-24s | %-32s\n", idx++, op_name, op->filename, op->details);
        curr = curr->next;
    }
    ui_pause();
}

static void handle_inspect_hex(VirtualDisk *disk) {
    ui_print_header("INSPECT RAW BLOCK HEX DUMP");
    int block_num = 0;
    printf("  Enter Block Number [0-%u]: ", disk->superblock.total_blocks - 1);
    if (scanf("%d", &block_num) != 1 || block_num < 0 || block_num >= (int)disk->superblock.total_blocks) {
        printf(COLOR_RED "  [-] Invalid block index.\n" COLOR_RESET);
        ui_pause();
        return;
    }

    uint8_t *data = vdisk_get_block_ptr(disk, block_num);
    bool is_alloc = bitmap_test(disk->block_bitmap, block_num);

    printf("\n  " COLOR_BOLD "Block #%d Details:" COLOR_RESET " (Status: %s)\n\n", 
           block_num, is_alloc ? COLOR_GREEN "ALLOCATED" COLOR_RESET : COLOR_RED "UNALLOCATED / FREE" COLOR_RESET);
    ui_print_hex_dump(data, VDISK_BLOCK_SIZE, 512);
    ui_pause();
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    ui_init();
    signatures_init_db();
    srand((unsigned int)time(NULL));

    VirtualDisk *disk = vdisk_init();
    if (!disk) {
        fprintf(stderr, "Failed to initialize Virtual Disk.\n");
        return 1;
    }

    EvidenceStore *evidence_store = evidence_store_create();
    ForensicScanner *scanner = scanner_create();
    FileReconstructor *reconstructor = reconstructor_create();

    /* Preload disk with baseline simulation files */
    demo_run_full_simulation(disk);

    int choice = -1;
    while (choice != 0) {
        ui_clear_screen();
        ui_print_banner();
        ui_print_menu();

        int res = scanf("%d", &choice);
        if (res == EOF) {
            choice = 0;
            break;
        }
        if (res != 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            choice = -1;
            continue;
        }

        switch (choice) {
            case 1:
                demo_run_full_simulation(disk);
                break;
            case 2:
                ui_clear_screen();
                ui_print_banner();
                vdisk_print_stats(disk);
                vdisk_dump_block_map(disk, 128);
                ui_pause();
                break;
            case 3:
                handle_view_active_files(disk);
                break;
            case 4:
                handle_view_deleted_files(disk);
                break;
            case 5:
                handle_create_file(disk);
                break;
            case 6:
                handle_delete_file(disk);
                break;
            case 7:
                handle_fragment_file(disk);
                break;
            case 8: {
                ui_clear_screen();
                ui_print_banner();
                ui_print_header("LAUNCH DEEP DISK SCANNER (FIFO Task Queue)");
                scanner_schedule_task(scanner, 0, (int)disk->superblock.total_blocks - 1, true);
                size_t found = scanner_execute_scan(scanner, disk, evidence_store);
                printf(COLOR_GREEN "  [+] Scan complete. Detected %zu signature headers in unallocated sectors.\n" COLOR_RESET, found);
                ui_pause();
                break;
            }
            case 9: {
                ui_clear_screen();
                ui_print_banner();
                ui_print_header("GRAPH DEFRAGMENTATION & MAX-HEAP FILE RECOVERY");
                size_t recovered = reconstructor_run_all(reconstructor, disk, scanner, evidence_store);
                printf(COLOR_GREEN "  [+] Recovery complete. %zu files carved, defragmented & ranked in Max-Heap.\n" COLOR_RESET, recovered);
                ui_pause();
                break;
            }
            case 10:
                ui_clear_screen();
                ui_print_banner();
                evidence_store_print_all(evidence_store);
                ui_pause();
                break;
            case 11:
                handle_view_stack_history(disk);
                break;
            case 12:
                handle_inspect_hex(disk);
                break;
            case 13: {
                ui_clear_screen();
                ui_print_banner();
                ui_print_header("GENERATE & EXPORT INVESTIGATION REPORT");
                ForensicReport rep;
                strcpy(rep.case_id, "CASE-2026-MANUAL-01");
                strcpy(rep.investigator_name, "Forensic Lead");
                rep.generated_time = time(NULL);
                rep.total_scanned_blocks = disk->superblock.total_blocks;
                rep.detected_deleted_files = list_size(scanner->discovered_headers);
                rep.successfully_recovered = list_size(reconstructor->recovered_list);
                rep.verified_files = 0;
                rep.average_confidence = 0.0;

                ListNode *curr = reconstructor->recovered_list->head;
                double sum_conf = 0.0;
                while (curr) {
                    RecoveredCandidate *c = (RecoveredCandidate*)curr->data;
                    sum_conf += c->confidence.total_confidence;
                    if (c->is_verified) rep.verified_files++;
                    curr = curr->next;
                }
                if (rep.successfully_recovered > 0) {
                    rep.average_confidence = sum_conf / rep.successfully_recovered;
                }

                report_print_terminal_summary(&rep, evidence_store, reconstructor);
                const char *out_file = "forensic_investigation_report.md";
                report_export_to_file(&rep, evidence_store, reconstructor, out_file);
                printf(COLOR_GREEN "\n  [+] Report successfully saved to '%s'.\n" COLOR_RESET, out_file);
                ui_pause();
                break;
            }
            case 14:
                ui_clear_screen();
                ui_print_banner();
                ui_print_ds_summary();
                ui_pause();
                break;
            case 0:
                printf("\n" COLOR_CYAN "Exiting ForensiRecover. Goodbye!\n" COLOR_RESET);
                break;
            default:
                printf(COLOR_RED "Invalid selection. Please try again.\n" COLOR_RESET);
                ui_pause();
                break;
        }
    }

    reconstructor_destroy(reconstructor);
    scanner_destroy(scanner);
    evidence_store_destroy(evidence_store);
    vdisk_destroy(disk);

    return 0;
}
