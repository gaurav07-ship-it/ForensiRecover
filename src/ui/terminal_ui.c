#include "ui/terminal_ui.h"
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#endif

/**
 * @file terminal_ui.c
 * @brief Terminal User Interface and Visual Forensic Hex/Block Display
 */

void ui_init(void) {
#ifdef _WIN32
    /* Enable Virtual Terminal Processing for ANSI escape codes on Windows */
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
#endif
}

void ui_clear_screen(void) {
    printf("\x1b[2J\x1b[H");
}

void ui_print_banner(void) {
    printf(COLOR_CYAN COLOR_BOLD);
    printf("  ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ \n");
    printf("  ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗\n");
    printf("  █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██████╔╝█████╗  ██║     ██║   ██║██║   ██║█████╗  ██████╔╝\n");
    printf("  ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██╔══██╗██╔══╝  ██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗\n");
    printf("  ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║██║  ██║███████╗╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║\n");
    printf("  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝\n");
    printf(COLOR_RESET);
    printf(COLOR_YELLOW "    [ C-Based Digital Forensics File Recovery & Data Structures Educational Simulation ]\n" COLOR_RESET);
    printf(COLOR_DIM "                         Course Project | Academic Version %s\n" COLOR_RESET, FORENSI_VERSION);
    printf("\n");
}

void ui_print_header(const char *title) {
    printf("\n" COLOR_BLUE COLOR_BOLD "┌──────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│  %-74s  │\n", title);
    printf("└──────────────────────────────────────────────────────────────────────────────┘" COLOR_RESET "\n\n");
}

void ui_print_menu(void) {
    printf(COLOR_BOLD "=== FORENSIRECOVER FORENSIC INVESTIGATION MENU ===" COLOR_RESET "\n");
    printf("  " COLOR_GREEN "1." COLOR_RESET " Run Full Automated 9-Step Forensic Recovery Simulation\n");
    printf("  " COLOR_CYAN "2." COLOR_RESET " Inspect Virtual Storage Device Status & Block Matrix\n");
    printf("  " COLOR_CYAN "3." COLOR_RESET " View Active Directory Files (Linked List & Hash Table)\n");
    printf("  " COLOR_CYAN "4." COLOR_RESET " View Deleted File Remnants (Metadata Unlinked, Bytes Intact)\n");
    printf("  " COLOR_YELLOW "5." COLOR_RESET " Inject / Create a New File into Virtual Disk\n");
    printf("  " COLOR_RED "6." COLOR_RESET " Simulate File Deletion (Remove Inode / Free Bitmap)\n");
    printf("  " COLOR_MAGENTA "7." COLOR_RESET " Simulate Intentional Disk Fragmentation (Scatter Blocks)\n");
    printf("  " COLOR_CYAN "8." COLOR_RESET " Launch Deep Disk Scanner (FIFO Queue Block Inspection)\n");
    printf("  " COLOR_GREEN "9." COLOR_RESET " Execute Graph Defragmentation & Max-Heap File Recovery\n");
    printf("  " COLOR_CYAN "10." COLOR_RESET " Inspect Forensic Evidence Ledger (Binary Search Tree)\n");
    printf("  " COLOR_CYAN "11." COLOR_RESET " View Operation History (LIFO Stack Logs)\n");
    printf("  " COLOR_YELLOW "12." COLOR_RESET " Inspect Raw Block Hex Dump\n");
    printf("  " COLOR_GREEN "13." COLOR_RESET " Generate & Export Forensic Case Report (.md / .txt)\n");
    printf("  " COLOR_MAGENTA "14." COLOR_RESET " View Comprehensive Data Structure Mapping Summary\n");
    printf("  " COLOR_WHITE "0." COLOR_RESET " Exit ForensiRecover\n");
    printf("\n" COLOR_BOLD "Select an option [0-14]: " COLOR_RESET);
}

void ui_pause(void) {
    printf("\n" COLOR_DIM "Press ENTER to continue..." COLOR_RESET);
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void ui_print_hex_dump(const uint8_t *data, size_t size, size_t max_bytes) {
    if (!data || size == 0) return;
    if (max_bytes > 0 && size > max_bytes) size = max_bytes;

    printf(COLOR_DIM "  Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |ASCII Value|\n" COLOR_RESET);
    printf(COLOR_DIM "  --------  -----------------------------------------------  |-----------|\n" COLOR_RESET);

    for (size_t i = 0; i < size; i += 16) {
        printf("  %08zX  ", i);

        /* Hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }

        /* ASCII chars */
        printf(" |");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                uint8_t c = data[i + j];
                printf("%c", isprint(c) ? c : '.');
            } else {
                printf(" ");
            }
        }
        printf("|\n");
    }
}

void ui_print_block_matrix(const VirtualDisk *disk, int start_block, int count) {
    (void)start_block;
    vdisk_dump_block_map(disk, count);
}

void ui_print_ds_summary(void) {
    ui_print_header("DATA STRUCTURE ARCHITECTURAL MAPPING IN FORENSIRECOVER");
    printf("  " COLOR_BOLD "1. Arrays & Bitmaps (Block Storage & Allocation Map)" COLOR_RESET "\n");
    printf("     - Role   : Models raw contiguous 512-byte physical sectors.\n");
    printf("     - Bitmap : O(1) bit-level testing & tracking of free vs allocated sectors.\n\n");

    printf("  " COLOR_BOLD "2. Doubly Linked Lists (Directory & Deleted Remnant Chains)" COLOR_RESET "\n");
    printf("     - Role   : Maintains active directory inodes and tracks deleted remnant entries.\n");
    printf("     - Big-O  : O(1) insertion/deletion at head/tail during file creation and unlinking.\n\n");

    printf("  " COLOR_BOLD "3. Chained Hash Tables (O(1) Metadata Directory Indexing)" COLOR_RESET "\n");
    printf("     - Role   : Provides instant O(1) average lookup of file metadata by filename or hash.\n");
    printf("     - Collis : Chained bucket collision resolution using DJB2 hashing.\n\n");

    printf("  " COLOR_BOLD "4. FIFO Task Queues (Forensic Scanner Pipeline)" COLOR_RESET "\n");
    printf("     - Role   : Schedules deep disk scanning workloads and block analysis tasks.\n");
    printf("     - Sched  : First-In-First-Out processing guarantees systematic disk sector inspection.\n\n");

    printf("  " COLOR_BOLD "5. LIFO Stacks (Forensic Operation History & Backtracking)" COLOR_RESET "\n");
    printf("     - Role   : Maintains chronological audit trail of all disk write, delete, and carve events.\n");
    printf("     - Usage  : Supports carving backtrack states and forensic investigation replay.\n\n");

    printf("  " COLOR_BOLD "6. Binary Search Trees (BST Evidence Ledger)" COLOR_RESET "\n");
    printf("     - Role   : Organizes discovered forensic artifacts indexed by unique Evidence ID.\n");
    printf("     - Traver : O(log N) search and in-order traversal generates sorted investigation timelines.\n\n");

    printf("  " COLOR_BOLD "7. Max-Heap Priority Queues (Recovery Confidence Ranking)" COLOR_RESET "\n");
    printf("     - Role   : Prioritizes reconstructed file candidates based on multi-factor confidence (0-100%%).\n");
    printf("     - Pop    : O(log N) extraction guarantees investigators inspect highest-confidence files first.\n\n");

    printf("  " COLOR_BOLD "8. Directed Weighted Graphs (Defragmentation Path Reconstruction)" COLOR_RESET "\n");
    printf("     - Role   : Vertices represent storage blocks; weighted edges represent transition correlation.\n");
    printf("     - Alg    : DFS heuristic path search solves fragmented block reconstruction.\n\n");
}
