#ifndef SCANNER_H
#define SCANNER_H

#include "common.h"
#include "storage/vdisk.h"
#include "ds/queue.h"
#include "evidence_store.h"

/**
 * @brief Scan Task dispatched through FIFO Queue
 */
typedef struct {
    int start_block;
    int end_block;
    bool scan_unallocated_only;
    bool deep_inspection;
} ScanTask;

/**
 * @brief Discovered Raw Header Marker on Disk
 */
typedef struct {
    int block_index;
    char file_type[16];
    size_t header_offset_in_block;
    bool has_matching_inode;
    uint32_t matched_inode_id;
} DiscoveredHeader;

/**
 * @brief Forensic Scanner Engine
 */
typedef struct {
    Queue *task_queue;                   /* FIFO Queue for scanning workloads */
    LinkedList *discovered_headers;      /* Linked List of all file headers found */
} ForensicScanner;

/* Scanner Operations */
ForensicScanner* scanner_create(void);
void scanner_destroy(ForensicScanner *scanner);
void scanner_schedule_task(ForensicScanner *scanner, int start_block, int end_block, bool unallocated_only);
size_t scanner_execute_scan(ForensicScanner *scanner, VirtualDisk *disk, EvidenceStore *evidence_store);

#endif /* SCANNER_H */
