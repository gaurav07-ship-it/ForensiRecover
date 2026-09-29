#ifndef RECONSTRUCTOR_H
#define RECONSTRUCTOR_H

#include "common.h"
#include "storage/vdisk.h"
#include "ds/heap.h"
#include "ds/graph.h"
#include "signatures.h"
#include "confidence.h"
#include "evidence_store.h"
#include "scanner.h"

/**
 * @brief Recovered File Candidate
 * Ranked inside Max-Heap by total recovery confidence score.
 */
typedef struct {
    uint32_t candidate_id;
    char file_type[16];
    char suggested_name[VDISK_MAX_FILENAME];
    uint8_t *reconstructed_data;
    size_t data_size;
    int block_path[MAX_BLOCKS_PER_FILE];
    int block_count;
    ConfidenceFactors confidence;
    uint32_t calculated_crc32;
    char calculated_sha256[65];
    bool is_verified;
    uint32_t matched_inode_id;
} RecoveredCandidate;

/**
 * @brief File Reconstructor & Carver Engine
 * Utilizes BlockGraph for defragmentation and MaxHeap for confidence ranking.
 */
typedef struct {
    MaxHeap *candidate_heap;     /* Max-Heap Priority Queue for candidate prioritization */
    BlockGraph *fragment_graph;  /* Directed Graph for fragmented block tracing */
    LinkedList *recovered_list;  /* List of finalized recovered files */
} FileReconstructor;

/* Reconstructor Operations */
FileReconstructor* reconstructor_create(void);
void reconstructor_destroy(FileReconstructor *rec);

/**
 * @brief Reconstructs a file from a detected header block using carving & graph path search.
 */
RecoveredCandidate* reconstructor_carve_file(FileReconstructor *rec, 
                                            VirtualDisk *disk, 
                                            int start_block, 
                                            const char *file_type);

/**
 * @brief Performs complete disk reconstruction of all detected headers.
 * Ranks all candidates in the Max-Heap and returns the total number of recovered candidates.
 */
size_t reconstructor_run_all(FileReconstructor *rec, 
                             VirtualDisk *disk, 
                             ForensicScanner *scanner, 
                             EvidenceStore *evidence_store);

/**
 * @brief Exports a recovered candidate file to the real host filesystem.
 */
StatusCode reconstructor_export_file(const RecoveredCandidate *cand, const char *destination_path);

#endif /* RECONSTRUCTOR_H */
