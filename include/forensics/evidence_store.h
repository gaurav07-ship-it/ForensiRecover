#ifndef EVIDENCE_STORE_H
#define EVIDENCE_STORE_H

#include "common.h"
#include "ds/bst.h"
#include "confidence.h"

typedef enum {
    EVIDENCE_DELETED_INODE = 1,
    EVIDENCE_CARVED_HEADER = 2,
    EVIDENCE_RECONSTRUCTED_FILE = 3,
    EVIDENCE_SUSPICIOUS_BLOCK = 4
} EvidenceType;

/**
 * @brief Forensic Evidence Record
 * Stored inside the Binary Search Tree (BST) indexed by unique evidence_id / block offset.
 */
typedef struct {
    uint32_t evidence_id;                /* Primary Key for BST */
    EvidenceType type;                   /* Evidence category */
    time_t discovery_time;               /* Timestamp when discovered during scan */
    int primary_block;                   /* Start block on virtual disk */
    int block_count;                     /* Number of blocks involved */
    char file_type[16];                  /* Detected file type */
    char suggested_name[VDISK_MAX_FILENAME]; /* Suggested filename */
    size_t estimated_size;               /* Size in bytes */
    ConfidenceFactors confidence;        /* Recovery confidence breakdown */
    char calculated_sha256[65];          /* SHA-256 of carved data */
    uint32_t calculated_crc32;           /* CRC-32 of carved data */
    bool is_verified;                    /* Hash verification outcome */
    char notes[256];                     /* Investigator notes */
} EvidenceRecord;

/**
 * @brief Forensic Evidence Store Manager
 */
typedef struct {
    BST *tree;                           /* Binary Search Tree of evidence records */
    uint32_t next_evidence_id;           /* Monotonically increasing ID */
} EvidenceStore;

/* Evidence Store Operations */
EvidenceStore* evidence_store_create(void);
void evidence_store_destroy(EvidenceStore *store);
EvidenceRecord* evidence_record_create(EvidenceType type, int start_block, const char *file_type);
bool evidence_store_insert(EvidenceStore *store, EvidenceRecord *record);
EvidenceRecord* evidence_store_find(const EvidenceStore *store, uint32_t evidence_id);
void evidence_store_print_all(const EvidenceStore *store);
size_t evidence_store_count(const EvidenceStore *store);

#endif /* EVIDENCE_STORE_H */
