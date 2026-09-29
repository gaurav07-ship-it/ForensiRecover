#ifndef REPORT_H
#define REPORT_H

#include "common.h"
#include "storage/vdisk.h"
#include "evidence_store.h"
#include "reconstructor.h"

/**
 * @brief Forensic Case Investigation Report
 */
typedef struct {
    char case_id[32];
    char investigator_name[64];
    time_t generated_time;
    size_t total_scanned_blocks;
    size_t detected_deleted_files;
    size_t successfully_recovered;
    size_t verified_files;
    double average_confidence;
} ForensicReport;

/* Reporting Functions */
void report_print_terminal_summary(const ForensicReport *rep, const EvidenceStore *store, const FileReconstructor *rec);
StatusCode report_export_to_file(const ForensicReport *rep, const EvidenceStore *store, const FileReconstructor *rec, const char *filepath);

#endif /* REPORT_H */
