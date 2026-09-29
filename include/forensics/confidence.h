#ifndef CONFIDENCE_H
#define CONFIDENCE_H

#include "common.h"
#include "signatures.h"

/**
 * @brief Detailed breakdown of recovery confidence factors
 */
typedef struct {
    double header_match_score;      /* 0 - 30: Magic header accuracy */
    double footer_match_score;      /* 0 - 25: Footer/EOF marker accuracy */
    double continuity_score;        /* 0 - 20: Sequential block allocation likelihood */
    double structure_validity_score;/* 0 - 15: File format structural validation (e.g. valid PNG chunks, PDF tags) */
    double metadata_bonus_score;    /* 0 - 10: Inode remnant or directory alignment */
    double total_confidence;        /* 0 - 100% total calculated confidence */
    char confidence_grade[16];      /* "HIGH (90-100%)", "MEDIUM (60-89%)", "LOW (<60%)" */
} ConfidenceFactors;

/**
 * @brief Evaluates recovery confidence for a candidate file.
 */
ConfidenceFactors confidence_evaluate(const FileSignature *sig, 
                                     const uint8_t *data, 
                                     size_t data_len, 
                                     const int *block_path, 
                                     int path_len, 
                                     bool has_metadata_hint);

#endif /* CONFIDENCE_H */
