#include "forensics/confidence.h"

/**
 * @file confidence.c
 * @brief Forensic Recovery Confidence Scoring Engine
 * 
 * Computes a weighted recovery confidence score (0-100%) based on:
 * - Signature Header Match (30%)
 * - Footer / EOF Match (25%)
 * - Block Continuity & Adjacency (20%)
 * - Structural Syntax Validation (15%)
 * - Metadata / Inode Remnant Clues (10%)
 */

/* Portable Byte Pattern Search Helper */
static bool contains_byte_pattern(const uint8_t *data, size_t data_len, const void *pattern, size_t pat_len) {
    if (!data || !pattern || pat_len == 0 || data_len < pat_len) return false;
    for (size_t i = 0; i <= data_len - pat_len; i++) {
        if (memcmp(&data[i], pattern, pat_len) == 0) return true;
    }
    return false;
}

ConfidenceFactors confidence_evaluate(const FileSignature *sig, 
                                     const uint8_t *data, 
                                     size_t data_len, 
                                     const int *block_path, 
                                     int path_len, 
                                     bool has_metadata_hint) {
    ConfidenceFactors factors;
    memset(&factors, 0, sizeof(factors));

    if (!data || data_len == 0) {
        strcpy(factors.confidence_grade, "LOW (<60%)");
        return factors;
    }

    /* 1. Header Match (Max 30 pts) */
    if (sig) {
        if (sig->header_len > 0 && data_len >= sig->header_len) {
            if (memcmp(data, sig->header_bytes, sig->header_len) == 0) {
                factors.header_match_score = 30.0;
            } else {
                factors.header_match_score = 10.0;
            }
        } else if (strcmp(sig->type_name, "TXT") == 0) {
            factors.header_match_score = 25.0;
        }
    } else {
        factors.header_match_score = 5.0;
    }

    /* 2. Footer Match (Max 25 pts) */
    if (sig && sig->has_footer) {
        size_t footer_offset = 0;
        if (signatures_check_footer(sig, data, data_len, &footer_offset)) {
            factors.footer_match_score = 25.0;
        } else {
            factors.footer_match_score = 5.0;
        }
    } else if (sig && !sig->has_footer) {
        /* Formats without fixed footers (BMP, TXT) */
        factors.footer_match_score = 20.0;
    } else {
        factors.footer_match_score = 5.0;
    }

    /* 3. Block Continuity (Max 20 pts) */
    if (path_len <= 1) {
        factors.continuity_score = 20.0; /* Single block is fully continuous */
    } else if (block_path && path_len > 1) {
        int continuous_steps = 0;
        for (int i = 1; i < path_len; i++) {
            if (block_path[i] == block_path[i - 1] + 1) {
                continuous_steps++;
            }
        }
        double ratio = (double)continuous_steps / (path_len - 1);
        factors.continuity_score = ratio * 20.0;
        if (factors.continuity_score < 5.0 && path_len > 1) {
            factors.continuity_score = 8.0; /* Graph heuristic bonus */
        }
    }

    /* 4. Structural Validation (Max 15 pts) */
    if (sig) {
        if (strcmp(sig->type_name, "PDF") == 0) {
            if (contains_byte_pattern(data, data_len, "obj", 3) || 
                contains_byte_pattern(data, data_len, "stream", 6) || 
                contains_byte_pattern(data, data_len, "xref", 4)) {
                factors.structure_validity_score = 15.0;
            } else {
                factors.structure_validity_score = 8.0;
            }
        } else if (strcmp(sig->type_name, "PNG") == 0) {
            if (contains_byte_pattern(data, data_len, "IHDR", 4) || 
                contains_byte_pattern(data, data_len, "IDAT", 4)) {
                factors.structure_validity_score = 15.0;
            } else {
                factors.structure_validity_score = 10.0;
            }
        } else if (strcmp(sig->type_name, "JPEG") == 0) {
            if (data_len > 4 && data[0] == 0xFF && data[1] == 0xD8) {
                factors.structure_validity_score = 15.0;
            } else {
                factors.structure_validity_score = 7.0;
            }
        } else if (strcmp(sig->type_name, "TXT") == 0) {
            size_t printable = 0;
            for (size_t i = 0; i < data_len; i++) {
                if ((data[i] >= 32 && data[i] <= 126) || data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
                    printable++;
                }
            }
            factors.structure_validity_score = ((double)printable / data_len) * 15.0;
        } else {
            factors.structure_validity_score = 10.0;
        }
    } else {
        factors.structure_validity_score = 5.0;
    }

    /* 5. Metadata Remnant Clues (Max 10 pts) */
    if (has_metadata_hint) {
        factors.metadata_bonus_score = 10.0;
    } else {
        factors.metadata_bonus_score = 3.0;
    }

    /* Calculate Total */
    factors.total_confidence = factors.header_match_score + 
                               factors.footer_match_score + 
                               factors.continuity_score + 
                               factors.structure_validity_score + 
                               factors.metadata_bonus_score;

    if (factors.total_confidence > 100.0) factors.total_confidence = 100.0;

    /* Assign Qualitative Grade */
    if (factors.total_confidence >= 90.0) {
        strcpy(factors.confidence_grade, "HIGH (90-100%)");
    } else if (factors.total_confidence >= 60.0) {
        strcpy(factors.confidence_grade, "MEDIUM (60-89%)");
    } else {
        strcpy(factors.confidence_grade, "LOW (<60%)");
    }

    return factors;
}
