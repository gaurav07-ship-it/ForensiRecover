#ifndef SIGNATURES_H
#define SIGNATURES_H

#include "common.h"

/**
 * @brief File Signature / Magic Bytes definition
 */
typedef struct {
    char type_name[16];           /* e.g., "PDF", "PNG", "JPEG", "BMP", "ZIP", "TXT" */
    char extension[8];            /* e.g., ".pdf", ".png", ".jpg", ".bmp", ".zip", ".txt" */
    uint8_t header_bytes[16];     /* Magic header bytes */
    size_t header_len;            /* Header signature length */
    uint8_t footer_bytes[16];     /* Magic footer bytes (if applicable) */
    size_t footer_len;            /* Footer length (0 if no fixed footer) */
    bool has_footer;              /* True if format uses an end-of-file marker */
} FileSignature;

/* Signature Database APIs */
void signatures_init_db(void);
const FileSignature* signatures_find_by_header(const uint8_t *block_data, size_t len);
const FileSignature* signatures_find_by_type(const char *type_name);
bool signatures_check_footer(const FileSignature *sig, const uint8_t *data, size_t len, size_t *out_offset);
const FileSignature* signatures_get_all(size_t *out_count);

#endif /* SIGNATURES_H */
