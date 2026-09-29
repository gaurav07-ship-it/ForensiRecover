#include "forensics/signatures.h"

/**
 * @file signatures.c
 * @brief File Signature / Magic Bytes Database
 * 
 * Provides known file headers and footers for forensic signature carving.
 */

static FileSignature g_signatures[] = {
    {
        .type_name = "PDF",
        .extension = ".pdf",
        .header_bytes = { 0x25, 0x50, 0x44, 0x46, 0x2D }, /* "%PDF-" */
        .header_len = 5,
        .footer_bytes = { 0x25, 0x25, 0x45, 0x4F, 0x46 }, /* "%%EOF" */
        .footer_len = 5,
        .has_footer = true
    },
    {
        .type_name = "PNG",
        .extension = ".png",
        .header_bytes = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, /* "\x89PNG\r\n\x1a\n" */
        .header_len = 8,
        .footer_bytes = { 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82 }, /* "IEND\xAE\x42\x60\x82" */
        .footer_len = 8,
        .has_footer = true
    },
    {
        .type_name = "JPEG",
        .extension = ".jpg",
        .header_bytes = { 0xFF, 0xD8, 0xFF }, /* "\xFF\xD8\xFF" */
        .header_len = 3,
        .footer_bytes = { 0xFF, 0xD9 },       /* "\xFF\xD9" */
        .footer_len = 2,
        .has_footer = true
    },
    {
        .type_name = "ZIP",
        .extension = ".zip",
        .header_bytes = { 0x50, 0x4B, 0x03, 0x04 }, /* "PK\x03\x04" */
        .header_len = 4,
        .footer_bytes = { 0x50, 0x4B, 0x05, 0x06 }, /* "PK\x05\x06" */
        .footer_len = 4,
        .has_footer = true
    },
    {
        .type_name = "BMP",
        .extension = ".bmp",
        .header_bytes = { 0x42, 0x4D }, /* "BM" */
        .header_len = 2,
        .footer_bytes = { 0 },
        .footer_len = 0,
        .has_footer = false
    },
    {
        .type_name = "TXT",
        .extension = ".txt",
        .header_bytes = { 0 }, /* ASCII heuristic detected */
        .header_len = 0,
        .footer_bytes = { 0 },
        .footer_len = 0,
        .has_footer = false
    }
};

static const size_t g_num_signatures = sizeof(g_signatures) / sizeof(g_signatures[0]);

void signatures_init_db(void) {
    /* Ready static database */
}

const FileSignature* signatures_find_by_header(const uint8_t *block_data, size_t len) {
    if (!block_data || len == 0) return NULL;

    for (size_t i = 0; i < g_num_signatures; i++) {
        if (g_signatures[i].header_len > 0 && len >= g_signatures[i].header_len) {
            if (memcmp(block_data, g_signatures[i].header_bytes, g_signatures[i].header_len) == 0) {
                return &g_signatures[i];
            }
        }
    }

    /* ASCII / UTF-8 Text File Heuristic Check */
    bool is_text = true;
    size_t printable_count = 0;
    size_t check_len = len < 64 ? len : 64;

    for (size_t k = 0; k < check_len; k++) {
        uint8_t c = block_data[k];
        if (c == '\0') {
            is_text = false;
            break;
        }
        if ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t') {
            printable_count++;
        } else {
            is_text = false;
            break;
        }
    }

    if (is_text && printable_count >= 8) {
        return signatures_find_by_type("TXT");
    }

    return NULL;
}

const FileSignature* signatures_find_by_type(const char *type_name) {
    if (!type_name) return NULL;
    for (size_t i = 0; i < g_num_signatures; i++) {
        if (strcmp(g_signatures[i].type_name, type_name) == 0) {
            return &g_signatures[i];
        }
    }
    return NULL;
}

bool signatures_check_footer(const FileSignature *sig, const uint8_t *data, size_t len, size_t *out_offset) {
    if (!sig || !data || !sig->has_footer || sig->footer_len == 0 || len < sig->footer_len) {
        return false;
    }

    for (size_t i = 0; i <= len - sig->footer_len; i++) {
        if (memcmp(&data[i], sig->footer_bytes, sig->footer_len) == 0) {
            if (out_offset) {
                *out_offset = i + sig->footer_len;
            }
            return true;
        }
    }
    return false;
}

const FileSignature* signatures_get_all(size_t *out_count) {
    if (out_count) *out_count = g_num_signatures;
    return g_signatures;
}
