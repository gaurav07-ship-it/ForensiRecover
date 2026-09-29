#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define FORENSI_VERSION "1.0.0"

/* Virtual Disk Configurations */
#define VDISK_BLOCK_SIZE 512          /* 512 bytes per block */
#define VDISK_TOTAL_BLOCKS 2048       /* 2048 blocks = 1,048,576 bytes (1 MB) */
#define VDISK_MAX_FILES 256           /* Maximum files in filesystem */
#define VDISK_MAX_FILENAME 64         /* Max file name length */
#define VDISK_MAGIC 0x464F5245        /* "FORE" magic identifier */

/* Max graph nodes for defragmentation */
#define MAX_GRAPH_NODES 256

/* ANSI Color Codes for terminal UI */
#define COLOR_RESET   "\x1b[0m"
#define COLOR_BOLD    "\x1b[1m"
#define COLOR_DIM     "\x1b[2m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_WHITE   "\x1b[37m"
#define COLOR_BG_RED  "\x1b[41m"
#define COLOR_BG_GREEN "\x1b[42m"
#define COLOR_BG_BLUE "\x1b[44m"

/* Standard Status Codes */
typedef enum {
    STATUS_OK = 0,
    STATUS_ERROR = -1,
    STATUS_NOT_FOUND = -2,
    STATUS_NO_SPACE = -3,
    STATUS_CORRUPTED = -4,
    STATUS_INVALID_PARAM = -5
} StatusCode;

#endif /* COMMON_H */
