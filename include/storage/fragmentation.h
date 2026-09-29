#ifndef FRAGMENTATION_H
#define FRAGMENTATION_H

#include "common.h"
#include "vdisk.h"

/**
 * @brief Fragmentation Strategy
 */
typedef enum {
    FRAG_STRATEGY_SCATTER,     /* Scatter blocks across random free regions */
    FRAG_STRATEGY_INTERLEAVE,  /* Interleave blocks with other files / dummy blocks */
    FRAG_STRATEGY_REVERSE,     /* Store non-contiguous blocks in reverse order */
    FRAG_STRATEGY_SPLIT_HALF   /* Split file into two halves separated by a large gap */
} FragStrategy;

/**
 * @brief Intentionally fragments an existing file on the virtual disk.
 * Moves blocks to non-contiguous locations, updates inode block table, and simulates
 * real-world disk fragmentation conditions for forensic recovery exercises.
 */
StatusCode vdisk_fragment_file(VirtualDisk *disk, const char *filename, FragStrategy strategy);

/**
 * @brief Fragments multiple files or creates an artificially heavily fragmented filesystem scenario.
 */
StatusCode vdisk_simulate_heavy_fragmentation(VirtualDisk *disk);

#endif /* FRAGMENTATION_H */
