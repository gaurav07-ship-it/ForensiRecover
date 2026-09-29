#ifndef DEMO_SCENARIOS_H
#define DEMO_SCENARIOS_H

#include "common.h"
#include "storage/vdisk.h"

/**
 * @brief Runs the complete automated 9-step end-to-end Forensic Recovery simulation:
 * 1. Create Files (PDF, PNG, JPG, TXT)
 * 2. Store on Virtual Disk (Block allocation & Inodes)
 * 3. Delete selected files (Metadata detached, data remnants retained)
 * 4. Fragment remaining & deleted files (Scatter blocks across non-contiguous regions)
 * 5. Scan virtual disk (FIFO Queue deep inspection)
 * 6. Identify signatures (Magic bytes database)
 * 7. Recover fragments (Graph path exploration & Max-Heap ranking)
 * 8. Verify integrity (SHA-256 and CRC-32 hash comparison)
 * 9. Generate forensic report (Evidence store BST & Investigation Report)
 */
void demo_run_full_simulation(VirtualDisk *disk);

/**
 * @brief Creates sample files on the host disk for manual import testing.
 */
void demo_create_sample_files(void);

#endif /* DEMO_SCENARIOS_H */
