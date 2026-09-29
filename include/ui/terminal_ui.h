#ifndef TERMINAL_UI_H
#define TERMINAL_UI_H

#include "common.h"
#include "storage/vdisk.h"

void ui_init(void);
void ui_clear_screen(void);
void ui_print_banner(void);
void ui_print_header(const char *title);
void ui_print_menu(void);
void ui_pause(void);
void ui_print_hex_dump(const uint8_t *data, size_t size, size_t max_bytes);
void ui_print_block_matrix(const VirtualDisk *disk, int start_block, int count);
void ui_print_ds_summary(void);

#endif /* TERMINAL_UI_H */
