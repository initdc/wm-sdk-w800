#ifndef __WM_BLE_DEMO_CLI_H__
#define __WM_BLE_DEMO_CLI_H__
#include "wm_bt_def.h"

tls_bt_status_t wm_demo_cli_init(uint16_t uuid, tls_ble_callback_t at_cb_ptr);
tls_bt_status_t wm_demo_cli_deinit(int client_if);

#endif

