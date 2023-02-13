#ifndef __WM_BLE_SERVER_DEMO_H__
#define __WM_BLE_SERVER_DEMO_H__
#include "wm_bt.h"

tls_bt_status_t wm_ble_server_api_demo_init(tls_ble_output_func_ptr output_func_ptr);
tls_bt_status_t wm_ble_server_api_demo_deinit();
tls_bt_status_t wm_ble_server_api_demo_connect(int status);
tls_bt_status_t wm_ble_server_api_demo_disconnect(int status);
tls_bt_status_t wm_ble_server_api_demo_send_msg(uint8_t *ptr, int length);
tls_bt_status_t wm_ble_server_api_demo_send_response(uint8_t *ptr, int length);
tls_bt_status_t wm_ble_server_api_demo_clean_up(int status);
tls_bt_status_t wm_ble_server_api_demo_disable(int status);
tls_bt_status_t wm_ble_server_api_demo_read_remote_rssi();
uint32_t wm_ble_server_api_demo_get_mtu();


#endif

