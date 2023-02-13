#ifndef __WM_BLE_CLIENT_DEMO_HUAWEI_H__
#define __WM_BLE_CLIENT_DEMO_HUAWEI_H__

#include "wm_bt_def.h"

tls_bt_status_t wm_ble_client_demo_api_init(tls_ble_output_func_ptr output_func_ptr);

tls_bt_status_t wm_ble_client_demo_api_deinit();

tls_bt_status_t wm_ble_client_api_demo_send_msg(uint8_t *ptr, int length);


#endif

