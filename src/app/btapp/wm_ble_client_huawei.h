#ifndef __WM_BLE_CLIENT_DEMO_HUAWEI_H__
#define __WM_BLE_CLIENT_DEMO_HUAWEI_H__

#include "wm_bt_def.h"

tls_bt_status_t wm_ble_client_huawei_init();

tls_bt_status_t wm_ble_client_huawei_deinit();

tls_bt_status_t wm_ble_client_huawei_scan(uint8_t start);

tls_bt_status_t wm_ble_client_huawei_search_service();


#endif

