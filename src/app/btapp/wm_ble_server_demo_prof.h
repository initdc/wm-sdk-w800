#ifndef __WM_BLE_DEMO_SERVER_PROF_H__
#define __WM_BLE_DEMO_SERVER_PROF_H__
tls_bt_status_t wm_demo_prof_init(uint16_t uuid, tls_ble_callback_t at_cb_ptr);
tls_bt_status_t wm_demo_prof_deinit(int server_if);

#endif


