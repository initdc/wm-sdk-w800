#ifndef __WM_BLE_WIFI_PROF_H__
#define __WM_BLE_WIFI_PROF_H__

typedef tls_bt_status_t (*op_exec_write_callback)(int exec);
typedef tls_bt_status_t (*op_write_callback)(int offset, uint8_t *ptr, int length, bool b_prep);
typedef tls_bt_status_t (*op_read_callback)(int offset);
typedef tls_bt_status_t (*op_disconnected_callback)(int status);
typedef tls_bt_status_t (*op_connected_callback)(int status);
typedef tls_bt_status_t (*op_indication_callback)(int status);
typedef tls_bt_status_t (*op_service_enabled_callback)(int status);


typedef struct
{
    size_t size;

    op_service_enabled_callback enabled_cb;

    op_connected_callback connected_cb;

    op_disconnected_callback disconnected_cb;

    op_read_callback read_cb;

    op_write_callback write_cb;

    op_exec_write_callback exec_write_cb;

    op_indication_callback indication_cb;

} wm_ble_wifi_prof_callbacks_t;

tls_bt_status_t wm_wifi_prof_init(wm_ble_wifi_prof_callbacks_t *callback);
tls_bt_status_t wm_wifi_prof_deinit();
tls_bt_status_t wm_wifi_prof_connect(int status);
tls_bt_status_t wm_wifi_prof_disconnect(int status);
tls_bt_status_t wm_wifi_prof_send_msg(uint8_t *ptr, int length);
tls_bt_status_t wm_wifi_prof_send_response(uint8_t *ptr, int length);
tls_bt_status_t wm_wifi_prof_clean_up(int status);
tls_bt_status_t wm_wifi_prof_disable(int status);

#endif

