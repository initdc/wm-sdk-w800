#ifndef __WM_BLE_DM_H__
#define __WM_BLE_DM_H__
#include "wm_bt_def.h"
/*Init function, register an device manager from btif_gatt*/
tls_bt_status_t wm_ble_dm_init();

/** Config the advertisemnt data or paramerters then start advertisement*/
unsigned int bt_enable_adv();

/**stop advertisement*/
unsigned int bt_disable_adv();

tls_bt_status_t wm_ble_register_report_evt(tls_ble_dm_evt_t rpt_evt,  tls_ble_dm_callback_t rpt_callback);
tls_bt_status_t wm_ble_deregister_report_evt(tls_ble_dm_evt_t rpt_evt,  tls_ble_dm_callback_t rpt_callback);

#endif
