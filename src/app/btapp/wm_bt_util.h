#ifndef __WM_BT_UTIL_H__
#define __WM_BT_UTIL_H__
#include <stdint.h>

#define TLS_TRACE_TYPE_ERROR            0x00000000
#define TLS_TRACE_TYPE_WARNING          0x00000001
#define TLS_TRACE_TYPE_API              0x00000002
#define TLS_TRACE_TYPE_EVENT            0x00000003
#define TLS_TRACE_TYPE_DEBUG            0x00000004

uint16_t app_uuid128_to_uuid16(tls_bt_uuid_t *uuid);

tls_bt_uuid_t * app_uuid16_to_uuid128(uint16_t uuid16);

/* define log for application */
#if 1
#define TLS_BT_APPL_TRACE_ERROR(...)				 {if (tls_appl_trace_level >= TLS_BT_LOG_ERROR) tls_bt_log(TLS_TRACE_TYPE_ERROR, ##__VA_ARGS__);}
#define TLS_BT_APPL_TRACE_WARNING(...) 				 {if (tls_appl_trace_level >= TLS_BT_LOG_WARNING) tls_bt_log(TLS_TRACE_TYPE_WARNING, ##__VA_ARGS__);}
#define TLS_BT_APPL_TRACE_API(...) 					 {if (tls_appl_trace_level >= TLS_BT_LOG_API) tls_bt_log( TLS_TRACE_TYPE_API, ##__VA_ARGS__);}
#define TLS_BT_APPL_TRACE_EVENT(...)			     {if (tls_appl_trace_level >= TLS_BT_LOG_EVENT) tls_bt_log(TLS_TRACE_TYPE_EVENT, ##__VA_ARGS__);}
#define TLS_BT_APPL_TRACE_DEBUG(...)				 {if (tls_appl_trace_level >= TLS_BT_LOG_DEBUG) tls_bt_log(TLS_TRACE_TYPE_DEBUG, ##__VA_ARGS__);}
#define TLS_BT_APPL_TRACE_VERBOSE(...) 				 {if (tls_appl_trace_level >= TLS_BT_LOG_VERBOSE) tls_bt_log(TLS_TRACE_TYPE_DEBUG, ##__VA_ARGS__);}
#else
#define TLS_BT_APPL_TRACE_ERROR(...)
#define TLS_BT_APPL_TRACE_WARNING(...)
#define TLS_BT_APPL_TRACE_API(...) 
#define TLS_BT_APPL_TRACE_EVENT(...)
#define TLS_BT_APPL_TRACE_DEBUG(...)
#define TLS_BT_APPL_TRACE_VERBOSE(...)

#endif
extern tls_bt_log_level_t tls_appl_trace_level;

void tls_bt_log(uint32_t trace_set_mask, const char *fmt_str, ...);
const char *tls_bt_host_evt_2_str(uint32_t event);
const char *tls_dm_evt_2_str(uint32_t event);
const char *tls_bt_status_2_str(uint32_t event);
const char *tls_gatt_evt_2_str(uint32_t event);





#endif
