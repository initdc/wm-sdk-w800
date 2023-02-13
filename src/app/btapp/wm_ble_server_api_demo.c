/*****************************************************************************
**
**  Name:           wm_bt_server_api_demo.c
**
**  Description:    This file contains the  implemention of ble demo server 
**
*****************************************************************************/


#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include "wm_config.h"

/*
* This file is a ble server demo:
* 1, How to create one ble server?
      a, register one ble server with specific uuid and callback functions structure;
      b, adding service in server register callback function;
      c, adding character in service adding callback function;
      d, adding descriptor in character adding callback function;
      e, repeat c or d until all character or descriptor added;
      f, start the servcie;
      g, configure advertise data and enable advertise in service enable callback function;
      h, Now you can access the service with app tool on phone.
  2, How to destroy the ble server?
      a, stop the service;
      b, delete the service in callback of stop service;
      c, unregister the server in callback of delete service;
      d, disable the advertisement in callback of deregister function;
  3, About the service configure, see structer of gattArray_t;
      in this demo, I enable one service uuid 0x6789.
      and configure two characters and one descriptor within this service.
      You can access the read/write/notification on phone with ble tool apps(eg. Nrf Connect, lightblue, etc...)
*/

#if (TLS_CONFIG_BLE == CFG_ON)

#include "wm_ble_server.h"
#include "wm_ble_gatt.h"
#include "wm_ble_server_api_demo.h"
#include "wm_bt_util.h"

/*
 * STRUCTURE DEFINITIONS
 ****************************************************************************************
 */

typedef enum
{
    ATTR_SERVICE = 1,
    ATTR_CHARACTISTIRC,
    ATTR_DESCRIPTOR_CCC,
    ATTR_NONE
} ATT_type;

typedef struct
{
    unsigned int numHandles;
    uint16_t uuid;
    ATT_type attrType;             /*filled by callback*/
    uint16_t attr_handle;  /*filled by callback*/
    uint16_t properties;
    uint16_t permissions;
} gattArray_t;


#define DEMO_SERVICE_UUID           (0x6789)
#define DEMO_SERVICE_INDEX          (0)
#define DEMO_PARAM_VALUE_INDEX      (1)
#define DEMO_KEY_VALUE_INDEX        (2)
#define DEMO_KEY_VALUE_CCCD_INDEX   (3)


#if 0
#define BTA_GATT_PERM_READ              GATT_PERM_READ              /* bit 0 -  0x0001 */
#define BTA_GATT_PERM_READ_ENCRYPTED    GATT_PERM_READ_ENCRYPTED    /* bit 1 -  0x0002 */
#define BTA_GATT_PERM_READ_ENC_MITM     GATT_PERM_READ_ENC_MITM     /* bit 2 -  0x0004 */
#define BTA_GATT_PERM_WRITE             GATT_PERM_WRITE             /* bit 4 -  0x0010 */
#define BTA_GATT_PERM_WRITE_ENCRYPTED   GATT_PERM_WRITE_ENCRYPTED   /* bit 5 -  0x0020 */
#define BTA_GATT_PERM_WRITE_ENC_MITM    GATT_PERM_WRITE_ENC_MITM    /* bit 6 -  0x0040 */
#define BTA_GATT_PERM_WRITE_SIGNED      GATT_PERM_WRITE_SIGNED      /* bit 7 -  0x0080 */
#define BTA_GATT_PERM_WRITE_SIGNED_MITM GATT_PERM_WRITE_SIGNED_MITM /* bit 8 -  0x0100 */
typedef uint16_t tBTA_GATT_PERM;

#define BTA_GATT_CHAR_PROP_BIT_BROADCAST    GATT_CHAR_PROP_BIT_BROADCAST    /* 0x01 */
#define BTA_GATT_CHAR_PROP_BIT_READ         GATT_CHAR_PROP_BIT_READ    /* 0x02 */
#define BTA_GATT_CHAR_PROP_BIT_WRITE_NR     GATT_CHAR_PROP_BIT_WRITE_NR    /* 0x04 */
#define BTA_GATT_CHAR_PROP_BIT_WRITE        GATT_CHAR_PROP_BIT_WRITE       /* 0x08 */
#define BTA_GATT_CHAR_PROP_BIT_NOTIFY       GATT_CHAR_PROP_BIT_NOTIFY      /* 0x10 */
#define BTA_GATT_CHAR_PROP_BIT_INDICATE     GATT_CHAR_PROP_BIT_INDICATE    /* 0x20 */
#define BTA_GATT_CHAR_PROP_BIT_AUTH         GATT_CHAR_PROP_BIT_AUTH        /* 0x40 */
#define BTA_GATT_CHAR_PROP_BIT_EXT_PROP     GATT_CHAR_PROP_BIT_EXT_PROP    /* 0x80 */

#endif

/*
 * GLOBAL VARIABLE DEFINITIONS
 ****************************************************************************************
 */

static gattArray_t gatt_uuid[] =
{
    {8,     0x1910, ATTR_SERVICE,       0, 0,    0},
    {0,     0x2B11, ATTR_CHARACTISTIRC, 0, 0x08, 0x11},
    {0,     0x2B10, ATTR_CHARACTISTIRC, 0, 0x10, 0x01},
    {0,     0x2902, ATTR_DESCRIPTOR_CCC, 0, 0,   0x11},
};

static int g_server_if;
static int g_conn_id = -1;
static tls_bt_addr_t g_addr;
static int g_trans_id;
static int g_offset;
static int g_service_index = 0;
static int demo_server_notification_timer_id = -1;

/*
 * LOCAL FUNCTION DEFINITIONS
 ****************************************************************************************
 */

static void dumphex(const char *info, uint8_t *p, int len)
{
	int i = 0;

	printf("%s", info);
	for(i = 0; i<len; i++)
	{
		printf("%02x ", p[i]);
	}
	printf("\r\n");
}

static void ble_server_adv_enable_cb(uint8_t triger_id)
{
	tls_ble_adv(true);
}
static void ble_server_cfg_and_enable_adv()
{
	tls_ble_dm_adv_data_t data;
	uint8_t adv_data[] = {0x0C, 0x07, 0x00, 0x10};

	memset(&data, 0, sizeof(data));
    data.set_scan_rsp = false;
    data.include_name = true;
    data.manufacturer_len = 4;
    memcpy(data.manufacturer_data, adv_data, 4);

    /*configure the user specific data, 0xFF field*/
	tls_ble_set_adv_data(&data);
	
    /*enable advertisement*/
	tls_dm_evt_triger(0, ble_server_adv_enable_cb);
	
}


static void ble_server_register_app_cb(int status, int server_if, uint16_t app_uuid)
{
    TLS_BT_APPL_TRACE_API("%s , status=%d\r\n", __FUNCTION__, status);

    if(status != 0)
    {
        return;
    }

    if(app_uuid != DEMO_SERVICE_UUID)
    {
    	TLS_BT_APPL_TRACE_ERROR("%s failed(app_uuid=0x%04x)\r\n", __FUNCTION__, app_uuid);
		return;
    }
    g_server_if = server_if;

	if(gatt_uuid[g_service_index].attrType != ATTR_SERVICE)
	{
		TLS_BT_APPL_TRACE_ERROR("%s failed(g_service_index=%d)\r\n", __FUNCTION__, g_service_index);
		return;
	}
    
    tls_ble_server_add_service(server_if, 1, 1, app_uuid16_to_uuid128(gatt_uuid[g_service_index].uuid), gatt_uuid[g_service_index].numHandles);
    
}
static void ble_server_deregister_app_cb(int status, int server_if)
{
    TLS_BT_APPL_TRACE_API("%s , status=%d\r\n", __FUNCTION__, status);
    g_service_index = 0;
    /*disable advertisement*/
    tls_ble_adv(false);
}

static void ble_server_connection_cb(int conn_id, int server_if, int connected, tls_bt_addr_t *bda)
{
    g_conn_id = conn_id;
    memcpy(&g_addr, bda, sizeof(tls_bt_addr_t));

    TLS_BT_APPL_TRACE_API("%s , connected=%d\r\n", __FUNCTION__, connected);

    if(connected)
    {
		/*Update connection parameter 5s timeout, if you need */
		//tls_ble_conn_parameter_update(bda, 16, 32, 0, 300);
    }
    else
    {
        g_conn_id = -1;
    }
}

static void ble_server_service_added_cb(int status, int server_if, int inst_id, bool is_primary, uint16_t app_uuid, int srvc_handle)
{
    TLS_BT_APPL_TRACE_API("%s , status=%d\r\n", __FUNCTION__, status);

    if(status != 0)
    {
        return;
    }
    gatt_uuid[g_service_index].attr_handle = srvc_handle;
	g_service_index++;
	if(gatt_uuid[g_service_index].attrType != ATTR_CHARACTISTIRC)
	{
		TLS_BT_APPL_TRACE_ERROR("tls_ble_server_add_characteristic failed(g_service_index=%d)\r\n", g_service_index);
		return;
	}
    
    tls_ble_server_add_characteristic(server_if, srvc_handle, app_uuid16_to_uuid128(gatt_uuid[g_service_index].uuid),  gatt_uuid[g_service_index].properties, gatt_uuid[g_service_index].permissions);
}

static void ble_server_included_service_added_cb(int status, int server_if,
        int srvc_handle,
        int incl_srvc_handle)
{
    TLS_BT_APPL_TRACE_API("%s , status=%d\r\n", __FUNCTION__, status);

}

static void ble_server_characteristic_added_cb(int status, int server_if, uint16_t char_id, int srvc_handle, int char_handle)
{
    TLS_BT_APPL_TRACE_API("%s , status=%d\r\n", __FUNCTION__, status);

    if(status != 0)
    {
        return;
    }

    gatt_uuid[g_service_index].attr_handle = char_handle;
	g_service_index++;

	if(gatt_uuid[g_service_index].attrType != ATTR_CHARACTISTIRC)
	{
		tls_ble_server_add_descriptor(server_if, srvc_handle, app_uuid16_to_uuid128(gatt_uuid[g_service_index].uuid), gatt_uuid[g_service_index].permissions);
	}else
	{
		tls_ble_server_add_characteristic(server_if, srvc_handle, app_uuid16_to_uuid128(gatt_uuid[g_service_index].uuid),  gatt_uuid[g_service_index].properties, gatt_uuid[g_service_index].permissions);
	}
}

	
    

static void ble_server_descriptor_added_cb(int status, int server_if,
                                    uint16_t descr_id, int srvc_handle,
                                    int descr_handle)
{
    TLS_BT_APPL_TRACE_API("%s , status=%d\r\n", __FUNCTION__, status);

    if(status != 0)
    {
        return;
    }

    gatt_uuid[g_service_index].attr_handle = descr_handle;
	g_service_index++;
    
	if(g_service_index > DEMO_KEY_VALUE_CCCD_INDEX)
	{
    	tls_ble_server_start_service(server_if, srvc_handle, WM_BLE_GATT_TRANSPORT_LE_BR_EDR);
	}else
	{
		tls_ble_server_add_characteristic(server_if, srvc_handle, app_uuid16_to_uuid128(gatt_uuid[g_service_index].uuid),  gatt_uuid[g_service_index].properties, gatt_uuid[g_service_index].permissions);
	}
}

static void ble_server_service_started_cb(int status, int server_if, int srvc_handle)
{
    TLS_BT_APPL_TRACE_API("%s , status=%d\r\n", __FUNCTION__, status);

    /*config advertise data and enable advertisement*/
    ble_server_cfg_and_enable_adv();
}

static void ble_server_service_stopped_cb(int status, int server_if, int srvc_handle)
{
    TLS_BT_APPL_TRACE_API("%s , status=%d\r\n", __FUNCTION__, status);

	tls_ble_server_delete_service(g_server_if, gatt_uuid[DEMO_SERVICE_INDEX].attr_handle);
}

static void ble_server_service_deleted_cb(int status, int server_if, int srvc_handle)
{
    TLS_BT_APPL_TRACE_API("%s , status=%d\r\n", __FUNCTION__, status);

	wm_ble_server_unregister_server(g_server_if);

}

static void ble_server_request_read_cb(int conn_id, int trans_id, tls_bt_addr_t *bda,
                                int attr_handle, int offset, bool is_long)
{
    TLS_BT_APPL_TRACE_API("%s , conn_id=%d, trans_id=%d, attr_handle=%d\r\n", __FUNCTION__, conn_id, trans_id, attr_handle);

    g_trans_id = trans_id;
    g_offset = offset;
    
    tls_ble_server_send_response(conn_id, trans_id, 0, offset, attr_handle, 0, "Hello", 5);
}

static void ble_demo_server_notification_started(int id)
{
	int len = 0;
	uint8_t ind[12];

	if(g_conn_id < 0) return;
	
	len = sprintf(ind, "BLE, %d\r\n", tls_os_get_time());

	tls_ble_server_send_indication(g_server_if,gatt_uuid[DEMO_KEY_VALUE_INDEX].attr_handle,g_conn_id,len,1,ind);
	
	tls_dm_start_timer(demo_server_notification_timer_id, 1000, ble_demo_server_notification_started);
}

static void ble_server_request_write_cb(int conn_id, int trans_id,
                                 tls_bt_addr_t *bda, int attr_handle,
                                 int offset, int length,
                                 bool need_rsp, bool is_prep, uint8_t *value)
{
    TLS_BT_APPL_TRACE_API("%s, conn_id=%d, trans_id=%d, attr_handle=%d\r\n", __FUNCTION__, conn_id, trans_id, attr_handle);
	
    if((value[0] == 0x00 || value[0] == 0x02 || value[0] == 0x01) && (attr_handle == gatt_uuid[DEMO_KEY_VALUE_CCCD_INDEX].attr_handle ))
    {
        TLS_BT_APPL_TRACE_DEBUG("This is an notification enable msg(%d),handle=%d\r\n", value[0], attr_handle);

		if(value[0] == 0x01)
		{
			demo_server_notification_timer_id = tls_dm_get_timer_id();
			tls_dm_start_timer(demo_server_notification_timer_id, 1000, ble_demo_server_notification_started);
		}else
		{
			if(demo_server_notification_timer_id >= 0)
			{
				tls_dm_stop_timer(demo_server_notification_timer_id);
				tls_dm_free_timer_id(demo_server_notification_timer_id);
			};
		}

        
        return;
    }
    
    dumphex("###write cb", value, length);
}

static void ble_server_request_exec_write_cb(int conn_id, int trans_id,
                                      tls_bt_addr_t *bda, int exec_write)
{
}

static void ble_server_response_confirmation_cb(int status, int conn_id, int trans_id)
{
}

static void ble_server_indication_sent_cb(int conn_id, int status)
{
}

static void ble_server_congestion_cb(int conn_id, bool congested)
{
}

static void ble_server_mtu_changed_cb(int conn_id, int mtu)
{
	TLS_BT_APPL_TRACE_DEBUG("ble_server_mtu_changed_cb, conn_id=%d, mtu=%d\r\n", conn_id, mtu);
}

static const wm_ble_server_callbacks_t servercb =
{
    ble_server_register_app_cb,
	ble_server_deregister_app_cb,
    ble_server_connection_cb,
    ble_server_service_added_cb,
    ble_server_included_service_added_cb,
    ble_server_characteristic_added_cb,
    ble_server_descriptor_added_cb,
    ble_server_service_started_cb,
    ble_server_service_stopped_cb,
    ble_server_service_deleted_cb,
    ble_server_request_read_cb,
    ble_server_request_write_cb,
    ble_server_request_exec_write_cb,
    ble_server_response_confirmation_cb,
    ble_server_indication_sent_cb,
    ble_server_congestion_cb,
    ble_server_mtu_changed_cb
};

tls_bt_status_t wm_ble_server_api_demo_init()
{
	tls_bt_status_t status;

    status = wm_ble_server_register_server(DEMO_SERVICE_UUID, &servercb);

	if(status == TLS_BT_STATUS_SUCCESS)
	{	
		TLS_BT_APPL_TRACE_DEBUG("### %s success\r\n", __FUNCTION__);
	}else
	{
		//strange logical, at cmd task , bt host task, priority leads to this situation;
		TLS_BT_APPL_TRACE_ERROR("### %s failed\r\n", __FUNCTION__);
	}
    
	return status;
}
tls_bt_status_t wm_ble_server_api_demo_deinit()
{
	tls_bt_status_t status;

    return tls_ble_server_stop_service(g_server_if, gatt_uuid[DEMO_SERVICE_INDEX].attr_handle);

}
tls_bt_status_t wm_ble_server_api_demo_connect(int status)
{
    return tls_ble_server_connect(g_server_if, (tls_bt_addr_t *)&g_addr, 1, 0);
}

tls_bt_status_t wm_ble_server_api_demo_disconnect(int status)
{
    return tls_ble_server_disconnect(g_server_if, (tls_bt_addr_t *)&g_addr, g_conn_id);
}

tls_bt_status_t wm_ble_server_api_demo_send_msg(uint8_t *ptr, int length)
{
    return tls_ble_server_send_indication(g_server_if, gatt_uuid[DEMO_KEY_VALUE_INDEX].attr_handle, g_conn_id, length, 1, ptr);
}

tls_bt_status_t wm_ble_server_api_demo_send_response(uint8_t *ptr, int length)
{
    return tls_ble_server_send_response(g_conn_id, g_trans_id,0, g_offset, gatt_uuid[DEMO_KEY_VALUE_INDEX].attr_handle, 0, ptr, length);
}


tls_bt_status_t wm_ble_server_api_demo_clean_up(int status)
{
    return tls_ble_server_delete_service(g_server_if, gatt_uuid[DEMO_SERVICE_INDEX].attr_handle);
}

tls_bt_status_t wm_ble_server_api_demo_disable(int status)
{
    return tls_ble_server_stop_service(g_server_if, gatt_uuid[DEMO_SERVICE_INDEX].attr_handle);
}
tls_bt_status_t wm_ble_server_api_demo_read_remote_rssi()
{
	return tls_dm_read_remote_rssi(&g_addr);
}

#endif

