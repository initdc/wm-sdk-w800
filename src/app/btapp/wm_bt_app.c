/*****************************************************************************
**
**  Name:           wm_bt_app.c
**
**  Description:    This file contains the sample functions for bluetooth application
**
*****************************************************************************/
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include "wm_config.h"
#include "wm_bt_app.h"
#include "wm_bt.h"
#include "wm_bt_util.h"
#include "wm_pmu.h"

#if (TLS_CONFIG_BLE == CFG_ON)
    #include "wm_ble_server_wifi_app.h"
    #include "wm_ble_client_huawei.h"
    #include "wm_ble_server_api_demo.h"
#endif

#if (TLS_CONFIG_BR_EDR == CFG_ON)
    #include "wm_audio_sink.h"
	#include "wm_hfp_hsp_client.h"
#endif

/*
 * GLOBAL VARIABLE DEFINITIONS
 ****************************************************************************************
 */

static tls_bt_host_callback_t tls_bt_host_callback_at_ptr = NULL;
static tls_bt_state_t bt_adapter_state = WM_BT_STATE_OFF;
static uint8_t bt_enabled_by_at = 0;
static uint8_t host_enabled_by_at = 0;

/*
 * LOCAL FUNCTION DEFINITIONS
 ****************************************************************************************
 */

void app_adapter_state_changed_callback(tls_bt_state_t status)
{
	tls_bt_property_t btp;
	tls_bt_host_msg_t msg;
	msg.adapter_state_change.status = status;
	TLS_BT_APPL_TRACE_DEBUG("adapter status = %s\r\n", status==WM_BT_STATE_ON?"bt_state_on":"bt_state_off");


	bt_adapter_state = status;

	#if (TLS_CONFIG_BLE == CFG_ON)

    if(status == WM_BT_STATE_ON)
    {
    	TLS_BT_APPL_TRACE_VERBOSE("init base application\r\n");
        /* those funtions should be called basiclly*/
    	wm_ble_dm_init();
		wm_ble_client_init();
    	wm_ble_server_init(); 

		//at here , user run their own applications;
		
        //application_run();
    }else
    {
        TLS_BT_APPL_TRACE_VERBOSE("deinit base application\r\n");
    	wm_ble_dm_deinit();
		wm_ble_client_deinit();
        wm_ble_server_deinit();

        //here, user may free their application;

        //application_stop();
    }

    #endif
    #if (TLS_CONFIG_BR_EDR == CFG_ON)

    if(status == WM_BT_STATE_ON)
    {
        tls_bt_enable_a2dp_sink();
    }else
    {
        tls_bt_disable_a2dp_sink();
    }
	
    if(status == WM_BT_STATE_ON)
    {
        tls_bt_enable_hfp_client();
    }else
    {
        tls_bt_disable_hfp_client();
    }
    
	/*
    	BT_SCAN_MODE_NONE,                     0
    	BT_SCAN_MODE_CONNECTABLE,              1
    	BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE  2
    	*/
    if(status == WM_BT_STATE_ON)
    {
        btp.type = WM_BT_PROPERTY_ADAPTER_SCAN_MODE;
        btp.len = 1;
        btp.val = "2";
    	tls_bt_set_adapter_property(&btp, 0);
    }
    #endif
	
	/*Notify at level application, if registered*/
	if(tls_bt_host_callback_at_ptr)
	{
		tls_bt_host_callback_at_ptr(WM_BT_ADAPTER_STATE_CHG_EVT, &msg);
	}

}

void app_adapter_properties_callback(tls_bt_status_t status,
                                     int num_properties,
                                     tls_bt_property_t *properties)
{
	tls_bt_host_msg_t msg;
	msg.adapter_prop.status = status;
	msg.adapter_prop.num_properties = num_properties;
	msg.adapter_prop.properties = properties;
	/*Notify at level application, if registered*/
	if(tls_bt_host_callback_at_ptr)tls_bt_host_callback_at_ptr(WM_BT_ADAPTER_PROP_CHG_EVT, &msg);

    if(properties->type == WM_BT_PROPERTY_BDADDR)
    {
        //TLS_BT_APPL_TRACE_DEBUG("BT_PROPERTY_BDADDR\r\n");
        //btapp_dm_store_local_device_address(properties->val);
    }

    if(properties->type == WM_BT_PROPERTY_UUIDS)
    {
        //TLS_BT_APPL_TRACE_DEBUG("BT_PROPERTY_UUIDS\r\n");
    }
	if(properties->type == WM_BT_PROPERTY_BDNAME)
    {
        //TLS_BT_APPL_TRACE_DEBUG("BT_PROPERTY_NAME\r\n");
    }

    //TLS_BT_APPL_TRACE_DEBUG("app_adapter_properties_callback[%s]\r\n",dump_property_type(properties->type));
}

void app_remote_device_properties_callback(tls_bt_status_t status,
        tls_bt_addr_t *bd_addr,
        int num_properties,
        tls_bt_property_t *properties)
{
    int i = 0;
    //TLS_BT_APPL_TRACE_DEBUG("app_remote_device_properties_callback:\r\n");

    for(i = 0; i < num_properties; i++)
    {
        //TLS_BT_APPL_TRACE_DEBUG("\t%s\r\n", dump_property_type((properties + i)->type));
    }
}

void app_device_found_callback(int num_properties, tls_bt_property_t *properties)
{
    TLS_BT_APPL_TRACE_DEBUG("app_device_found_callback\r\n");
}
void app_discovery_state_changed_callback(tls_bt_discovery_state_t state)
{
    TLS_BT_APPL_TRACE_DEBUG("%s %s %d is called, attention..\r\n", __FILE__, __FUNCTION__, __LINE__);
}

void app_bond_state_changed_callback(tls_bt_status_t status,
                                     tls_bt_addr_t *remote_bd_addr,
                                     tls_bt_bond_state_t state)
{
    TLS_BT_APPL_TRACE_DEBUG("app_bond_state_changed_callback is called, state=(%d)\r\n", state);
}
void app_acl_state_changed_callback(tls_bt_status_t status, tls_bt_addr_t *remote_bd_addr,
                                    tls_bt_acl_state_t state)
{
    //TLS_BT_APPL_TRACE_DEBUG("%s %s %d is called, attention..\r\n", __FILE__, __FUNCTION__, __LINE__);
}
void app_dut_mode_recv_callback(uint16_t opcode, uint8_t *buf, uint8_t len)
{
    TLS_BT_APPL_TRACE_DEBUG("%s %s %d is called, attention..\r\n", __FILE__, __FUNCTION__, __LINE__);
}

void app_energy_info_callback(tls_bt_activity_energy_info *energy_info)
{
    TLS_BT_APPL_TRACE_DEBUG("%s %s %d is called, attention..\r\n", __FILE__, __FUNCTION__, __LINE__);
}

void app_ssp_request_callback(tls_bt_addr_t *remote_bd_addr,
                              tls_bt_bdname_t *bd_name,
                              uint32_t cod,
                              tls_bt_ssp_variant_t pairing_variant,
                              uint32_t pass_key)
{
    TLS_BT_APPL_TRACE_DEBUG("app_ssp_request_callback, attention...(%s) cod=0x%08x, ssp_variant=%d, pass_key=0x%08x\r\n", bd_name->name, cod, pairing_variant, pass_key);
	
	tls_bt_ssp_reply(remote_bd_addr, pairing_variant, 1, pass_key);
}

/** Bluetooth Legacy PinKey Request callback */
void app_pin_request_callback(tls_bt_addr_t *remote_bd_addr,
                          tls_bt_bdname_t *bd_name, uint32_t cod, uint8_t min_16_digit)
{
    TLS_BT_APPL_TRACE_DEBUG("app_request_callback\r\n");
}


static void tls_bt_host_callback_handler(tls_bt_host_evt_t evt, tls_bt_host_msg_t *msg)
{
	TLS_BT_APPL_TRACE_EVENT("%s, event:%s,%d\r\n", __FUNCTION__, tls_bt_host_evt_2_str(evt), evt);

	switch(evt)
	{
		case WM_BT_ADAPTER_STATE_CHG_EVT:
			app_adapter_state_changed_callback(msg->adapter_state_change.status);
			break;
		case WM_BT_ADAPTER_PROP_CHG_EVT:
			app_adapter_properties_callback(msg->adapter_prop.status, msg->adapter_prop.num_properties, msg->adapter_prop.properties);
			break;
		case WM_BT_RMT_DEVICE_PROP_EVT:
			app_remote_device_properties_callback(msg->remote_device_prop.status, msg->remote_device_prop.address, 
									msg->remote_device_prop.num_properties, msg->remote_device_prop.properties);
			break;
	   case WM_BT_DEVICE_FOUND_EVT:
	   		app_device_found_callback(msg->device_found.num_properties, msg->device_found.properties);
			break;
	 	case WM_BT_DISCOVERY_STATE_CHG_EVT:
			app_discovery_state_changed_callback(msg->discovery_state.state);
			break;
		case WM_BT_BOND_STATE_CHG_EVT:
			app_bond_state_changed_callback(msg->bond_state.status, msg->bond_state.remote_bd_addr, msg->bond_state.state);
			break;
		case WM_BT_ACL_STATE_CHG_EVT:
			app_acl_state_changed_callback(msg->acl_state.status, msg->acl_state.remote_address, msg->acl_state.state);
			break;
		case WM_BT_ENERGY_INFO_EVT:
			app_energy_info_callback(msg->energy_info.energy_info);
			break;
		case WM_BT_SSP_REQUEST_EVT:
			app_ssp_request_callback(msg->ssp_request.remote_bd_addr, msg->ssp_request.bd_name, msg->ssp_request.cod, msg->ssp_request.pairing_variant, msg->ssp_request.pass_key);
			break;
		case WM_BT_PIN_REQUEST_EVT:
			app_pin_request_callback(msg->pin_request.remote_bd_addr, msg->pin_request.bd_name, msg->pin_request.cod, msg->pin_request.min_16_digit);
			break;
	}
	
}


void tls_bt_entry()
{
    //tls_bt_enable(tls_bt_host_callback_handler, NULL, TLS_BT_LOG_NONE);
}

void tls_bt_exit()
{
    //tls_bt_disable();
}

tls_bt_status_t at_bt_enable(int uart_no, tls_bt_log_level_t log_level, tls_bt_host_callback_t at_callback_ptr)
{
	tls_bt_status_t status;
	bt_enabled_by_at = 1;
	tls_appl_trace_level = log_level;
    tls_bt_hci_if_t hci_if;
	
	if(host_enabled_by_at) 
	{
		TLS_BT_APPL_TRACE_WARNING("bt host stack enabled by at+btcfghost=1, please do at+btcfghost=0, then continue...\r\n");
		return TLS_BT_STATUS_UNSUPPORTED;
    }
	if(tls_bt_host_callback_at_ptr)
	{
		TLS_BT_APPL_TRACE_WARNING("bt system already enabled\r\n");
		return TLS_BT_STATUS_DONE;
	}

	tls_open_peripheral_clock(TLS_PERIPHERAL_TYPE_BT);

	tls_bt_host_callback_at_ptr = at_callback_ptr;
	
	TLS_BT_APPL_TRACE_VERBOSE("bt system running, uart_no=%d, log_level=%d\r\n", uart_no, log_level);

	hci_if.uart_index = uart_no;
	hci_if.band_rate = 115200;
	hci_if.data_bit = 8;
	hci_if.stop_bit = 1;
	hci_if.verify_bit = 0;
	
	status = tls_bt_enable(tls_bt_host_callback_handler, &hci_if, TLS_BT_LOG_NONE);
	if((status != TLS_BT_STATUS_SUCCESS) &&(status != TLS_BT_STATUS_DONE) )
	{
		tls_bt_host_callback_at_ptr = NULL;
		TLS_BT_APPL_TRACE_ERROR("tls_bt_enable, ret:%s,%d\r\n", tls_bt_status_2_str(status),status);
	}

	return status;
}
tls_bt_status_t at_bt_destroy()
{
	tls_bt_status_t status;
	if(host_enabled_by_at)
	{
		TLS_BT_APPL_TRACE_WARNING("do not support, bt system enabled by at+btcfghost=1,n\r\n");
		return TLS_BT_STATUS_UNSUPPORTED;
	}
	bt_enabled_by_at = 0;
	if(tls_bt_host_callback_at_ptr == NULL)
	{
		TLS_BT_APPL_TRACE_WARNING("bt system already destroyed\r\n");
		return TLS_BT_STATUS_DONE;
	}
	
	TLS_BT_APPL_TRACE_VERBOSE("bt system destroy\r\n");
	status = tls_bt_disable();
	if((status != TLS_BT_STATUS_SUCCESS) && (status != TLS_BT_STATUS_DONE))
	{
		TLS_BT_APPL_TRACE_ERROR("tls_bt_disable, ret:%s,%d\r\n", tls_bt_status_2_str(status),status);
	}

	tls_close_peripheral_clock(TLS_PERIPHERAL_TYPE_BT);
	
	return TLS_BT_STATUS_SUCCESS;
}


tls_bt_status_t at_bt_enable_host(tls_bt_log_level_t log_level, tls_bt_host_callback_t at_callback_ptr)
{
	tls_bt_status_t status;
	tls_bt_ctrl_status_t ctrl_status;

	ctrl_status = tls_bt_controller_get_status();
	if(ctrl_status == TLS_BT_CTRL_IDLE)
	{
		TLS_BT_APPL_TRACE_WARNING("please enable controller first\r\n");
		return TLS_BT_STATUS_NOT_READY;
	}
	TLS_BT_APPL_TRACE_VERBOSE("run bluedroid\r\n");
	host_enabled_by_at = 1;
    if(bt_enabled_by_at) 
	{
		TLS_BT_APPL_TRACE_WARNING("bt host stack enabled by at+bten=1,n\r\n");
		return TLS_BT_STATUS_UNSUPPORTED;
    }
	
	tls_appl_trace_level = log_level;
	if(tls_bt_host_callback_at_ptr)
	{
		TLS_BT_APPL_TRACE_WARNING("bluedroid already enabled\r\n");
		return TLS_BT_STATUS_DONE;
	}
	tls_bt_host_callback_at_ptr = at_callback_ptr;
	status = tls_bt_host_enable(tls_bt_host_callback_handler, log_level);
	if(status != TLS_BT_STATUS_SUCCESS)
	{
		tls_bt_host_callback_at_ptr = NULL;
		TLS_BT_APPL_TRACE_ERROR("tls_bt_host_enable, ret:%s,%d\r\n", tls_bt_status_2_str(status),status);
	}
	
	return status;
}

tls_bt_status_t at_bt_destroy_host()
{
	tls_bt_status_t status;
	if(bt_enabled_by_at)
	{
		TLS_BT_APPL_TRACE_WARNING("do not support, bt system enabled by at+bten=1,n\r\n");
		return TLS_BT_STATUS_UNSUPPORTED;
	}
    host_enabled_by_at = 0;
	TLS_BT_APPL_TRACE_VERBOSE("stop bluedroid\r\n");
	if(tls_bt_host_callback_at_ptr == NULL)
	{
		TLS_BT_APPL_TRACE_WARNING("bluedroid already disabled\r\n");
		return TLS_BT_STATUS_DONE;
	}
	status = tls_bt_host_disable();
	if(status != TLS_BT_STATUS_SUCCESS)
	{
		TLS_BT_APPL_TRACE_WARNING("tls_bt_host_disable, ret:%s,%d\r\n", tls_bt_status_2_str(status),status);
		if(status == TLS_BT_STATUS_NOT_READY)
			return TLS_BT_STATUS_SUCCESS;
	}
	return status;
}
tls_bt_status_t at_bt_cleanup_host()
{
	tls_bt_status_t status;
	TLS_BT_APPL_TRACE_DEBUG("cleanup bluedroid\r\n");
	tls_bt_host_callback_at_ptr = NULL;
	status = tls_bt_host_cleanup();
	if(status != TLS_BT_STATUS_SUCCESS)
	{
		TLS_BT_APPL_TRACE_ERROR("tls_bt_host_cleanup, ret:%s,%d\r\n", tls_bt_status_2_str(status),status);
	}
	return status;
}

void bt_run_btc()
{
	TLS_BT_APPL_TRACE_VERBOSE("run controller\r\n");
	tls_bt_ctrl_enable(NULL, TLS_BT_LOG_NONE);	
}
void bt_clean_btc()
{
	TLS_BT_APPL_TRACE_VERBOSE("cleanup controller stack\r\n");
	tls_bt_ctrl_disable();	
}

/*
*bluetooth api demo 
*/
int demo_bt_enable()
{
	tls_bt_status_t status;
    uint8_t uart_no = 1;    //default we use uart 1 for testing;
	tls_appl_trace_level = TLS_BT_LOG_VERBOSE;
    tls_bt_hci_if_t hci_if;

    if(bt_adapter_state == WM_BT_STATE_ON)
    {
       TLS_BT_APPL_TRACE_VERBOSE("bt system enabled already"); 
       return TLS_BT_STATUS_SUCCESS;
    }
	
	tls_open_peripheral_clock(TLS_PERIPHERAL_TYPE_BT);
	
	TLS_BT_APPL_TRACE_VERBOSE("bt system running, uart_no=%d, log_level=%d\r\n", uart_no, tls_appl_trace_level);

	hci_if.uart_index = uart_no;
	hci_if.band_rate = 115200;
	hci_if.data_bit = 8;
	hci_if.stop_bit = 1;
	hci_if.verify_bit = 0;
	
	status = tls_bt_enable(tls_bt_host_callback_handler, &hci_if, TLS_BT_LOG_NONE);
	if((status != TLS_BT_STATUS_SUCCESS) &&(status != TLS_BT_STATUS_DONE) )
	{
		TLS_BT_APPL_TRACE_ERROR("tls_bt_enable, ret:%s,%d\r\n", tls_bt_status_2_str(status),status);
	}

	return status;    
}

int demo_bt_destroy()
{

	tls_bt_status_t status;
	
	TLS_BT_APPL_TRACE_VERBOSE("bt system destroy\r\n");

    if(bt_adapter_state == WM_BT_STATE_OFF)
    {
       TLS_BT_APPL_TRACE_VERBOSE("bt system destroyed already"); 
       return TLS_BT_STATUS_SUCCESS;
    }    
	status = tls_bt_disable();
	if((status != TLS_BT_STATUS_SUCCESS) && (status != TLS_BT_STATUS_DONE))
	{
		TLS_BT_APPL_TRACE_ERROR("tls_bt_disable, ret:%s,%d\r\n", tls_bt_status_2_str(status),status);
	}

	tls_close_peripheral_clock(TLS_PERIPHERAL_TYPE_BT);

    while(bt_adapter_state == WM_BT_STATE_ON)
    {
        tls_os_time_delay(500);
    }

    TLS_BT_APPL_TRACE_VERBOSE("bt system cleanup host\r\n");

    status = tls_bt_host_cleanup();
	if(status != TLS_BT_STATUS_SUCCESS)
	{
		TLS_BT_APPL_TRACE_ERROR("tls_bt_host_cleanup, ret:%s,%d\r\n", tls_bt_status_2_str(status),status);
	}
	
	return status;  
}

int demo_ble_server_on()
{
    if(bt_adapter_state == WM_BT_STATE_OFF)
    {
       TLS_BT_APPL_TRACE_VERBOSE("please enable bluetooth system first\r\n"); 
       return -1;
    }   
    wm_ble_server_api_demo_init(); 
    return 0;
}
int demo_ble_server_off()
{
    if(bt_adapter_state == WM_BT_STATE_OFF)
    {
       TLS_BT_APPL_TRACE_VERBOSE("bluetooth system stopped\r\n"); 
       return -1;
    } 

    wm_ble_server_api_demo_deinit(); 

    return 0;
}


