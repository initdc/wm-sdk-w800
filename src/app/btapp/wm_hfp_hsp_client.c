
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#include "wm_config.h"

#if (TLS_CONFIG_BR_EDR == CFG_ON)

#include "wm_hfp_hsp_client.h"
#include "btif_util.h"
#include "bt_hf_client.h"
const char *dump_hf_client_call_state(bthf_client_call_state_t event);
const char *dump_hf_client_call(bthf_client_call_t event);
const char *dump_hf_client_callsetup(bthf_client_callsetup_t event);
const char *dump_hf_client_callheld(bthf_client_callheld_t event);
const char *dump_hf_client_resp_and_hold(bthf_client_resp_and_hold_t event);
const char *dump_hf_client_call_direction(uint16_t event);
const char *dump_hf_client_conn_state(bthf_client_connection_state_t event);
const char *dump_hf_client_audio_state(bthf_client_audio_state_t event);



void hfp_client_connection_state_cb(bthf_client_connection_state_t state,
                                    unsigned int peer_feat,
                                    unsigned int chld_feat,
                                    tls_bt_addr_t *bd_addr)
{
    hci_dbg_msg("hfp_client_connection_state_cb: state=%s\r\n", dump_hf_client_conn_state(state));
}

void hfp_client_audio_state_cb(bthf_client_audio_state_t state,
                               tls_bt_addr_t *bd_addr)
{
    hci_dbg_msg("hfp_client_audio_state_cb: state=%s\r\n", dump_hf_client_audio_state(state));
}

void hfp_client_vr_cmd_cb(bthf_client_vr_state_t state)
{
    hci_dbg_msg("hfp_client_vr_cmd_cb: state=%d\r\n", state);
}

/** Callback for network state change
 */
void hfp_client_network_state_cb(bthf_client_network_state_t state)
{
    hci_dbg_msg("hfp_client_network_state_cb: state=%d\r\n", state);
    dbg_0_mem(8);
}

/** Callback for network roaming status change
 */
void hfp_client_network_roaming_cb(bthf_client_service_type_t type)
{
    hci_dbg_msg("hfp_client_network_roaming_cb, type=%d\r\n", type);
}

/** Callback for signal strength indication
 */
void hfp_client_network_signal_cb(int signal_strength)
{
    hci_dbg_msg("hfp_client_network_signal_cb(%d)\r\n", signal_strength);
}

/** Callback for battery level indication
 */
void hfp_client_battery_level_cb(int battery_level)
{
    hci_dbg_msg("hfp_client_battery_level_cb, battery_level=%d\r\n", battery_level);
    dbg_0_mem(9);
}

/** Callback for current operator name
 */
void hfp_client_current_operator_cb(const char *name)
{
    hci_dbg_msg("hfp_client_current_operator_cb, name=%s\r\n", name);
}

/** Callback for call indicator
 */
void hfp_client_call_cb(bthf_client_call_t call)
{
    hci_dbg_msg("hfp_client_call_cb,call=%s\r\n", dump_hf_client_call(call));
    dbg_0_mem(6);
}

/** Callback for callsetup indicator
 */
void hfp_client_callsetup_cb(bthf_client_callsetup_t callsetup)
{
    hci_dbg_msg("hfp_client_callsetup_cb, callsetup=%s\r\n", dump_hf_client_callsetup(callsetup));
    dbg_0_mem(7);
}

/** Callback for callheld indicator
 */
void hfp_client_callheld_cb(bthf_client_callheld_t callheld)
{
    hci_dbg_msg("hfp_client_callheld_cb, callheld=%s\r\n", dump_hf_client_callheld(callheld));
    dbg_0_mem(0x0A);
}

/** Callback for response and hold
 */
void hfp_client_resp_and_hold_cb(bthf_client_resp_and_hold_t resp_and_hold)
{
    hci_dbg_msg("hfp_client_resp_and_hold_cb, resp_and_hold=%s\r\n", dump_hf_client_resp_and_hold(resp_and_hold));
}

/** Callback for Calling Line Identification notification
 *  Will be called only when there is an incoming call and number is provided.
 */
void hfp_client_clip_cb(const char *number)
{
    hci_dbg_msg("hfp_client_clip_cb, number=%s\r\n", number);
}

/**
 * Callback for Call Waiting notification
 */
void hfp_client_call_waiting_cb(const char *number)
{
    hci_dbg_msg("hfp_client_call_waiting_cb, number=%s\r\n", number);
}

/**
 *  Callback for listing current calls. Can be called multiple time.
 *  If number is unknown NULL is passed.
 */
void hfp_client_current_calls_cb(int index, bthf_client_call_direction_t dir,
                                 bthf_client_call_state_t state,
                                 bthf_client_call_mpty_type_t mpty,
                                 const char *number)
{
    hci_dbg_msg("hfp_client_current_calls_cb, bthf_client_call_state_t=%s, number=%s\r\n", dump_hf_client_call_state(state), number);
}

/** Callback for audio volume change
 */
void hfp_client_volume_change_cb(bthf_client_volume_type_t type, int volume)
{
    hci_dbg_msg("hfp_client_volume_change_cb, type=%d, volume=%d\r\n", type, volume);
}

/** Callback for command complete event
 *  cme is valid only for BTHF_CLIENT_CMD_COMPLETE_ERROR_CME type
 */
void hfp_client_cmd_complete_cb(bthf_client_cmd_complete_t type, int cme)
{
    hci_dbg_msg("hfp_client_cmd_complete_cb, type=%d\r\n", type);
}

/** Callback for subscriber information
 */
void hfp_client_subscriber_info_cb(const char *name,
                                   bthf_client_subscriber_service_type_t type)
{
    hci_dbg_msg("hfp_client_subscriber_info_cb, name=%s, type=%d\r\n", name, type);
}

/** Callback for in-band ring tone settings
 */
void hfp_client_in_band_ring_tone_cb(bthf_client_in_band_ring_state_t state)
{
    hci_dbg_msg("hfp_client_in_band_ring_tone_cb, in_band_ring_state=%d\r\n", state);
}

/**
 * Callback for requested number from AG
 */
void hfp_client_last_voice_tag_number_cb(const char *number)
{
    hci_dbg_msg("hfp_client_last_voice_tag_number_cb\r\n");
}

/**
 * Callback for sending ring indication to app
 */
void hfp_client_ring_indication_cb(void)
{
    hci_dbg_msg("hfp_client_ring_indication_cb\r\n");
}

static bthf_client_callbacks_t sBluetoothHfpCallbacks =
{
    sizeof(bthf_client_callbacks_t),
    hfp_client_connection_state_cb,
    hfp_client_audio_state_cb,
    hfp_client_vr_cmd_cb,
    hfp_client_network_state_cb,
    hfp_client_network_roaming_cb,
    hfp_client_network_signal_cb,
    hfp_client_battery_level_cb,
    hfp_client_current_operator_cb,
    hfp_client_call_cb,
    hfp_client_callsetup_cb,
    hfp_client_callheld_cb,
    hfp_client_resp_and_hold_cb,
    hfp_client_clip_cb,
    hfp_client_call_waiting_cb,
    hfp_client_current_calls_cb,
    hfp_client_volume_change_cb,
    hfp_client_cmd_complete_cb,
    hfp_client_subscriber_info_cb,
    hfp_client_in_band_ring_tone_cb,
    hfp_client_last_voice_tag_number_cb,
    hfp_client_ring_indication_cb
};


void enable_hfp_hsp_client()
{
    bt_interface_t *btif = NULL;
    btif = (bt_interface_t *)bluetooth__get_bluetooth_interface();
    assert(btif != NULL);
    const bthf_client_interface_t *itf = (bthf_client_interface_t *)btif->get_profile_interface("handsfree_client");
    itf->init(&sBluetoothHfpCallbacks);
}


const char *dump_hf_client_call_state(bthf_client_call_state_t event)
{
    switch(event)
    {
            CASE_RETURN_STR(BTHF_CLIENT_CALL_STATE_ACTIVE)
            CASE_RETURN_STR(BTHF_CLIENT_CALL_STATE_HELD)
            CASE_RETURN_STR(BTHF_CLIENT_CALL_STATE_DIALING)
            CASE_RETURN_STR(BTHF_CLIENT_CALL_STATE_ALERTING)
            CASE_RETURN_STR(BTHF_CLIENT_CALL_STATE_INCOMING)
            CASE_RETURN_STR(BTHF_CLIENT_CALL_STATE_WAITING)
            CASE_RETURN_STR(BTHF_CLIENT_CALL_STATE_HELD_BY_RESP_HOLD)

        default:
            return "UNKNOWN MSG ID(call_state)";
    }
}



const char *dump_hf_client_call(bthf_client_call_t event)
{
    switch(event)
    {
            CASE_RETURN_STR(BTHF_CLIENT_CALL_NO_CALLS_IN_PROGRESS)
            CASE_RETURN_STR(BTHF_CLIENT_CALL_CALLS_IN_PROGRESS)

        default:
            return "UNKNOWN MSG ID(call)";
    }
}


const char *dump_hf_client_callsetup(bthf_client_callsetup_t event)
{
    switch(event)
    {
            CASE_RETURN_STR(BTHF_CLIENT_CALLSETUP_NONE)
            CASE_RETURN_STR(BTHF_CLIENT_CALLSETUP_INCOMING)
            CASE_RETURN_STR(BTHF_CLIENT_CALLSETUP_OUTGOING)
            CASE_RETURN_STR(BTHF_CLIENT_CALLSETUP_ALERTING)

        default:
            return "UNKNOWN MSG ID(callheld)";
    }
}


const char *dump_hf_client_callheld(bthf_client_callheld_t event)
{
    switch(event)
    {
            CASE_RETURN_STR(BTHF_CLIENT_CALLHELD_NONE)
            CASE_RETURN_STR(BTHF_CLIENT_CALLHELD_HOLD_AND_ACTIVE)
            CASE_RETURN_STR(BTHF_CLIENT_CALLHELD_HOLD)

        default:
            return "UNKNOWN MSG ID(callheld)";
    }
}

const char *dump_hf_client_resp_and_hold(bthf_client_resp_and_hold_t event)
{
    switch(event)
    {
            CASE_RETURN_STR(BTHF_CLIENT_RESP_AND_HOLD_HELD)
            CASE_RETURN_STR(BTRH_CLIENT_RESP_AND_HOLD_ACCEPT)
            CASE_RETURN_STR(BTRH_CLIENT_RESP_AND_HOLD_REJECT)

        default:
            return "UNKNOWN MSG ID(hf_client_resp_and_hold)";
    }
}

const char *dump_hf_client_call_direction(uint16_t event)
{
    switch(event)
    {
            CASE_RETURN_STR(BTHF_CLIENT_CALL_DIRECTION_OUTGOING)
            CASE_RETURN_STR(BTHF_CLIENT_CALL_DIRECTION_INCOMING)

        default:
            return "UNKNOWN MSG ID(hf_client_call_direction)";
    }
}

const char *dump_hf_client_conn_state(bthf_client_connection_state_t event)
{
    switch(event)
    {
            CASE_RETURN_STR(BTHF_CLIENT_CONNECTION_STATE_DISCONNECTED)
            CASE_RETURN_STR(BTHF_CLIENT_CONNECTION_STATE_CONNECTING)
            CASE_RETURN_STR(BTHF_CLIENT_CONNECTION_STATE_CONNECTED)
            CASE_RETURN_STR(BTHF_CLIENT_CONNECTION_STATE_SLC_CONNECTED)
            CASE_RETURN_STR(BTHF_CLIENT_CONNECTION_STATE_DISCONNECTING)

        default:
            return "UNKNOWN MSG ID(hf_client_conn_state)";
    }
}
const char *dump_hf_client_audio_state(bthf_client_audio_state_t event)
{
    switch(event)
    {
            CASE_RETURN_STR(BTHF_CLIENT_AUDIO_STATE_DISCONNECTED)
            CASE_RETURN_STR(BTHF_CLIENT_AUDIO_STATE_CONNECTING)
            CASE_RETURN_STR(BTHF_CLIENT_AUDIO_STATE_CONNECTED)
            CASE_RETURN_STR(BTHF_CLIENT_AUDIO_STATE_CONNECTED_MSBC)

        default:
            return "UNKNOWN MSG ID(hf_client_audio_state)";
    }
}

#endif

