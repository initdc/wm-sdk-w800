
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#include "wm_config.h"

#if (TLS_CONFIG_BR_EDR == CFG_ON)

#include "wm_audio_sink.h"
#include "bt_rc.h"
#include "bt_av.h"



static void bta2dp_connection_state_callback(btav_connection_state_t state, tls_bt_addr_t *bd_addr)
{
    switch(state)
    {
        case BTAV_CONNECTION_STATE_DISCONNECTED:
            hci_dbg_msg("BTAV_CONNECTION_STATE_DISCONNECTED\r\n");
            //sbc_ABV_buffer_reset();
            break;

        case BTAV_CONNECTION_STATE_CONNECTING:
            hci_dbg_msg("BTAV_CONNECTION_STATE_CONNECTING\r\n");
            break;

        case BTAV_CONNECTION_STATE_CONNECTED:
            hci_dbg_msg("BTAV_CONNECTION_STATE_CONNECTED\r\n");
            break;

        case BTAV_CONNECTION_STATE_DISCONNECTING:
            hci_dbg_msg("BTAV_CONNECTION_STATE_DISCONNECTING\r\n");
            break;

        default:
            hci_dbg_msg("UNKNOWN BTAV_AUDIO_STATE...\r\n");
    }
}


static void bta2dp_audio_state_callback(btav_audio_state_t state, tls_bt_addr_t *bd_addr)
{
    switch(state)
    {
        case BTAV_AUDIO_STATE_STARTED:
            hci_dbg_msg("BTAV_AUDIO_STATE_STARTED\r\n");
            //sbc_ABV_buffer_reset();
            //VolumeControl(16);
            break;

        case BTAV_AUDIO_STATE_STOPPED:
            hci_dbg_msg("BTAV_AUDIO_STATE_STOPPED\r\n");
            break;

        case BTAV_AUDIO_STATE_REMOTE_SUSPEND:
            hci_dbg_msg("BTAV_AUDIO_STATE_REMOTE_SUSPEND\r\n");
            break;

        default:
            hci_dbg_msg("UNKNOWN BTAV_AUDIO_STATE...\r\n");
    }
}
static void bta2dp_audio_config_callback(tls_bt_addr_t *bd_addr, uint32_t sample_rate, uint8_t channel_count)
{
    hci_dbg_msg("CBACK:%02x:%02x:%02x:%02x:%02x:%02x::sample_rate=%d, channel_count=%d\r\n",
                bd_addr->address[0], bd_addr->address[1], bd_addr->address[2], bd_addr->address[3], bd_addr->address[4], bd_addr->address[5], sample_rate, channel_count);
}


static btav_callbacks_t sBluetoothA2dpSinkCallbacks =
{
    sizeof(sBluetoothA2dpSinkCallbacks),
    bta2dp_connection_state_callback,
    bta2dp_audio_state_callback,
    bta2dp_audio_config_callback
};


static btav_callbacks_t sBluetoothA2dpSrcCallbacks =
{
    sizeof(sBluetoothA2dpSrcCallbacks),
    bta2dp_connection_state_callback,
    bta2dp_audio_state_callback
};


static void btavrcp_remote_features_callback(tls_bt_addr_t *bd_addr, btrc_remote_features_t features)
{
    hci_dbg_msg("CBACK(%s): features:%d\r\n", __FUNCTION__, features);
}
static void btavrcp_get_play_status_callback()
{
    hci_dbg_msg("CBACK(%s): \r\n", __FUNCTION__);
}
static void btavrcp_get_element_attr_callback(uint8_t num_attr, btrc_media_attr_t *p_attrs)
{
    hci_dbg_msg("CBACK(%s): num_attr:%d, param:%d\r\n", __FUNCTION__, num_attr);
}
static void btavrcp_register_notification_callback(btrc_event_id_t event_id, uint32_t param)
{
    hci_dbg_msg("CBACK(%s): event_id:%d, param:%d\r\n", __FUNCTION__, event_id, param);
}

static void btavrcp_volume_change_callback(uint8_t volume, uint8_t ctype)
{
    hci_dbg_msg("CBACK: volume:%d, type:%d\r\n", volume, ctype);
}
static void btavrcp_passthrough_command_callback(int id, int pressed)
{
    hci_dbg_msg("CBACK(%s): id:%d, pressed:%d\r\n", __FUNCTION__, id, pressed);
}



static btrc_callbacks_t sBluetoothAvrcpCallbacks =
{
    sizeof(sBluetoothAvrcpCallbacks),
    btavrcp_remote_features_callback,
    btavrcp_get_play_status_callback,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    btavrcp_get_element_attr_callback,
    btavrcp_register_notification_callback,
    btavrcp_volume_change_callback,
    btavrcp_passthrough_command_callback,
};


static void btavrcp_passthrough_response_callback(int id, int pressed)
{
}

static void btavrcp_connection_state_callback(bool state, tls_bt_addr_t *bd_addr)
{
    hci_dbg_msg("CBACK:%02x:%02x:%02x:%02x:%02x:%02x::state:%d\r\n",
                bd_addr->address[0], bd_addr->address[1], bd_addr->address[2], bd_addr->address[3], bd_addr->address[4], bd_addr->address[5], state);
}


static btrc_ctrl_callbacks_t sBluetoothAvrcpCtrlCallbacks =
{
    sizeof(sBluetoothAvrcpCallbacks),
    btavrcp_passthrough_response_callback,
    btavrcp_connection_state_callback
};

void enable_sink()
{
    bt_interface_t *btif = NULL;
    btif = (bt_interface_t *)bluetooth__get_bluetooth_interface();
    assert(btif != NULL);
    //btav_interface_t *itf = (btav_interface_t *)btif->get_profile_interface("a2dp");
    //itf->init(NULL); we do not care a2dp source feature now;
    const btav_interface_t *itf = (btav_interface_t *)btif->get_profile_interface("a2dp_sink");
    itf->init(&sBluetoothA2dpSinkCallbacks);
    const btrc_interface_t *itcf = (btrc_interface_t *)btif->get_profile_interface("avrcp");
    itcf->init(&sBluetoothAvrcpCallbacks);
    const btrc_ctrl_interface_t *itccf = (btrc_ctrl_interface_t *)btif->get_profile_interface("avrcp_ctrl");
    itccf->init(&sBluetoothAvrcpCtrlCallbacks);
}
#endif

