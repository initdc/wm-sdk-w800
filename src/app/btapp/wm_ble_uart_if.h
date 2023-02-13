#ifndef __WM_UART_BLE_IF_H__
#define __WM_UART_BLE_IF_H__
#include "wm_uart.h"
#include "wm_bt.h"

typedef enum
{
    BLE_UART_SERVER_MODE,
    BLE_UART_CLIENT_MODE,
    BLE_UART_UNKNOWN_MODE,
} ble_uart_mode_t;


tls_bt_status_t wm_uart_ble_init(ble_uart_mode_t mode, uint8_t uart_id, tls_uart_options_t *p_hci_if);
uint32_t wm_uart_ble_buffer_size();
uint32_t wm_uart_ble_buffer_available();
tls_bt_status_t wm_uart_ble_deinit(ble_uart_mode_t mode,uint8_t uart_id);
uint32_t wm_uart_ble_buffer_read(uint8_t *ptr, uint32_t length);
uint32_t wm_uart_ble_buffer_delete(uint32_t length);
uint32_t wm_uart_ble_buffer_peek(uint8_t *ptr, uint32_t length);

#endif
