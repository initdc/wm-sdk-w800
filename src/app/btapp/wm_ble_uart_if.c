/*****************************************************************************
**
**  Name:           wm_uart_ble_if.c
**
**  Description:    This file contains the  implemention of uart_ble_passthrough
**
*****************************************************************************/
#include <assert.h>

#include "wm_bt_config.h"

#if (WM_BLE_INCLUDED == CFG_ON)

#include "wm_ble_uart_if.h"
#include "wm_ble_server_api_demo.h"
#include "wm_ble_client_api_demo.h"
#include "wm_bt_util.h"
#include "wm_mem.h"

typedef struct 
{
    uint32_t total;
    uint32_t available;
    uint8_t *base;
    uint8_t *head;
    uint8_t *tail;
} ringbuffer_t;


static ringbuffer_t *rb_ptr_t = NULL;
static uint8_t g_uart_id = -1;
#define RING_BUFFER_SIZE (4096)
static ble_uart_mode_t g_bum = BLE_UART_SERVER_MODE;

static ringbuffer_t *ringbuffer_init(const size_t size)
{
    ringbuffer_t *p = tls_mem_alloc(sizeof(ringbuffer_t));
    p->base = tls_mem_alloc(size);
    p->head = p->tail = p->base;
    p->total = p->available = size;
    return p;
}

static void ringbuffer_free(ringbuffer_t *rb)
{
    if(rb != NULL)
    {
        tls_mem_free(rb->base);
    }

    tls_mem_free(rb);
}
static uint32_t ringbuffer_available(const ringbuffer_t *rb)
{
    assert(rb);
    return rb->available;
}
static uint32_t ringbuffer_size(const ringbuffer_t *rb)
{
    assert(rb);
    return rb->total - rb->available;
}

static uint32_t ringbuffer_insert(ringbuffer_t *rb, const uint8_t *p, uint32_t length)
{
    assert(rb);
    assert(p);
    uint32_t cpu_sr = tls_os_set_critical();

    if(length > ringbuffer_available(rb))
    {
        length = ringbuffer_available(rb);
    }

    for(size_t i = 0; i != length; ++i)
    {
        *rb->tail++ = *p++;

        if(rb->tail >= (rb->base + rb->total))
        {
            rb->tail = rb->base;
        }
    }

    rb->available -= length;
    tls_os_release_critical(cpu_sr);
    return length;
}

static uint32_t ringbuffer_delete(ringbuffer_t *rb, uint32_t length)
{
    assert(rb);
    uint32_t cpu_sr = tls_os_set_critical();

    if(length > ringbuffer_size(rb))
    {
        length = ringbuffer_size(rb);
    }

    rb->head += length;

    if(rb->head >= (rb->base + rb->total))
    {
        rb->head -= rb->total;
    }

    rb->available += length;
    tls_os_release_critical(cpu_sr);
    return length;
}

static uint32_t ringbuffer_peek(const ringbuffer_t *rb, int offset, uint8_t *p, uint32_t length)
{
    assert(rb);
    assert(p);
    assert(offset >= 0);
    uint32_t cpu_sr = tls_os_set_critical();
    assert((uint32_t)offset <= ringbuffer_size(rb));
    uint8_t *b = ((rb->head - rb->base + offset) % rb->total) + rb->base;
    const size_t bytes_to_copy = (offset + length > ringbuffer_size(rb)) ? ringbuffer_size(rb) - offset : length;

    for(size_t copied = 0; copied < bytes_to_copy; ++copied)
    {
        *p++ = *b++;

        if(b >= (rb->base + rb->total))
        {
            b = rb->base;
        }
    }
    tls_os_release_critical(cpu_sr);
    return bytes_to_copy;
}

static uint32_t ringbuffer_pop(ringbuffer_t *rb, uint8_t *p, uint32_t length)
{
    assert(rb);
    assert(p);
    uint32_t cpu_sr = tls_os_set_critical();  
    const uint32_t copied = ringbuffer_peek(rb, 0, p, length);
    
    
    rb->head += copied;

    if(rb->head >= (rb->base + rb->total))
    {
        rb->head -= rb->total;
    }

    rb->available += copied;
    tls_os_release_critical(cpu_sr);
    return copied;
}

static void wm_uart_async_write(uint8_t *p_data, uint16_t length)
{
    //TLS_BT_APPL_TRACE_API("%s , send to uart %d bytes\r\n", __FUNCTION__, length);
    tls_uart_write_async(g_uart_id, p_data, length);    
}

static void wm_uart_async_read_cb(int size, void *user_data)
{
    int read_out = 0;
    uint32_t cache_length = 0;
    uint32_t mtu = 0;
    tls_bt_status_t bt_status;

    if(size <= 0) return;

    if(ringbuffer_available(rb_ptr_t)< size)
    {
        TLS_BT_APPL_TRACE_WARNING("uart_ble_cache_buffer is full\r\n");
        return;
    }
    
    uint8_t *tmp_ptr = tls_mem_alloc(size);
    
    cache_length = ringbuffer_size(rb_ptr_t);
    
    read_out = tls_uart_read(g_uart_id, tmp_ptr, size);
    //TLS_BT_APPL_TRACE_DEBUG("%s , need_read(%d),read_out(%d),cache_length(%d)\r\n", __FUNCTION__, size, read_out, cache_length);
    //if no cache data, send directly; otherwise append to cache buffer
    if(cache_length == 0)
    {
        mtu = wm_ble_server_api_demo_get_mtu();
        cache_length = MIN(mtu, read_out);
        if(cache_length)
        {

            /*send out*/
            //TLS_BT_APPL_TRACE_DEBUG("send out %d bytes\r\n", cache_length);
            if(g_bum == BLE_UART_SERVER_MODE)
            {
                bt_status = wm_ble_server_api_demo_send_msg(tmp_ptr, cache_length);
            }else
            {
                bt_status = wm_ble_client_api_demo_send_msg(tmp_ptr, cache_length);
            }
            if(bt_status == TLS_BT_STATUS_BUSY)
            {
                ringbuffer_insert(rb_ptr_t, tmp_ptr, cache_length);
            }

            /*append the left to ringbuffer*/
            if(cache_length < read_out)
            {
               //TLS_BT_APPL_TRACE_DEBUG("insert %d bytes\r\n", read_out-cache_length);
               ringbuffer_insert(rb_ptr_t, tmp_ptr+cache_length, read_out-cache_length); 
            }          
        }
        
    }else
    {
        //TLS_BT_APPL_TRACE_DEBUG("total insert %d bytes\r\n", read_out);
        ringbuffer_insert(rb_ptr_t, tmp_ptr, read_out);
    }


    tls_mem_free(tmp_ptr);
}

tls_bt_status_t wm_uart_ble_init(ble_uart_mode_t mode, uint8_t uart_id, tls_uart_options_t *p_hci_if)
{
    int status;
    
    TLS_BT_APPL_TRACE_API("%s , uart_id=%d\r\n", __FUNCTION__, uart_id);
    if(rb_ptr_t) return TLS_BT_STATUS_DONE;

    g_uart_id = uart_id;
    g_bum = mode;

    if(mode == BLE_UART_SERVER_MODE)
    {
        status = wm_ble_server_api_demo_init(wm_uart_async_write);
    }else if(mode == BLE_UART_CLIENT_MODE)
    {
        status = wm_ble_client_demo_api_init(wm_uart_async_write);
    }else
    {
        return TLS_BT_STATUS_UNSUPPORTED;
    }
    
    if(status != TLS_BT_STATUS_SUCCESS)
    {
        return status;
    }
    
    rb_ptr_t = ringbuffer_init(RING_BUFFER_SIZE);
    if(rb_ptr_t == NULL)
    {
        
        if(mode == BLE_UART_SERVER_MODE)
        {
            wm_ble_server_api_demo_deinit();
        }else if(mode == BLE_UART_CLIENT_MODE)
        {
            wm_ble_client_demo_api_deinit();
        }
        return TLS_BT_STATUS_NOMEM;
    }

    status = tls_uart_port_init(uart_id, NULL, 0);
    if(status != WM_SUCCESS)
    {
        if(mode == BLE_UART_SERVER_MODE)
        {
            wm_ble_server_api_demo_deinit();
        }else if(mode == BLE_UART_CLIENT_MODE)
        {
            wm_ble_client_demo_api_deinit();
        }

        ringbuffer_free(rb_ptr_t);
        rb_ptr_t = NULL;
        return TLS_BT_STATUS_FAIL;
    }
    tls_uart_rx_callback_register(uart_id, wm_uart_async_read_cb, (void *)NULL);

    return TLS_BT_STATUS_SUCCESS;
}

tls_bt_status_t wm_uart_ble_deinit(ble_uart_mode_t mode,uint8_t uart_id)
{
    if(rb_ptr_t == NULL)
        return TLS_BT_STATUS_DONE;
    
    if(rb_ptr_t)
    {
       ringbuffer_free(rb_ptr_t); 
    }

    rb_ptr_t = NULL;

    //TODO deinit uart interface???

    if(mode == BLE_UART_SERVER_MODE)
    {
        wm_ble_server_api_demo_deinit();
    }else if(mode == BLE_UART_CLIENT_MODE)
    {
        wm_ble_client_demo_api_deinit();
    }
    
    return TLS_BT_STATUS_SUCCESS;
}
uint32_t wm_uart_ble_buffer_size()
{
    return ringbuffer_size(rb_ptr_t);
}
uint32_t wm_uart_ble_buffer_available()
{
    return ringbuffer_available(rb_ptr_t);
}

uint32_t wm_uart_ble_buffer_read(uint8_t *ptr, uint32_t length)
{
    return ringbuffer_pop(rb_ptr_t, ptr, length);
}
uint32_t wm_uart_ble_buffer_peek(uint8_t *ptr, uint32_t length)
{
    return ringbuffer_peek(rb_ptr_t,0,ptr,length);
}
uint32_t wm_uart_ble_buffer_delete(uint32_t length)
{
    return ringbuffer_delete(rb_ptr_t,length);
}

#endif
