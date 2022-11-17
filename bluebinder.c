/*
 *
 *  bluebinder is a simple proxy for using android binder based bluetooth
 *  through vhci (based on btproxy from bluez5/tools/btproxy.c).
 *
 *  Contact: <franz.haider@jolla.com>
 *
 *  Copyright (C) 2018-2022  Jolla Ltd.
 *
 *  Based on bluez5/tools/btproxy.c:
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <linux/rfkill.h>
#include <sys/ioctl.h>

#if USE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include <gbinder.h>

#include <glib-unix.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(val) (val)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le16(val) bswap_16(val)
#else
#error "unknown byte order"
#endif

#define HCI_PRIMARY    0x00

#define BINDER_BLUETOOTH_SERVICE_DEVICE "/dev/hwbinder"
#define BINDER_BLUETOOTH_SERVICE_IFACE "android.hardware.bluetooth@1.0::IBluetoothHci"
#define BINDER_BLUETOOTH_SERVICE_IFACE_CALLBACKS "android.hardware.bluetooth@1.0::IBluetoothHciCallbacks"
#define BINDER_BLUETOOTH_SERVICE_SLOT "default"

// Priority for wait packet processed must be higher than the gio channel (PRIORITY_HOST_READ_PACKETS)
// otherwise we might process a second command
// before the first one was accepted.
// but it must be lower than the binder reply callback since otherwise we might send more packets
// than the remote can handle.
// it is defined in libgbinder as G_PRIORITY_DEFAULT and must stay in sync with this
#define PRIORITY_WAIT_PACKET_PROCESSED (G_PRIORITY_DEFAULT + 1)
// After bluetooth has been enabled we need to process pending packets (vhci -> HAL)
// immediately before anything else for example turning bluetooth on/off can interfere.
// but it still must be lower than the wait packet processed priority.
#define PRIORITY_PROCESS_PACKETS_ONCE (G_PRIORITY_DEFAULT + 2)
#define PRIORITY_HOST_READ_PACKETS (G_PRIORITY_DEFAULT + 3) // HAL -> vhci
#define PRIORITY_CHECK_BT_STATE (G_PRIORITY_DEFAULT + 4)
// This one is to be executed after the setup procedure to potentially turn bluetooth off
// after the setup is complete if it was off before reboot for example.
// Needs to be higher than the rfkill channel otherwise an event from the user
// to turn bluetooth on/off might sneak in before we are done.
#define PRIORITY_CHECK_BT_STATE_DONE (G_PRIORITY_DEFAULT + 5)

// Priority of turning bluetooth on and off, should wait until binder callbacks
// are completely handled.
#define PRIORITY_RFKILL_CHANNEL (G_PRIORITY_DEFAULT + 6)

enum bluetooth_codes {
    INITIALIZE = GBINDER_FIRST_CALL_TRANSACTION,
    SEND_HCI_COMMAND,
    SEND_ACL_DATA,
    SEND_SCO_DATA,
    CLOSE,
};

enum bluetooth_callback_codes {
    INITIALIZATION_COMPLETE = GBINDER_FIRST_CALL_TRANSACTION,
    HCI_EVENT_RECEIVED,
    ACL_DATA_RECEIVED,
    SCO_DATA_RECEIVED,
};

struct pending_packet {
    uint8_t *packet;
    unsigned int size;
};

struct proxy {
    /* Receive commands, ACL and SCO data */
    int host_fd;
    gchar host_buf[4096];
    uint16_t host_len;

    GMainLoop *loop;
    GIOChannel *channel;
    GBinderClient *binder_client;
    int gio_channel_event_id;

    int binder_replies_pending;

    int rfkill_fd;
    GIOChannel *rfkill_channel;
    int rfkill_watch_id;
    int own_hci_index;

    GBinderLocalObject *local_callbacks_object;
    GBinderRemoteObject *remote;
    GBinderServiceManager *sm;

    bool bluetooth_hal_initialized;

    int death_id;

    GList *pending_packets;
};

static
gboolean
process_packets(
    struct proxy *proxy);

static
void
binder_remote_died(
    GBinderRemoteObject* obj,
    void* user_data);

void
handle_binder_reply(
    GBinderClient* client,
    GBinderRemoteReply* reply,
    int status,
    void* user_data)
{
    struct proxy *proxy = user_data;

    proxy->binder_replies_pending--;

    if (status != GBINDER_STATUS_OK || !reply) {
        fprintf(stderr, "%s: binder transaction has failed: status = %d reply = %p\n", __func__, status, reply);
        g_main_loop_quit(proxy->loop);
    }
}

gboolean
waiting_for_binder_reply(
    gpointer user_data
)
{
    struct proxy *proxy = user_data;
    return proxy->binder_replies_pending > 0;
}

static
void
host_write_packet(
    struct proxy *proxy,
    void *buf,
    uint16_t len)
{
    GBinderLocalRequest *local_request = NULL;
    GBinderWriter writer;

    local_request = gbinder_client_new_request(proxy->binder_client);
    if (!local_request) {
        fprintf(stderr, "Failed to allocate local gbinder request\n");
        g_main_loop_quit(proxy->loop);
        return;
    }

    gbinder_local_request_init_writer(local_request, &writer);
    // data, without the package type.
    gbinder_writer_append_hidl_vec(&writer, (void*)((char*)buf + 1), len - 1, sizeof(uint8_t));

    proxy->binder_replies_pending++;
    g_idle_add_full(PRIORITY_WAIT_PACKET_PROCESSED, waiting_for_binder_reply, proxy, NULL);

    if (((uint8_t*)buf)[0] == HCI_COMMAND_PKT) {
        gbinder_client_transact(proxy->binder_client, SEND_HCI_COMMAND, 0, local_request, handle_binder_reply, NULL, proxy);
    } else if (((uint8_t*)buf)[0] == HCI_ACLDATA_PKT) {
        gbinder_client_transact(proxy->binder_client, SEND_ACL_DATA, 0,  local_request, handle_binder_reply, NULL, proxy);
    } else if (((uint8_t*)buf)[0] == HCI_SCODATA_PKT) {
        gbinder_client_transact(proxy->binder_client, SEND_SCO_DATA, 0,  local_request, handle_binder_reply, NULL, proxy);
    } else {
        fprintf(stderr, "Received incorrect packet type from HCI client.\n");
        g_main_loop_quit(proxy->loop);
    }

    gbinder_local_request_unref(local_request);
}

static
void
dev_write_packet(
    struct proxy *proxy,
    void *buf,
    uint16_t len)
{
    while (len > 0) {
        gsize written;
        GError *error = NULL;

        GIOStatus status = g_io_channel_write_chars(
            proxy->channel,
            buf,
            len,
            &written,
            &error);

        if (status == G_IO_STATUS_ERROR) {
            fprintf(stderr, "Writing packet from HAL to vhci device failed: %s\n", error->message);
            // do not quit here, since this might happen if the user switches off
            // bt but the hw still wants to send a final event.
            return;
        }

        buf += written;
        len -= written;
    }
}

static
void
configure_bt(
    struct proxy *proxy,
    gboolean bluetooth_on)
{
    int status = 0;
    bool fail = FALSE;

    if (bluetooth_on) {
        GBinderRemoteReply *reply;
        GBinderLocalRequest *initialize_request;

        fprintf(stderr, "Turning bluetooth on\n");

        initialize_request = gbinder_client_new_request(proxy->binder_client);

        gbinder_local_request_append_local_object
            (initialize_request, proxy->local_callbacks_object);

        reply = gbinder_client_transact_sync_reply
            (proxy->binder_client, INITIALIZE, initialize_request, &status);

        if (status != GBINDER_STATUS_OK) {
            fprintf(stderr, "ERROR: init reply: %p, %d\n", reply, status);
            fail = TRUE;
        }

        gbinder_remote_reply_unref(reply);
        gbinder_local_request_unref(initialize_request);
    } else {
        GBinderRemoteReply *reply;

        fprintf(stderr, "Turning bluetooth off\n");
        proxy->bluetooth_hal_initialized = FALSE;

        reply = gbinder_client_transact_sync_reply
            (proxy->binder_client, CLOSE, NULL, &status);

        if (status != GBINDER_STATUS_OK) {
            fprintf(stderr, "ERROR: close reply: %p, %d\n", reply, status);
            fail = TRUE;
        }
        gbinder_remote_reply_unref(reply);
    }

    if (fail) {
        binder_remote_died(NULL, proxy);
    }
}

static
gboolean
host_read_callback(
    GIOChannel *channel,
    GIOCondition io_conditions,
    gpointer user_data)
{
    struct proxy *proxy = user_data;
    GError *error = NULL;
    gsize len;

    if (io_conditions & (G_IO_ERR | G_IO_NVAL)) {
        fprintf(stderr, "Error from host descriptor\n");
        g_main_loop_quit(proxy->loop);
        proxy->gio_channel_event_id = 0;
        return G_SOURCE_REMOVE;
    }

    if (io_conditions & (G_IO_HUP)) {
        fprintf(stderr, "Remote hangup of host descriptor\n");
        g_main_loop_quit(proxy->loop);
        proxy->gio_channel_event_id = 0;
        return G_SOURCE_REMOVE;
    }

    GIOStatus status = g_io_channel_read_chars(
        proxy->channel,
        proxy->host_buf + proxy->host_len,
        sizeof(proxy->host_buf) - proxy->host_len, &len,
        &error);

    if (status == G_IO_STATUS_AGAIN) {
        return G_SOURCE_CONTINUE;
    }

    if (status == G_IO_STATUS_ERROR) {
        fprintf(stderr, "Read from host descriptor failed: %s\n", error->message);
        g_main_loop_quit(proxy->loop);
        proxy->gio_channel_event_id = 0;
        return G_SOURCE_REMOVE;
    }

    proxy->host_len += len;

    if (!proxy->bluetooth_hal_initialized) {
        fprintf(stderr, "delaying writing host command to controller until bt is up\n");
        return G_SOURCE_CONTINUE;
    }

    return process_packets(proxy);
}

static
gboolean
process_packets(
    struct proxy *proxy)
{
    hci_command_hdr *cmd_hdr;
    hci_acl_hdr *acl_hdr;
    hci_sco_hdr *sco_hdr;
    uint16_t pktlen;

process_packet:
    if (proxy->host_len < 1) {
        return G_SOURCE_CONTINUE;
    }

    switch ((guint8)proxy->host_buf[0]) {
        case HCI_COMMAND_PKT:
            if (proxy->host_len < 1 + sizeof(*cmd_hdr))
                return G_SOURCE_CONTINUE;

            cmd_hdr = (void *) (proxy->host_buf + 1);
            pktlen = 1 + sizeof(*cmd_hdr) + cmd_hdr->plen;
            break;
        case HCI_ACLDATA_PKT:
            if (proxy->host_len < 1 + sizeof(*acl_hdr))
                return G_SOURCE_CONTINUE;

            acl_hdr = (void *) (proxy->host_buf + 1);
            pktlen = 1 + sizeof(*acl_hdr) + cpu_to_le16(acl_hdr->dlen);
            break;
        case HCI_SCODATA_PKT:
            if (proxy->host_len < 1 + sizeof(*sco_hdr))
                return G_SOURCE_CONTINUE;

            sco_hdr = (void *) (proxy->host_buf + 1);
            pktlen = 1 + sizeof(*sco_hdr) + sco_hdr->dlen;
            break;
        case 0xff:
            /* Notification packet from /dev/vhci - ignore */
            memmove(proxy->host_buf, proxy->host_buf + 4,
                proxy->host_len - 4);
            proxy->host_len -= 4;
            goto process_packet;
        default:
            fprintf(stderr, "Received unknown host packet type 0x%02x\n",
                proxy->host_buf[0]);
            g_main_loop_quit(proxy->loop);
            proxy->gio_channel_event_id = 0;
            return G_SOURCE_REMOVE;
    }

    if (proxy->host_len < pktlen) {
        return G_SOURCE_CONTINUE;
    }

    host_write_packet(proxy, proxy->host_buf, pktlen);

    if (proxy->host_len > pktlen) {
        memmove(proxy->host_buf, proxy->host_buf + pktlen,
            proxy->host_len - pktlen);
        proxy->host_len -= pktlen;
        goto process_packet;
    }

    proxy->host_len = 0;

    return G_SOURCE_CONTINUE;
}

static
bool
setup_watch(
    struct proxy *proxy)
{
    proxy->channel = g_io_channel_unix_new(proxy->host_fd);

    g_io_channel_set_encoding(proxy->channel, NULL, NULL);
    g_io_channel_set_buffered(proxy->channel, FALSE);

    proxy->gio_channel_event_id = g_io_add_watch_full(
        proxy->channel,
        PRIORITY_HOST_READ_PACKETS, // see host_write_packet
        G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
        host_read_callback,
        proxy,
        NULL);

    return TRUE;
}

static
int
open_vhci(
    uint8_t type)
{
    uint8_t create_req[2] = { 0xff, type };
    ssize_t written;
    int fd;

    fd = open("/dev/vhci", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "Failed to open /dev/vhci device");
        return -1;
    }

    written = write(fd, create_req, sizeof(create_req));
    if (written < 0) {
        fprintf(stderr, "Failed to set device type");
        close(fd);
        return -1;
    }

    return fd;
}

static
gboolean
signal_callback(
    void *user_data)
{
    struct proxy *proxy = user_data;

    fprintf(stderr, "Received signal, quitting\n");
    g_main_loop_quit(proxy->loop);

    return G_SOURCE_CONTINUE;
}

static
void
binder_remote_died(
    GBinderRemoteObject* obj,
    void* user_data)
{
    struct proxy *proxy = user_data;
    char *fqname =
        (BINDER_BLUETOOTH_SERVICE_IFACE "/" BINDER_BLUETOOTH_SERVICE_SLOT);
    int status;

    fprintf(stderr, "Remote has died, trying to reconnect...\n");

    gbinder_client_unref(proxy->binder_client);
    proxy->binder_client = NULL;

    gbinder_remote_object_remove_handler(proxy->remote, proxy->death_id);

    gbinder_remote_object_unref(proxy->remote);

    int retries = 0;
    while (retries < 10) {
        proxy->remote = gbinder_remote_object_ref
            (gbinder_servicemanager_get_service_sync(proxy->sm, fqname, &status));

        if (proxy->remote) {
            proxy->death_id = gbinder_remote_object_add_death_handler
                    (proxy->remote, binder_remote_died, proxy);
            break;
        }

        sleep(1);
        retries++;
    }
    if (!proxy->remote) goto failed;

    proxy->binder_client = gbinder_client_new(proxy->remote, BINDER_BLUETOOTH_SERVICE_IFACE);

    configure_bt(proxy, FALSE);

    return;

failed:
    g_main_loop_quit(proxy->loop);
}

static
gboolean
setup_vhci(
    struct proxy* proxy)
{
    bool ret = FALSE;
    GList *previous_devices = NULL;
    int rfkill_fd = -1;

    rfkill_fd = open("/dev/rfkill", O_RDONLY);
    proxy->own_hci_index = -1;

    if (rfkill_fd < 0) {
        fprintf(stderr, "Failed to open /dev/rfkill %d: %s\n", errno, strerror(errno));
        goto exit;
    }

    fcntl(rfkill_fd, F_SETFL, O_NONBLOCK);

    for (;;) {
        struct rfkill_event event;
        int len;

        if ((len = read(rfkill_fd, &event, sizeof(event))) < 0) {
            if (errno == EAGAIN) {
                break;
            } else {
                fprintf(stderr, "Reading from rfkill failed\n");
                goto exit;
            }
        }

        if (event.type == RFKILL_TYPE_BLUETOOTH) {
            previous_devices = g_list_append(previous_devices, GINT_TO_POINTER(event.idx));
        }
    }

    close(rfkill_fd);
    rfkill_fd = -1;

    proxy->host_fd = open_vhci(HCI_PRIMARY);
    if (proxy->host_fd < 0) {
        fprintf(stderr, "Unable to open virtual device\n");
        goto exit;
    }

    if (!setup_watch(proxy)) {
        fprintf(stderr, "Unable to setup watch\n");
        goto exit;
    }

    rfkill_fd = open("/dev/rfkill", O_RDONLY);

    if (rfkill_fd < 0) {
        fprintf(stderr, "Failed to open /dev/rfkill %d: %s\n", errno, strerror(errno));
        goto exit;
    }

    fcntl(rfkill_fd, F_SETFL, O_NONBLOCK);

    for (;;) {
        struct rfkill_event event;
        int len;

        if ((len = read(rfkill_fd, &event, sizeof(event))) < 0) {
            if (errno == EAGAIN) {
                break;
            } else {
                fprintf(stderr, "Reading from rfkill failed\n");
                goto exit;
            }
        }

        if (event.type == RFKILL_TYPE_BLUETOOTH && !g_list_find(previous_devices, GINT_TO_POINTER(event.idx))) {
            if (proxy->own_hci_index == -1) {
                proxy->own_hci_index = event.idx;
            } else {
                fprintf(stderr, "Found multiple new hci devices, couldn't determine own hci index for rfkill handling.\n");
                goto exit;
            }
        }
    }

    if (proxy->own_hci_index >= 0) {
        fprintf(stderr, "Own hci index: %d\n", proxy->own_hci_index);
        ret = TRUE;
    } else {
        fprintf(stderr, "Could not find own hci index\n");
    }

exit:
    g_list_free(previous_devices);
    if (rfkill_fd >= 0) close(rfkill_fd);
    return ret;
}

gboolean
turn_on_bt_after_startup(
    gpointer user_data)
{
    struct proxy *proxy = user_data;
    configure_bt(proxy, TRUE);
    return G_SOURCE_REMOVE;
}

static gboolean
check_bt_state(
    gpointer user_data)
{
    struct proxy *proxy = user_data;
    char fname[PATH_MAX];
    char hciname[PATH_MAX];
    int fd_name;
    int hci_index = -1;
    int sk = -1;
    struct hci_dev_info di;

    snprintf(fname, PATH_MAX, "/sys/class/rfkill/rfkill%u/name", proxy->own_hci_index);
    fd_name = open(fname, O_RDONLY);
    if (fd_name < 0) {
        fprintf(stderr, "Couldn't read rfkill name from %s!\n", fname);
        g_main_loop_quit(proxy->loop);
        return G_SOURCE_REMOVE;
    }

    /* read name */
    memset(hciname, 0, sizeof(hciname));
    if (read(fd_name, hciname, sizeof(hciname) - 1) < 0) {
        fprintf(stderr, "Couldn't read rfkill name (2)!\n");
        g_main_loop_quit(proxy->loop);
        return G_SOURCE_REMOVE;
    }
    close(fd_name);

    sscanf(hciname, "hci%d", &hci_index);
    if (hci_index < 0) {
        fprintf(stderr, "Couldn't get hci index %s!\n", hciname);
        g_main_loop_quit(proxy->loop);
        return G_SOURCE_REMOVE;
    }

    sk = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
    if (sk < 0) {
        fprintf(stderr, "Couldn't open bt socket %s!\n", strerror(errno));
        g_main_loop_quit(proxy->loop);
        return G_SOURCE_REMOVE;
    }

    di.dev_id = hci_index;

    if (ioctl(sk, HCIGETDEVINFO, (void *) &di) < 0) {
        fprintf(stderr, "Couldn't get hci dev info!\n");
        g_main_loop_quit(proxy->loop);
        return G_SOURCE_REMOVE;
    }
    close(sk);


    bdaddr_t zero_bdaddr;
    memset(&zero_bdaddr, 0, sizeof(bdaddr_t));

    if ((hci_test_bit(HCI_UP, &di.flags) && !hci_test_bit(HCI_INIT, &di.flags))
        || (!hci_test_bit(HCI_RUNNING, &di.flags) && (memcmp(&zero_bdaddr, &di.bdaddr, sizeof(bdaddr_t)) != 0))) {
        fprintf(stderr, "Successfully initialized vhci bluetooth\n");
#if USE_SYSTEMD
        sd_notify(0, "READY=1");
#endif
        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE;
}

static
gboolean
process_packets_once(
    gpointer user_data)
{
    struct proxy *proxy = user_data;
    process_packets(proxy);
    return G_SOURCE_REMOVE;
}

static
GBinderLocalReply*
bluebinder_callbacks_transact(
    GBinderLocalObject* obj,
    GBinderRemoteRequest* req,
    guint code,
    guint flags,
    int* status,
    void* user_data)
{
    static unsigned long long local_features_mask = 0;
    static int env_gotten = 0;
    struct proxy *proxy = user_data;
    const char* iface = gbinder_remote_request_interface(req);

    if (!env_gotten) {
        const char *value = getenv("BLUEBINDER_LOCAL_FEATURES_MASK");
        if (value)
            local_features_mask = strtoull(value, 0, 16);
        fprintf(stderr, "Got BLUEBINDER_LOCAL_FEATURES_MASK 0x%llx\n", local_features_mask);
        env_gotten = 1;
    }

    if (flags & GBINDER_TX_FLAG_ONEWAY) {
        fprintf(stderr, "Expected non-oneway transaction\n");
        return NULL;
    }

    if (!g_strcmp0(iface, BINDER_BLUETOOTH_SERVICE_IFACE_CALLBACKS)) {
        if (code == INITIALIZATION_COMPLETE) {
            int result = 0;

            gbinder_remote_request_read_int32(req, &result);

            if (result != 0) {
                fprintf(stderr, "Bluetooth binder service failed\n");
                /* we need to tell BT service that we properly handled Status::INITIALIZATION_ERROR */
            } else {
                proxy->bluetooth_hal_initialized = TRUE;
                fprintf(stderr, "Bluetooth binder initialized successfully\n");
                g_idle_add_full(PRIORITY_PROCESS_PACKETS_ONCE, process_packets_once, proxy, NULL);
            }

            *status = GBINDER_STATUS_OK;
            return gbinder_local_reply_append_int32(gbinder_local_object_new_reply(obj), 0);
        } else if (code == HCI_EVENT_RECEIVED || code == ACL_DATA_RECEIVED || code == SCO_DATA_RECEIVED) {
            gsize count, elemsize;
            GBinderReader reader;
            const uint8_t *vec;
            uint8_t *packet;

            gbinder_remote_request_init_reader(req, &reader);

            vec = gbinder_reader_read_hidl_vec(&reader, &count, &elemsize);
            if (elemsize != 1) {
                fprintf(stderr, "Received unexpected array element size, expected sizeof(uint8_t)\n");
                g_main_loop_quit(proxy->loop);
                *status = GBINDER_STATUS_FAILED;
                return NULL;
            }

            // first byte will be the type
            packet = malloc(count + 1);
            memcpy(packet + 1, vec, count);

            packet[0] = (code == HCI_EVENT_RECEIVED) ? HCI_EVENT_PKT :
                        (code == ACL_DATA_RECEIVED) ? HCI_ACLDATA_PKT :
                        (code == SCO_DATA_RECEIVED) ? HCI_SCODATA_PKT : /* unreachable */ 0xFF;

            if (local_features_mask) {
                // Command complete
                if (packet[0] == HCI_EVENT_PKT && count >= 14 && packet[1] == 0x0e) {
                    // HCI_Read_Local_Supported_Features
                    if (((packet[5] << 8) | packet[4]) == 0x1003) {
                        for (int l = 0; l < 8; l++) {
                            uint8_t data_in = packet[7+l];
                            uint8_t mask = local_features_mask >> (7 - l) * 8;
                            uint8_t data_out = data_in & ~mask;
                            packet[7+l] = data_out;
                        }
                    }
                }
            }

            dev_write_packet(proxy, packet, count + 1);

            free(packet);

            *status = GBINDER_STATUS_OK;
            return gbinder_local_reply_append_int32(gbinder_local_object_new_reply(obj), 0);
        } else {
            fprintf(stderr, "Unknown binder transaction.\n");
            g_main_loop_quit(proxy->loop);
            *status = GBINDER_STATUS_FAILED;
            return NULL;
        }
    } else {
        fprintf(stderr, "Unknown binder interface.\n");
        g_main_loop_quit(proxy->loop);
        *status = GBINDER_STATUS_FAILED;
        return NULL;
    }
}

static
gboolean
rfkill_callback(
    GIOChannel *channel,
    GIOCondition condition,
    gpointer user_data)
{
    struct proxy *proxy = (struct proxy*)user_data;
    gboolean bluetooth_on = FALSE;
    bool bt_event = false;

    if (condition & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
        proxy->rfkill_watch_id = 0;
        return G_SOURCE_REMOVE;
    }

    if (condition & G_IO_IN) {
        GIOStatus status;
        struct rfkill_event event;
        gsize read;

        status = g_io_channel_read_chars(channel,
                                          (char *) &event,
                                          sizeof(event),
                                          &read,
                                          NULL);

        while (status == G_IO_STATUS_NORMAL && read == sizeof(event)) {
            if (event.type == RFKILL_TYPE_BLUETOOTH && event.idx == proxy->own_hci_index) {
                bt_event = true;
                if (event.soft || event.hard) {
                    bluetooth_on = FALSE;
                } else {
                    bluetooth_on = TRUE;
                }
            }

            status = g_io_channel_read_chars(channel,
                                              (char *) &event,
                                              sizeof(event),
                                              &read,
                                              NULL);
        }
    } else {
        fprintf(stderr, "No data received in rfkill_callback!\n");
        proxy->rfkill_watch_id = 0;
        return G_SOURCE_REMOVE;
    }

    if (bt_event) {
        configure_bt(proxy, bluetooth_on);
    }

    return G_SOURCE_CONTINUE;
}

void stop_watch(struct proxy *proxy) {
    g_io_channel_shutdown(proxy->channel, TRUE, NULL);
    g_io_channel_unref(proxy->channel);
    proxy->channel = NULL;
}

int main(int argc, char *argv[])
{
    char *fqname =
        (BINDER_BLUETOOTH_SERVICE_IFACE "/" BINDER_BLUETOOTH_SERVICE_SLOT);
    struct proxy proxy;
    int status = 0;
    int err = 0;

    guint sigtrm = 0;
    guint sigint = 0;

    GBinderRemoteReply* reply = NULL;

    memset(&proxy, 0, sizeof(struct proxy));

    proxy.sm = gbinder_servicemanager_new(BINDER_BLUETOOTH_SERVICE_DEVICE);

    proxy.remote = gbinder_remote_object_ref
        (gbinder_servicemanager_get_service_sync(proxy.sm, fqname, &status));

    proxy.binder_client = gbinder_client_new(proxy.remote, BINDER_BLUETOOTH_SERVICE_IFACE);

    if (!proxy.binder_client) {
        fprintf(stderr, "Failed to connect to bluetooth binder service\n");
        g_main_loop_quit(proxy.loop);
        goto unref;
    }

    proxy.local_callbacks_object = gbinder_servicemanager_new_local_object(
        proxy.sm,
        BINDER_BLUETOOTH_SERVICE_IFACE_CALLBACKS,
        bluebinder_callbacks_transact,
        &proxy);

    sigtrm = g_unix_signal_add(SIGTERM, signal_callback, &proxy);
    sigint = g_unix_signal_add(SIGINT, signal_callback, &proxy);

    proxy.death_id = gbinder_remote_object_add_death_handler
            (proxy.remote, binder_remote_died, &proxy);

    if (setup_vhci(&proxy)) {
        gboolean bluetooth_on = FALSE;

        proxy.rfkill_fd = open("/dev/rfkill", O_RDONLY);
        proxy.rfkill_channel = g_io_channel_unix_new(proxy.rfkill_fd);
        g_io_channel_set_encoding(proxy.rfkill_channel, NULL, NULL);
        g_io_channel_set_buffered(proxy.rfkill_channel, FALSE);

        fcntl(proxy.rfkill_fd, F_SETFL, O_NONBLOCK);

        for (;;) {
            struct rfkill_event event;
            int len;

            if ((len = read(proxy.rfkill_fd, &event, sizeof(event))) < 0) {
                if (errno == EAGAIN) {
                    break;
                } else {
                    fprintf(stderr, "Reading from rfkill failed\n");
                    return 1;
                }
            }

            if (event.type == RFKILL_TYPE_BLUETOOTH && event.idx == proxy.own_hci_index) {
                if (event.soft || event.hard) {
                    bluetooth_on = FALSE;
                } else {
                    bluetooth_on = TRUE;
                }
            }
        }


        g_idle_add_full(PRIORITY_CHECK_BT_STATE, turn_on_bt_after_startup, &proxy, NULL);
        g_idle_add_full(PRIORITY_CHECK_BT_STATE, check_bt_state, &proxy, NULL);

        proxy.rfkill_watch_id = g_io_add_watch_full(proxy.rfkill_channel,
                                    PRIORITY_RFKILL_CHANNEL,
                                    (GIOCondition)(G_IO_IN | G_IO_HUP | G_IO_ERR),
                                    (GIOFunc)rfkill_callback, (gpointer)&proxy,
                                    NULL);
        g_io_channel_set_flags(proxy.rfkill_channel, G_IO_FLAG_NONBLOCK, NULL);

        proxy.loop = g_main_loop_new(NULL, FALSE);
        g_main_loop_run(proxy.loop);
        g_main_loop_unref(proxy.loop);
    }

    if (proxy.bluetooth_hal_initialized) {
        fprintf(stderr, "Turning bluetooth off on stop.\n");
        reply = gbinder_client_transact_sync_reply
            (proxy.binder_client, CLOSE, NULL, &status);

        if (status != GBINDER_STATUS_OK) {
            fprintf(stderr, "ERROR: close reply: %p, %d\n", reply, status);
        }

        gbinder_client_unref(proxy.binder_client);
        proxy.binder_client = NULL;
    }

    if (sigtrm) {
        g_source_remove(sigtrm);
    }

    if (sigint) {
        g_source_remove(sigint);
    }

    gbinder_remote_object_remove_handler(proxy.remote, proxy.death_id);

unref:

    gbinder_local_object_unref(proxy.local_callbacks_object);

    gbinder_remote_object_unref(proxy.remote);

    gbinder_servicemanager_unref(proxy.sm);

    if (proxy.gio_channel_event_id) {
        g_source_remove(proxy.gio_channel_event_id);
    }
    if (proxy.rfkill_watch_id) {
        g_source_remove(proxy.rfkill_watch_id);
    }

    stop_watch(&proxy);

    close(proxy.host_fd);

#if USE_SYSTEMD
    sd_notify(0,
        "STATUS=Exiting.\n"
        "ERRNO=19");
#endif

    return err;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
