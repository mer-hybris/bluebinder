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
    gboolean init_failed;
};

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
    // priority must be higher than the gio channel, otherwise we might process a second command
    // before the first one was accepted.
    // but it must be lower than the binder reply callback since otherwise we might send more packets
    // than the remote can handle.
    // it is defined in libgbinder as G_PRIORITY_DEFAULT_IDLE and must stay in sync with this
    g_idle_add_full(G_PRIORITY_DEFAULT_IDLE + 1, waiting_for_binder_reply, proxy, NULL);

    if (((uint8_t*)buf)[0] == HCI_COMMAND_PKT) {
        gbinder_client_transact(proxy->binder_client, 2 /* sendHciCommand */, 0, local_request, handle_binder_reply, NULL, proxy);
    } else if (((uint8_t*)buf)[0] == HCI_ACLDATA_PKT) {
        gbinder_client_transact(proxy->binder_client, 3 /* sendAclData */, 0,  local_request, handle_binder_reply, NULL, proxy);
    } else if (((uint8_t*)buf)[0] == HCI_SCODATA_PKT) {
        gbinder_client_transact(proxy->binder_client, 4 /* sendScoData */, 0,  local_request, handle_binder_reply, NULL, proxy);
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
            fprintf(stderr, "Writing packet to device failed: %s\n", error->message);
            // do not quit here, since this might happen if the user switches off
            // bt but the hw still wants to send a final event.
            return;
        }

        buf += written;
        len -= written;
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

    hci_command_hdr *cmd_hdr;
    hci_acl_hdr *acl_hdr;
    hci_sco_hdr *sco_hdr;
    gsize len;
    uint16_t pktlen;
    GError *error = NULL;

    if (io_conditions & (G_IO_ERR | G_IO_NVAL)) {
        fprintf(stderr, "Error from host descriptor\n");
        g_main_loop_quit(proxy->loop);
        return false;
    }

    if (io_conditions & (G_IO_HUP)) {
        fprintf(stderr, "Remote hangup of host descriptor\n");
        g_main_loop_quit(proxy->loop);
        return false;
    }

    GIOStatus status = g_io_channel_read_chars(
        proxy->channel,
        proxy->host_buf + proxy->host_len,
        sizeof(proxy->host_buf) - proxy->host_len, &len,
        &error);

    if (status == G_IO_STATUS_AGAIN) {
        return true;
    }

    if (status == G_IO_STATUS_ERROR) {
        fprintf(stderr, "Read from host descriptor failed: %s\n", error->message);
        g_main_loop_quit(proxy->loop);
        return false;
    }

    proxy->host_len += len;

process_packet:
    if (proxy->host_len < 1)
        return true;

    switch ((guint8)proxy->host_buf[0]) {
        case HCI_COMMAND_PKT:
            if (proxy->host_len < 1 + sizeof(*cmd_hdr))
                return true;

            cmd_hdr = (void *) (proxy->host_buf + 1);
            pktlen = 1 + sizeof(*cmd_hdr) + cmd_hdr->plen;
            break;
        case HCI_ACLDATA_PKT:
            if (proxy->host_len < 1 + sizeof(*acl_hdr))
                return true;

            acl_hdr = (void *) (proxy->host_buf + 1);
            pktlen = 1 + sizeof(*acl_hdr) + cpu_to_le16(acl_hdr->dlen);
            break;
        case HCI_SCODATA_PKT:
            if (proxy->host_len < 1 + sizeof(*sco_hdr))
                return true;

            sco_hdr = (void *) (proxy->host_buf + 1);
            pktlen = 1 + sizeof(*sco_hdr) + sco_hdr->dlen;
            break;
        case 0xff:
            /* Notification packet from /dev/vhci - ignore */
            proxy->host_len = 0;
            return true;
        default:
            fprintf(stderr, "Received unknown host packet type 0x%02x\n",
                proxy->host_buf[0]);
            g_main_loop_quit(proxy->loop);
            return false;
    }

    if (proxy->host_len < pktlen)
        return true;

    host_write_packet(proxy, proxy->host_buf, pktlen);

    if (proxy->host_len > pktlen) {
        memmove(proxy->host_buf, proxy->host_buf + pktlen,
            proxy->host_len - pktlen);
        proxy->host_len -= pktlen;
        goto process_packet;
    }

    proxy->host_len = 0;

    return true;
}

static
bool
setup_watch(
    struct proxy *proxy)
{
    proxy->channel = g_io_channel_unix_new(proxy->host_fd);

    if (!proxy->channel) {
        return false;
    }

    g_io_channel_set_encoding(proxy->channel, NULL, NULL);
    g_io_channel_set_buffered(proxy->channel, FALSE);

    proxy->gio_channel_event_id = g_io_add_watch_full(
        proxy->channel,
        G_PRIORITY_DEFAULT_IDLE + 2, // see host_write_packet
        G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
        host_read_callback,
        proxy,
        NULL);

    return true;
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
    fprintf(stderr, "Remote has died, exiting...");
    g_main_loop_quit(proxy->loop);
}

static
gboolean
binder_init_complete(
    struct proxy* proxy)
{
    fprintf(stderr, "Binder interface initialized, opening virtual device\n");

    proxy->host_fd = open_vhci(HCI_PRIMARY);
    if (proxy->host_fd < 0) {
        fprintf(stderr, "Unable to open virtual device\n");
        return FALSE;
    }

    if (!setup_watch(proxy)) {
        fprintf(stderr, "Unable to setup watch\n");
        return FALSE;
    }

    if (proxy->init_failed && proxy->loop)
        g_main_loop_quit(proxy->loop);

    return TRUE;
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
    struct proxy *proxy = user_data;
    const char* iface = gbinder_remote_request_interface(req);

    if (flags & GBINDER_TX_FLAG_ONEWAY) {
        fprintf(stderr, "Expected non-oneway transaction\n");
        return NULL;
    }

    if (!g_strcmp0(iface, BINDER_BLUETOOTH_SERVICE_IFACE_CALLBACKS)) {
        if (code == 1) { /* initializationComplete */
            int result = 0;

            gbinder_remote_request_read_int32(req, &result);

            if (result != 0) {
                fprintf(stderr, "Bluetooth binder service failed\n");
                /* we need to tell BT service that we properly handled Status::INITIALIZATION_ERROR */
                *status = GBINDER_STATUS_OK;
                proxy->init_failed = TRUE;
                return gbinder_local_reply_append_int32(gbinder_local_object_new_reply(obj), 0);
            }

            if (binder_init_complete(proxy)) {
                proxy->init_failed = FALSE;
#if USE_SYSTEMD
                sd_notify(0, "READY=1");
#endif
                *status = GBINDER_STATUS_OK;
                return gbinder_local_reply_append_int32(gbinder_local_object_new_reply(obj), 0);
            } else {
                proxy->init_failed = TRUE;
                *status = GBINDER_STATUS_FAILED;
                return NULL;
            }

        } else if (code == 2 || code == 3 || code == 4) {
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

            packet[0] = (code == 2) ? HCI_EVENT_PKT :
                        (code == 3) ? HCI_ACLDATA_PKT :
                        (code == 4) ? HCI_SCODATA_PKT : /* unreachable */ 0xFF;

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

int main(int argc, char *argv[])
{
    char *fqname =
        (BINDER_BLUETOOTH_SERVICE_IFACE "/" BINDER_BLUETOOTH_SERVICE_SLOT);
    struct proxy proxy;
    int status = 0;
    int err = 0;

    guint sigtrm = 0;
    guint sigint = 0;
    gulong death_id = 0;

    GBinderServiceManager *sm = NULL; 
    GBinderLocalObject* local_object = NULL; 
    GBinderRemoteObject* remote = NULL;
    GBinderRemoteReply* reply = NULL;
    GBinderLocalObject *local_callbacks_object = NULL;
    GBinderLocalRequest *initialize_request = NULL;

    memset(&proxy, 0, sizeof(struct proxy));

    sm = gbinder_servicemanager_new(BINDER_BLUETOOTH_SERVICE_DEVICE);
    local_object = gbinder_servicemanager_new_local_object
        (sm, NULL, NULL, NULL);

    remote = gbinder_remote_object_ref
        (gbinder_servicemanager_get_service_sync(sm, fqname, &status));

    proxy.binder_client = gbinder_client_new(remote, BINDER_BLUETOOTH_SERVICE_IFACE);

    if (!proxy.binder_client) {
        fprintf(stderr, "Failed to connect to %s binder service", fqname);
        err = 1;
        goto unref;
    }

    local_callbacks_object = gbinder_servicemanager_new_local_object(
        sm,
        BINDER_BLUETOOTH_SERVICE_IFACE_CALLBACKS,
        bluebinder_callbacks_transact,
        &proxy);

    initialize_request = gbinder_client_new_request(proxy.binder_client);

    gbinder_local_request_append_local_object
        (initialize_request, local_callbacks_object);

    reply = gbinder_client_transact_sync_reply
        (proxy.binder_client, 1 /* initialize */, initialize_request, &status);

    if (status != GBINDER_STATUS_OK || !reply) {
        fprintf(stderr, "ERROR: init reply: %p, %d\n", reply, status);
        err = 2;
        goto unref;
    }

    gbinder_remote_reply_unref(reply);
    gbinder_local_request_unref(initialize_request);
    reply = NULL;
    initialize_request = NULL;

    proxy.loop = g_main_loop_new(NULL, FALSE);

    sigtrm = g_unix_signal_add(SIGTERM, signal_callback, &proxy);
    sigint = g_unix_signal_add(SIGINT, signal_callback, &proxy);

    death_id = gbinder_remote_object_add_death_handler
            (remote, binder_remote_died, &proxy);

    if (!proxy.init_failed)
        g_main_loop_run(proxy.loop);

    g_main_loop_unref(proxy.loop);

    reply = gbinder_client_transact_sync_reply
        (proxy.binder_client, 5 /* close */, NULL, &status);

    if (status != GBINDER_STATUS_OK || !reply) {
        fprintf(stderr, "ERROR: close reply: %p, %d\n", reply, status);
    }

    if (sigtrm) {
        g_source_remove(sigtrm);
    }

    if (sigint) {
        g_source_remove(sigint);
    }

    gbinder_remote_object_remove_handler(remote, death_id);

unref:

    gbinder_local_request_unref(initialize_request);
    gbinder_remote_reply_unref(reply);

    gbinder_local_object_unref(local_callbacks_object);
    gbinder_local_object_unref(local_object);

    gbinder_remote_object_unref(remote);

    gbinder_servicemanager_unref(sm);

    if (proxy.gio_channel_event_id) {
        g_source_remove(proxy.gio_channel_event_id);
    }

    if (proxy.channel) {
        g_io_channel_shutdown(proxy.channel, TRUE, NULL);
        g_io_channel_unref(proxy.channel);
    }

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
