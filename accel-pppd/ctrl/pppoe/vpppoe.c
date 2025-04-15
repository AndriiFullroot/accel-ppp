#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/interface.api.vapi.h>
#include <vapi/pppoe.api.vapi.h>

#include <stdio.h>

#include "vpppoe.h"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
DEFINE_VAPI_MSG_IDS_PPPOE_API_JSON

static struct {
	vapi_ctx_t vapi;
	unsigned int rfcounter;
} vpp_connect;

const char vpp_app_name[] = "accel-vpppoe";

static void vpppoe_connect_to_vpp()
{
	vapi_error_e verr = vapi_ctx_alloc(&vpp_connect.vapi);

	fprintf(stderr, "--| %s\n", __FUNCTION__);

    if (verr != VAPI_OK) {
        fprintf(stderr, "--| Can't allocate vpp context! %d\n", verr);
		vpp_connect.vapi = NULL;
        return;
    }

    // verr = vapi_connect_ex(vpp_connect.vapi, vpp_app_name, NULL, 32, 32, VAPI_MODE_BLOCKING, true, true);
    verr = vapi_connect_ex(vpp_connect.vapi, vpp_app_name, NULL, 32, 32, VAPI_MODE_BLOCKING, false, true);
	if (verr != VAPI_OK) {
        fprintf(stderr, "--| Can't connect to vpp! %d\n", verr);
		vapi_ctx_free(vpp_connect.vapi);
		vpp_connect.vapi = NULL;
        return;
    }
}

vapi_error_e vpppoe_set_ip4_reply_callback(struct vapi_ctx_s *ctx,
    void *callback_ctx,
    vapi_error_e rv,
    bool is_last,
    vapi_payload_sw_interface_add_del_address_reply *reply)
{
    fprintf(stderr, "--| %s\n", __FUNCTION__);
    fprintf(stderr, "---| ADD ADDR %d %p\n", rv, reply);
    return VAPI_OK;
}


static void print_ip(uint8_t *p) {
	int i = 0;
	for(; i < 3; ++i) {
		fprintf(stderr, "%d.", p[i]);
	}
	fprintf(stderr, "%d", p[3]);
}

void vpppoe_set_ip4(uint32_t if_index, in_addr_t *ip, uint8_t preffix) {
    vapi_msg_sw_interface_add_del_address *req = vapi_alloc_sw_interface_add_del_address(vpp_connect.vapi);

	fprintf(stderr, "--| %s\n", __FUNCTION__);
    fprintf(stderr, "---| setup ipv4 for %p %d ", ip, if_index);
    print_ip(ip);
    fprintf(stderr, "/%d\n", preffix);
    fflush(stderr);


    req->payload.is_add = 1;

    req->payload.prefix.address.af = ADDRESS_IP4;
    memcpy(req->payload.prefix.address.un.ip4, ip, sizeof(*ip));
    // inet_pton(AF_INET, c_client_ip, req->payload.prefix.address.un.ip4);

    req->payload.prefix.len = preffix;

    req->payload.del_all = 0;
    req->payload.sw_if_index = if_index;

    vapi_sw_interface_add_del_address(vpp_connect.vapi, req, vpppoe_set_ip4_reply_callback, NULL);
}

void vpppoe_delete_ip4_addr(uint32_t if_index) {
    vapi_msg_sw_interface_add_del_address *req = vapi_alloc_sw_interface_add_del_address(vpp_connect.vapi);

	fprintf(stderr, "--| %s ifindex %d\n", __FUNCTION__, if_index);

    req->payload.sw_if_index = if_index;
    req->payload.is_add = 0;
    req->payload.del_all = 1;

    vapi_sw_interface_add_del_address(vpp_connect.vapi, req, vpppoe_set_ip4_reply_callback, NULL);
}

vapi_error_e vpppoe_session_add_reply_callback(struct vapi_ctx_s *ctx,
    void *callback_ctx,
    vapi_error_e rv,
    bool is_last,
    vapi_payload_pppoe_add_del_session_reply *reply)
{
    fprintf(stderr, "--| %s %d %p %p\n", __FUNCTION__, rv, reply, callback_ctx);

    if (callback_ctx != NULL && reply != NULL) {
        uint32_t *sw = (uint32_t *)(callback_ctx);
        *sw = reply->sw_if_index;
    }

    if (reply != NULL) {
        fprintf(stderr, "---| %s sw %d\n", __FUNCTION__, reply->sw_if_index);
    }

    return VAPI_OK;
}

static uint32_t vpppoe_setup_pppoe_session(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, bool is_add)
{
	vapi_msg_pppoe_add_del_session *req = NULL;
    uint32_t sw = -1;

	fprintf(stderr, "--| %s\n", __FUNCTION__);

	if (!vpp_connect.vapi)
		return;

	req = vapi_alloc_pppoe_add_del_session(vpp_connect.vapi);

    req->payload.client_ip.af = ADDRESS_IP4;
	memcpy(req->payload.client_ip.un.ip4, client_ip, sizeof(*client_ip));

    // memcpy(req->payload.client_mac, client_mac, ETH_ALEN);
    memcpy(req->payload.client_mac, client_mac, 6);

    req->payload.is_add = is_add;
    req->payload.session_id = session_id;

    vapi_pppoe_add_del_session(vpp_connect.vapi, req, vpppoe_session_add_reply_callback, &sw);

    return sw;
}


static void print_mac(uint8_t *m) {
	int i = 0;
	for(; i < 5; ++i) {
		fprintf(stderr, "%02x:", m[i]);
	}
	fprintf(stderr, "%02x", m[5]);
}

vapi_error_e pppoe_session_dump_reply_callback(struct vapi_ctx_s *ctx,
    void *callback_ctx,
    vapi_error_e rv,
    bool is_last,
    vapi_payload_pppoe_session_details *reply)
{
    fprintf(stderr, "---| %s %d %p %d\n", __FUNCTION__, is_last, reply, rv);

    if (reply) {
        fprintf(stderr, "----| sw if %d ", reply->sw_if_index);
        print_mac(reply->client_mac);
        fprintf(stderr, " ");
        print_ip(reply->client_ip.un.ip4);
        fprintf(stderr, " sid %d\n", reply->session_id);
    }
    return VAPI_OK;
}

void test_vapi_sessions() {

	fprintf(stderr, "--| %s\n", __FUNCTION__);

    vapi_msg_pppoe_session_dump *req = vapi_alloc_pppoe_session_dump(vpp_connect.vapi);

    vapi_pppoe_session_dump(vpp_connect.vapi, req, pppoe_session_dump_reply_callback, NULL);
}



void vpppoe_init() {
    vpp_connect.vapi = NULL;
    vpp_connect.rfcounter = 0;
}

static void vpppoe_disconnect_from_vpp()
{
	fprintf(stderr, "--| %s\n", __FUNCTION__);

	vapi_disconnect(vpp_connect.vapi);
    vapi_ctx_free(vpp_connect.vapi);
	vpp_connect.vapi = NULL;
}

void vpppoe_get()
{
	fprintf(stderr, "--| %s\n", __FUNCTION__);
	if (!vpp_connect.rfcounter) {
		vpppoe_connect_to_vpp();
	}
	vpp_connect.rfcounter += 1;
}

void vpppoe_put()
{
	fprintf(stderr, "--| %s\n", __FUNCTION__);
	if (!vpp_connect.rfcounter)
		return;

	vpp_connect.rfcounter -= 1;

	if (!vpp_connect.rfcounter)
		vpppoe_disconnect_from_vpp();
}


/* TODO: add checks for contiguous 1's */
static uint8_t mask_to_preffix(uint32_t mask) {
    uint8_t preffix = 0;
    size_t i = 31;
    for (; i > 0; --i) {
        if ((mask >> i) & 1) {
            ++preffix;
        } else {
            break;
        }
    }

    return preffix;
}

uint32_t vpppoe_create_pppoe_session(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, in_addr_t *host_ip, uint32_t mask)
{
    uint8_t preffix = 32;
    uint32_t sw_ifindex = -1;
	fprintf(stderr, "--| %s\n", __FUNCTION__);

    if (mask != 0 && mask != 32) {
        preffix = mask_to_preffix(mask);
    }

	sw_ifindex = vpppoe_setup_pppoe_session(client_mac, client_ip, session_id, true);

    if (sw_ifindex != -1) {
        vpppoe_set_ip4(sw_ifindex, host_ip, preffix);
    }

    return sw_ifindex;
}

void vpppoe_delete_pppoe_session(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, uint32_t sw_ifindex)
{
	fprintf(stderr, "--| %s\n", __FUNCTION__);

    // test_vapi_sessions();

    vpppoe_delete_ip4_addr(sw_ifindex);

    vpppoe_setup_pppoe_session(client_mac, client_ip, session_id, false);

}

