#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/interface.api.vapi.h>
#include <vapi/pppoe.api.vapi.h>
#include <vapi/lcp.api.vapi.h>
#include <vapi/feature.api.vapi.h>

#include <linux/if_ether.h>

#include "vpppoe.h"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
DEFINE_VAPI_MSG_IDS_PPPOE_API_JSON
DEFINE_VAPI_MSG_IDS_LCP_API_JSON
DEFINE_VAPI_MSG_IDS_FEATURE_API_JSON

static struct vpp_connect_t {
	vapi_ctx_t vapi;
	int rfcounter;
} vpp_connect;

const char vpp_app_name[] = "accel-vpppoe";

static void vpppoe_connect_to_vpp()
{
	vapi_error_e verr = vapi_ctx_alloc(&vpp_connect.vapi);

    if (verr != VAPI_OK) {
		vpp_connect.vapi = NULL;
        return;
    }

    verr = vapi_connect_ex(vpp_connect.vapi, vpp_app_name, NULL, 32, 32, VAPI_MODE_BLOCKING, true, true);

	if (verr != VAPI_OK) {
		vapi_ctx_free(vpp_connect.vapi);
		vpp_connect.vapi = NULL;
    }
}

static void vpppoe_disconnect_from_vpp()
{
	vapi_disconnect(vpp_connect.vapi);
    vapi_ctx_free(vpp_connect.vapi);
	vpp_connect.vapi = NULL;
}

void vpppoe_init() {
    vpp_connect.vapi = NULL;
    vpp_connect.rfcounter = 0;

    memset(&vpp_connect, 0, sizeof(vpp_connect));
}

void vpppoe_get()
{
    int rfc = __sync_fetch_and_add(&vpp_connect.rfcounter, 1);
	if (!rfc)
		vpppoe_connect_to_vpp();
}

void vpppoe_put()
{
    int rfc = __sync_sub_and_fetch(&vpp_connect.rfcounter, 1);
	if (!rfc)
		vpppoe_disconnect_from_vpp();
}

static vapi_error_e vpppoe_session_add_reply_callback(struct vapi_ctx_s *ctx,
    void *callback_ctx,
    vapi_error_e rv,
    bool is_last,
    vapi_payload_pppoe_add_del_session_reply *reply)
{
    if (callback_ctx != NULL && reply != NULL) {
        uint32_t *sw = (uint32_t *)(callback_ctx);
        *sw = reply->sw_if_index;
    }

    return VAPI_OK;
}

int vpppoe_pppoe_session_add_del(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, int is_add, uint32_t *out_ifindex)
{
	vapi_msg_pppoe_add_del_session *req = vapi_alloc_pppoe_add_del_session(vpp_connect.vapi);
    if (req == NULL)
        return -1;

    req->payload.client_ip.af = ADDRESS_IP4;
	memcpy(req->payload.client_ip.un.ip4, client_ip, sizeof(*client_ip));
    memcpy(req->payload.client_mac, client_mac, ETH_ALEN);

    req->payload.is_add = is_add;
    req->payload.session_id = session_id;
    req->payload.disable_fib = 1;

    return vapi_pppoe_add_del_session(vpp_connect.vapi, req, vpppoe_session_add_reply_callback, out_ifindex);
}

typedef struct {
    uint32_t ifindex;
    char *name;
    size_t len;
} vpppoe_ifname_by_ifindex_t;

static vapi_error_e vpppoe_ifname_by_ifindex_reply_callback(struct vapi_ctx_s *ctx,
                                                            void *callback_ctx,
                                                            vapi_error_e rv,
                                                            bool is_last,
                                                            vapi_payload_sw_interface_details *reply)
{
    if (reply && callback_ctx != NULL) {
        vpppoe_ifname_by_ifindex_t *ifname = (vpppoe_ifname_by_ifindex_t *)callback_ctx;
        if (ifname->ifindex == reply->sw_if_index) {
            size_t len = ifname->len > 63 ? 63 : ifname->len;
            strncpy(ifname->name, (const char *)reply->interface_name, len);
        }
    }

    return VAPI_OK;
}

int vpppoe_get_sw_ifname_by_index(uint32_t sw_ifindex, char *ifname, size_t len)
{
    vpppoe_ifname_by_ifindex_t ctx;

    ctx.ifindex = sw_ifindex;
    ctx.name = ifname;
    ctx.len = len;

    vapi_msg_sw_interface_dump *req = vapi_alloc_sw_interface_dump(vpp_connect.vapi, 0);
    if (req == NULL)
        return -1;

    req->payload.sw_if_index = sw_ifindex;

    return vapi_sw_interface_dump(vpp_connect.vapi, req, vpppoe_ifname_by_ifindex_reply_callback, &ctx);
}


static vapi_error_e vpppoe_lsc_callback(struct vapi_ctx_s *ctx,
                                        void *callback_ctx,
                                        vapi_error_e rv,
                                        bool is_last,
                                        vapi_payload_lcp_itf_pair_add_del_reply *reply)
{
    return VAPI_OK;
}

int vpppoe_lcp_tun_add_del(uint32_t ifindex, const char *host_if_name, int is_add)
{
    vapi_msg_lcp_itf_pair_add_del* req = vapi_alloc_lcp_itf_pair_add_del(vpp_connect.vapi);
    if (req == NULL)
        return -1;

    strncpy((char *)req->payload.host_if_name, host_if_name, 15);
    req->payload.sw_if_index = ifindex;
    req->payload.host_if_type = LCP_API_ITF_HOST_TUN;
    req->payload.is_add = is_add;

    return vapi_lcp_itf_pair_add_del(vpp_connect.vapi, req, vpppoe_lsc_callback, NULL);
}

static vapi_error_e vpppoe_set_feature_callback(struct vapi_ctx_s *ctx,
                                                void *callback_ctx,
                                                vapi_error_e rv,
                                                bool is_last,
                                                vapi_payload_feature_enable_disable_reply *reply)
{
    return VAPI_OK;
}

int vpppoe_set_feature(uint32_t ifindex, int is_enabled, const char *feature, const char *arc)
{
    vapi_msg_feature_enable_disable* req = vapi_alloc_feature_enable_disable(vpp_connect.vapi);
    if (req == NULL)
        return -1;

    strncpy((char *)req->payload.feature_name, feature, 63);
    strncpy((char *)req->payload.arc_name, arc, 63);
    req->payload.sw_if_index = ifindex;
    req->payload.enable = is_enabled;

    return vapi_feature_enable_disable(vpp_connect.vapi, req, vpppoe_set_feature_callback, NULL);
}
