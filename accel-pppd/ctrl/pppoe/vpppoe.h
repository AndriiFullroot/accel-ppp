#ifndef VPPPOE_H
#define VPPPOE_H

void vpppoe_init();
void vpppoe_get();
void vpppoe_put();

int vpppoe_pppoe_session_add_del(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, int is_add, uint32_t *out_ifindex);
int vpppoe_get_sw_ifname_by_index(uint32_t sw_ifindex, char *ifname, size_t len);
int vpppoe_lcp_tun_add_del(uint32_t ifindex, const char *host_if_name, int is_add);
int vpppoe_set_feature(uint32_t ifindex, int is_enabled, const char *feature, const char *arc);

#endif /* VPPPOE_H */