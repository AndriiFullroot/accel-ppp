#ifndef VPPPOE_H
#define VPPPOE_H


void vpppoe_init();

void vpppoe_get();
void vpppoe_put();
uint32_t vpppoe_create_pppoe_session(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, in_addr_t *host_ip, uint32_t mask);
void vpppoe_delete_pppoe_session(uint8_t *client_mac, in_addr_t *client_ip, uint16_t session_id, uint32_t sw_ifindex);

// void vpppoe_set_ip4(uint32_t if_index, in_addr_t *ip, uint8_t preffix);

#endif /* VPPPOE_H */