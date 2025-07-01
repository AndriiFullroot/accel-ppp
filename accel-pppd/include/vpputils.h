#ifndef VPPUTILS_H
#define VPPUTILS_H

struct vapi_ctx_s;
struct vapi_ctx_s * vpp_get_vapi();

void vpp_lock();
void vpp_unlock();

/* export symbols */
void vpp_get();
void vpp_put();


#endif /* VPPUTILS_H */
