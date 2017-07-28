#ifndef KRB_HEADER_FIX_H
#define KRB_HEADER_FIX_H

#ifndef MECHEAP_GSS_CONST_NAME_T_IS_POINTER
/* The 10.x releases of the MIT Kerberos library defined gss_const_ctx_id_t,
 * gss_const_cred_id_t, and gss_const_name_t as structs. 
 * They should be pointers. We define our own typedefs instead.
 */


typedef const struct gss_ctx_id_struct *gss_mecheap_const_ctx_id_t;
typedef const struct gss_cred_id_struct *gss_mecheap_const_cred_id_t;
typedef const struct gss_name_struct *gss_mecheap_const_name_t;

#define gss_const_ctx_id_t gss_mecheap_const_ctx_id_t
#define gss_const_cred_id_t gss_mecheap_const_cred_id_t
#define gss_const_name_t gss_mecheap_const_name_t
#endif

#endif
