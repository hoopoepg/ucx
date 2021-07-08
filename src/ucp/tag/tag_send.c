/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "tag_match.h"
#include "eager.h"
#include "rndv.h"

#include <ucp/core/ucp_ep.h>
#include <ucp/core/ucp_worker.h>
#include <ucp/core/ucp_context.h>
#include <ucp/proto/proto_am.inl>
#include <ucs/datastruct/mpool.inl>
#include <string.h>


static UCS_F_ALWAYS_INLINE size_t
ucp_tag_get_rndv_threshold(const ucp_request_t *req, size_t count,
                           size_t max_iov, size_t rndv_rma_thresh,
                           size_t rndv_am_thresh)
{
    switch (req->send.datatype & UCP_DATATYPE_CLASS_MASK) {
    case UCP_DATATYPE_IOV:
        if ((count > max_iov) &&
            ucp_ep_is_tag_offload_enabled(ucp_ep_config(req->send.ep))) {
            /* Make sure SW RNDV will be used, because tag offload does
             * not support multi-packet eager protocols. */
            return 1;
        }
        /* Fall through */
    case UCP_DATATYPE_CONTIG:
        return ucs_min(rndv_rma_thresh, rndv_am_thresh);
    case UCP_DATATYPE_GENERIC:
        return rndv_am_thresh;
    default:
        ucs_error("Invalid data type %lx", req->send.datatype);
    }

    return SIZE_MAX;
}

static UCS_F_ALWAYS_INLINE ucs_status_ptr_t
ucp_tag_send_req(ucp_request_t *req, size_t dt_count,
                 const ucp_ep_msg_config_t* msg_config,
                 size_t rndv_rma_thresh, size_t rndv_am_thresh,
                 ucp_send_callback_t cb, const ucp_request_send_proto_t *proto,
                 int enable_zcopy)
{
    size_t rndv_thresh  = ucp_tag_get_rndv_threshold(req, dt_count,
                                                     msg_config->max_iov,
                                                     rndv_rma_thresh,
                                                     rndv_am_thresh);
    ssize_t max_short   = ucp_proto_get_short_max(req, msg_config);
    ucs_status_t status;
    size_t zcopy_thresh;

    if (enable_zcopy ||
        ucs_unlikely(!UCP_MEM_IS_ACCESSIBLE_FROM_CPU(req->send.mem_type))) {
        zcopy_thresh = ucp_proto_get_zcopy_threshold(req, msg_config, dt_count,
                                                     rndv_thresh);
    } else {
        zcopy_thresh = rndv_thresh;
    }

    ucs_trace_req("select tag request(%p) progress algorithm datatype=%lx "
                  "buffer=%p length=%zu max_short=%zd rndv_thresh=%zu "
                  "zcopy_thresh=%zu zcopy_enabled=%d",
                  req, req->send.datatype, req->send.buffer, req->send.length,
                  max_short, rndv_thresh, zcopy_thresh, enable_zcopy);

    status = ucp_request_send_start(req, -1, zcopy_thresh, rndv_thresh,
                                    dt_count, msg_config, proto);
    if (ucs_unlikely(status != UCS_OK)) {
        if (status == UCS_ERR_NO_PROGRESS) {
            /* RMA/AM rendezvous */
            ucs_assert(req->send.length >= rndv_thresh);
            status = ucp_tag_send_start_rndv(req);
            if (status != UCS_OK) {
                return UCS_STATUS_PTR(status);
            }

            UCP_EP_STAT_TAG_OP(req->send.ep, RNDV);
        } else {
            return UCS_STATUS_PTR(status);
        }
    }

    if (req->flags & UCP_REQUEST_FLAG_SYNC) {
        UCP_EP_STAT_TAG_OP(req->send.ep, EAGER_SYNC);
    } else {
        UCP_EP_STAT_TAG_OP(req->send.ep, EAGER);
    }

    /*
     * Start the request.
     * If it is completed immediately, release the request and return the status.
     * Otherwise, return the request.
     */
    status = ucp_request_send(req, 0);
    if (req->flags & UCP_REQUEST_FLAG_COMPLETED) {
        ucs_trace_req("releasing send request %p, returning status %s", req,
                      ucs_status_string(status));
        if (enable_zcopy) {
            ucp_request_put(req);
        }
        return UCS_STATUS_PTR(status);
    }

    if (enable_zcopy) {
        ucp_request_set_callback(req, send.cb, cb)
    }

    ucs_trace_req("returning send request %p", req);
    return req + 1;
}

static void ucp_tag_send_add_debug_entry(ucp_request_t *req)
{
    ucp_tag_rndv_debug_entry_t *entry = ucp_worker_rndv_debug_entry(req->send.ep->worker,
                                                                    req->send.rndv_req_id);
    entry->id             = req->send.rndv_req_id;
    entry->type           = "tag_send";
    entry->ep             = req->send.ep;
    entry->local_address  = req->send.buffer;
    entry->size           = req->send.length;
    entry->rts_seq        = 0;
    entry->send_tag       = req->send.msg_proto.tag.tag;
    entry->recv_tag       = 0;
    entry->remote_address = 0;
    entry->remote_reqptr  = 0;
    entry->rndv_get_req   = NULL;
    entry->recv_req       = NULL;
    entry->send_req       = req;
    memcpy(entry->udata, req->send.buffer,
           ucs_min(UCP_TAG_MAX_DATA, req->send.length));
}

static UCS_F_ALWAYS_INLINE void
ucp_tag_send_req_init(ucp_request_t* req, ucp_ep_h ep, const void* buffer,
                      uintptr_t datatype, size_t count, ucp_tag_t tag,
                      uint32_t flags)
{
    ucp_worker_h worker = ep->worker;

    req->flags                  = flags | UCP_REQUEST_FLAG_SEND_TAG;
    req->send.ep                = ep;
    req->send.buffer            = (void*)buffer;
    req->send.datatype          = datatype;
    req->send.msg_proto.tag.tag = tag;
    ucp_request_send_state_init(req, datatype, count);
    req->send.length       = ucp_dt_length(req->send.datatype, count,
                                           req->send.buffer,
                                           &req->send.state.dt);
    req->send.mem_type     = ucp_memory_type_detect(ep->worker->context,
                                                    (void*)buffer,
                                                    req->send.length);
    req->send.lane         = ucp_ep_config(ep)->tag.lane;
    req->send.pending_lane = UCP_NULL_LANE;
    req->send.rndv_req_id  = worker->rndv_req_id++;

    if (ucs_unlikely(worker->tm.rndv_debug.queue_length > 0)) {
        ucp_tag_send_add_debug_entry(req);
    }
}

//static UCS_F_ALWAYS_INLINE int
//ucp_tag_eager_is_inline(ucp_ep_h ep, const ucp_memtype_thresh_t *max_eager_short,
//                        ssize_t length)
//{
//    return (ucs_likely(length <= max_eager_short->memtype_off) ||
//            (length <= max_eager_short->memtype_on &&
//             ucp_memory_type_cache_is_empty(ep->worker->context)));
//}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_tag_send_inline(ucp_ep_h ep, const void *buffer, size_t count,
                    uintptr_t datatype, ucp_tag_t tag)
{
//    ucs_status_t status;
//    size_t length;
//
//    if (ucs_unlikely(!UCP_DT_IS_CONTIG(datatype))) {
//        return UCS_ERR_NO_RESOURCE;
//    }
//
//    length = ucp_contig_dt_length(datatype, count);
//
//    if (ucp_tag_eager_is_inline(ep, &ucp_ep_config(ep)->tag.max_eager_short,
//                                length)) {
//        UCS_STATIC_ASSERT(sizeof(ucp_tag_t) == sizeof(ucp_eager_hdr_t));
//        UCS_STATIC_ASSERT(sizeof(ucp_tag_t) == sizeof(uint64_t));
//        status = uct_ep_am_short(ucp_ep_get_am_uct_ep(ep), UCP_AM_ID_EAGER_ONLY,
//                                 tag, buffer, length);
//    } else if (ucp_tag_eager_is_inline(ep, &ucp_ep_config(ep)->tag.offload.max_eager_short,
//                                       length)) {
//        UCS_STATIC_ASSERT(sizeof(ucp_tag_t) == sizeof(uct_tag_t));
//        status = uct_ep_tag_eager_short(ucp_ep_get_tag_uct_ep(ep), tag, buffer,
//                                        length);
//    } else {
//        return UCS_ERR_NO_RESOURCE;
//    }
//
//    if (status != UCS_ERR_NO_RESOURCE) {
//        UCP_EP_STAT_TAG_OP(ep, EAGER);
//    }
//
//    return status;
    return UCS_ERR_NO_RESOURCE;
}


UCS_PROFILE_FUNC(ucs_status_ptr_t, ucp_tag_send_nb,
                 (ep, buffer, count, datatype, tag, cb),
                 ucp_ep_h ep, const void *buffer, size_t count,
                 uintptr_t datatype, ucp_tag_t tag, ucp_send_callback_t cb)
{
    ucp_request_param_t params = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_CALLBACK,
        .datatype     = datatype,
        .cb.send      = (ucp_send_nbx_callback_t)cb
    };

    return ucp_tag_send_nbx(ep, buffer, count, tag, &params);
}

UCS_PROFILE_FUNC(ucs_status_t, ucp_tag_send_nbr,
                 (ep, buffer, count, datatype, tag, request),
                 ucp_ep_h ep, const void *buffer, size_t count,
                 uintptr_t datatype, ucp_tag_t tag, void *request)
{
    ucp_request_param_t param = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_REQUEST,
        .datatype     = datatype,
        .request      = request
    };
    ucs_status_ptr_t status;

    status = ucp_tag_send_nbx(ep, buffer, count, tag, &param);
    if (ucs_likely(status == UCS_OK)) {
        return UCS_OK;
    }

    if (ucs_unlikely(UCS_PTR_IS_ERR(status))) {
        return UCS_PTR_STATUS(status);
    }
    return UCS_INPROGRESS;
}

UCS_PROFILE_FUNC(ucs_status_ptr_t, ucp_tag_send_sync_nb,
                 (ep, buffer, count, datatype, tag, cb),
                 ucp_ep_h ep, const void *buffer, size_t count,
                 uintptr_t datatype, ucp_tag_t tag, ucp_send_callback_t cb)
{
    ucp_request_t *req;
    ucs_status_ptr_t ret;
    ucs_status_t status;

    UCP_CONTEXT_CHECK_FEATURE_FLAGS(ep->worker->context, UCP_FEATURE_TAG,
                                    return UCS_STATUS_PTR(UCS_ERR_INVALID_PARAM));
    UCP_WORKER_THREAD_CS_ENTER_CONDITIONAL(ep->worker);

    ucs_trace_req("send_sync_nb buffer %p count %zu tag %"PRIx64" to %s cb %p",
                  buffer, count, tag, ucp_ep_peer_name(ep), cb);

    if (!ucp_ep_config_test_rndv_support(ucp_ep_config(ep))) {
        ret = UCS_STATUS_PTR(UCS_ERR_UNSUPPORTED);
        goto out;
    }

    status = ucp_ep_resolve_dest_ep_ptr(ep, ucp_ep_config(ep)->tag.lane);
    if (status != UCS_OK) {
        ret = UCS_STATUS_PTR(status);
        goto out;
    }

    req = ucp_request_get(ep->worker);
    if (req == NULL) {
        ret = UCS_STATUS_PTR(UCS_ERR_NO_MEMORY);
        goto out;
    }

    ucp_tag_send_req_init(req, ep, buffer, datatype, count, tag,
                          UCP_REQUEST_FLAG_SYNC);

    ret = ucp_tag_send_req(req, count, &ucp_ep_config(ep)->tag.eager,
                           ucp_ep_config(ep)->tag.rndv.rma_thresh,
                           ucp_ep_config(ep)->tag.rndv.am_thresh,
                           cb, ucp_ep_config(ep)->tag.sync_proto, 1);
out:
    UCP_WORKER_THREAD_CS_EXIT_CONDITIONAL(ep->worker);
    return ret;
}

UCS_PROFILE_FUNC(ucs_status_ptr_t, ucp_tag_send_nbx,
                 (ep, buffer, count, tag, param),
                 ucp_ep_h ep, const void *buffer, size_t count,
                 ucp_tag_t tag, const ucp_request_param_t *param)
{
    size_t contig_length = 0;
    ucs_status_t status;
    ucp_request_t *req;
    ucs_status_ptr_t ret;
    uintptr_t datatype;
    uint32_t attr_mask;
    ucp_worker_h worker;
    ucp_send_callback_t cb;

    UCP_CONTEXT_CHECK_FEATURE_FLAGS(ep->worker->context, UCP_FEATURE_TAG,
                                    return UCS_STATUS_PTR(UCS_ERR_INVALID_PARAM));
    UCP_WORKER_THREAD_CS_ENTER_CONDITIONAL(ep->worker);

    ucs_trace_req("send_nbx buffer %p count %zu tag %" PRIx64 " to %s",
                  buffer, count, tag, ucp_ep_peer_name(ep));

    attr_mask = param->op_attr_mask &
                (UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FLAG_NO_IMM_CMPL);

    if (ucs_likely(attr_mask == 0))
    {
        status = UCS_PROFILE_CALL(ucp_tag_send_inline, ep, buffer, count, 
                                  ucp_dt_make_contig(1), tag);
        ucp_request_send_check_status(status, ret, goto out);
        datatype = ucp_dt_make_contig(1);
        contig_length = count;
    }
    else if (attr_mask == UCP_OP_ATTR_FIELD_DATATYPE)
    {
        datatype = param->datatype;
        if (ucs_likely(UCP_DT_IS_CONTIG(datatype)))
        {
            contig_length = ucp_contig_dt_length(datatype, count);
            status = UCS_PROFILE_CALL(ucp_tag_send_inline, ep, buffer,
                                      contig_length, datatype, tag);
            ucp_request_send_check_status(status, ret, goto out);
        }
    }
    else
    {
        datatype = ucp_dt_make_contig(1);
    }

    if (ucs_unlikely(param->op_attr_mask & UCP_OP_ATTR_FLAG_FORCE_IMM_CMPL))
    {
        ret = UCS_STATUS_PTR(UCS_ERR_NO_RESOURCE);
        goto out;
    }

    worker = ep->worker;
    req = ucp_request_get_param(worker, param,
                                {
                                    ret = UCS_STATUS_PTR(UCS_ERR_NO_MEMORY);
                                    goto out;
                                });

    if (param->op_attr_mask & UCP_OP_ATTR_FIELD_CALLBACK) {
        cb             = (ucp_send_callback_t)param->cb.send;
        req->user_data = param->op_attr_mask & UCP_OP_ATTR_FIELD_USER_DATA ?
                         param->user_data : NULL;
    } else {
        cb = NULL;
    }


    ucp_tag_send_req_init(req, ep, buffer, datatype, count, tag, 0);
    ret = ucp_tag_send_req(req, count, &ucp_ep_config(ep)->tag.eager,
                           ucp_ep_config(ep)->tag.rndv.rma_thresh,
                           ucp_ep_config(ep)->tag.rndv.am_thresh,
                           cb, ucp_ep_config(ep)->tag.proto, !!cb);

out:
    UCP_WORKER_THREAD_CS_EXIT_CONDITIONAL(ep->worker);
    return ret;
}

UCS_PROFILE_FUNC(ucs_status_ptr_t, ucp_tag_send_sync_nbx,
                 (ep, buffer, count, tag, param),
                 ucp_ep_h ep, const void *buffer, size_t count,
                 ucp_tag_t tag, const ucp_request_param_t *param)
{
    return UCS_STATUS_PTR(UCS_ERR_NOT_IMPLEMENTED);
}
