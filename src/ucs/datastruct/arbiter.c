/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include <limits.h>

#include "arbiter.h"

#include <ucs/arch/cpu.h>
#include <ucs/debug/assert.h>
#include <ucs/debug/log.h>

static ucs_mpool_ops_t ucp_arbiter_mpool_ops = {
    .chunk_alloc   = ucs_mpool_chunk_malloc,
    .chunk_release = ucs_mpool_chunk_free,
    .obj_init      = NULL,
    .obj_cleanup   = NULL
};

ucs_status_t ucs_arbiter_init(ucs_arbiter_t *arbiter)
{
    UCS_ARBITER_GUARD_INIT(arbiter);

    ucs_list_head_init(&arbiter->groups);

    return ucs_mpool_init(&arbiter->groups_mp, 0,
                          sizeof(ucs_arbiter_group_t),
                          0, UCS_SYS_CACHE_LINE_SIZE, 128, UINT_MAX,
                          &ucp_arbiter_mpool_ops, "ucs_arbiter_groups");
}

ucs_status_t ucs_arbiter_group_init(ucs_arbiter_t *arbiter, ucs_arbiter_group_t **group)
{
    if (*group) {
        return UCS_OK; /* group already initialized */
    }

    *group = (ucs_arbiter_group_t*)ucs_mpool_get(&arbiter->groups_mp);
    return (*group) ? UCS_OK : UCS_ERR_NO_MEMORY;
}

void ucs_arbiter_cleanup(ucs_arbiter_t *arbiter)
{
    ucs_mpool_cleanup(&arbiter->groups_mp, 1);
}

void ucs_arbiter_group_cleanup(ucs_arbiter_group_t *group)
{
    ucs_assert(group != NULL);
    ucs_assert(ucs_list_is_empty(&group->elems));

    *group->ep_group = NULL;
    ucs_mpool_put(group);
}

void ucs_arbiter_group_push_elem_always(ucs_arbiter_group_t *group,
                                        ucs_arbiter_elem_t *elem)
{
    ucs_list_add_tail(&group->elems, &elem->list);
    elem->group = group;
}

void ucs_arbiter_group_push_head_elem_always(ucs_arbiter_group_t *group,
                                             ucs_arbiter_elem_t *elem)
{
    ucs_list_add_head(&group->elems, &elem->list);
    elem->group = group;
}

void ucs_arbiter_group_head_desched(ucs_arbiter_group_t *group)
{
    if (ucs_arbiter_group_is_scheduled(group)) {
        return; /* already de-scheduled */
    }

    ucs_list_del(&group->list);
}

void ucs_arbiter_group_purge(ucs_arbiter_t *arbiter,
                             ucs_arbiter_group_t *group,
                             ucs_arbiter_callback_t cb, void *cb_arg)
{
    ucs_arbiter_elem_t *elem;
    ucs_arbiter_elem_t *next;
    ucs_arbiter_cb_result_t result;

    ucs_list_for_each_safe(elem, next, &group->elems, list) {
        ucs_assert(elem->group == group);
        ucs_list_del(&elem->list);
        ucs_arbiter_elem_init(elem);
        result = cb(arbiter, elem, cb_arg);

        if (result != UCS_ARBITER_CB_RESULT_REMOVE_ELEM) {
            elem->group = group;
            ucs_list_insert_before(&next->list, &elem->list);
        }
    }

    if (ucs_arbiter_group_is_scheduled(group)) {
       if (!ucs_arbiter_group_is_empty(group)) {
            ucs_list_shift_head(&arbiter->groups, &group->list);
        } else {
            ucs_list_del(&group->list);
        }
    }

    if (ucs_arbiter_group_is_empty(group)) {
        ucs_arbiter_group_cleanup(group);
    }
}

void ucs_arbiter_group_schedule_nonempty(ucs_arbiter_t *arbiter,
                                         ucs_arbiter_group_t *group)
{
    UCS_ARBITER_GUARD_CHECK(arbiter);

    if (ucs_arbiter_group_is_scheduled(group)) {
        return;
    }

    ucs_list_add_head(&arbiter->groups, &group->list);
}

void ucs_arbiter_dispatch_nonempty(ucs_arbiter_t *arbiter, unsigned per_group,
                                   ucs_arbiter_callback_t cb, void *cb_arg)
{
    UCS_LIST_HEAD(resched_groups);
    unsigned group_dispatch_count;
    ucs_arbiter_group_t *group;
    ucs_arbiter_group_t *tgroup;
    ucs_arbiter_elem_t *elem;
    ucs_arbiter_elem_t *next;
    ucs_arbiter_cb_result_t result;

    if (ucs_unlikely(per_group == 0)) {
        return;
    }

    ucs_list_for_each_safe(group, tgroup, &arbiter->groups, list) {
        group_dispatch_count = 0;

        ucs_list_for_each_safe(elem, next, &group->elems, list) {
            ucs_assert(elem->group == group);
            ucs_list_del(&elem->list);
            ucs_arbiter_elem_init(elem);
            UCS_ARBITER_GUARD_ENTER(arbiter);
            result = cb(arbiter, elem, cb_arg);
            UCS_ARBITER_GUARD_EXIT(arbiter);

            if (result == UCS_ARBITER_CB_RESULT_REMOVE_ELEM) {
                if ((++group_dispatch_count) >= per_group) {
                    break;
                }
            } else {
                elem->group = group;
                ucs_list_insert_before(&next->list, &elem->list);
                if (result == UCS_ARBITER_CB_RESULT_NEXT_GROUP) {
                    break;
                } else if ((result == UCS_ARBITER_CB_RESULT_DESCHED_GROUP) ||
                           (result == UCS_ARBITER_CB_RESULT_RESCHED_GROUP)) {
                    ucs_list_del(&group->list);
                    if (result == UCS_ARBITER_CB_RESULT_RESCHED_GROUP) {
                        ucs_list_add_tail(&resched_groups, &group->list);
                    }
                    break;
                } else if (result == UCS_ARBITER_CB_RESULT_STOP) {
                    /* make sure that next dispatch() will continue
                     * from the current group */
                    ucs_list_shift_head(&arbiter->groups, &group->list);
                    goto out;
                } else {
                    ucs_bug("unexpected return value from arbiter callback");
                }
            }
        }

        if (ucs_arbiter_group_is_empty(group)) {
            ucs_list_del(&group->list);
            ucs_arbiter_group_cleanup(group);
        }
    }
out:
    ucs_list_splice_tail(&arbiter->groups, &resched_groups);
}

void ucs_arbiter_dump(ucs_arbiter_t *arbiter, FILE *stream)
{
    ucs_arbiter_group_t *first_group = ucs_list_head(&arbiter->groups, ucs_arbiter_group_t, list);
    ucs_arbiter_group_t *group;
    ucs_arbiter_elem_t *elem;

    fprintf(stream, "-------\n");
    if (ucs_arbiter_is_empty(arbiter)) {
        fprintf(stream, "(empty)\n");
        goto out;
    }

    ucs_list_for_each(group, &arbiter->groups, list) {
        if (group == first_group) {
            fprintf(stream, "=> ");
        } else {
            fprintf(stream, " * ");
        }

        ucs_list_for_each(elem, &group->elems, list) {
            fprintf(stream, "[%p", elem);
            fprintf(stream, " grp:%p]", elem->group);
            if (!ucs_arbiter_elem_is_last(group, elem)) {
                fprintf(stream, "->");
            }
        }
    }

out:
    fprintf(stream, "-------\n");
}
