/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ogs-dbi.h"

int ogs_dbi_auth_info(const char *id_type, const char *ue_id,
        ogs_dbi_auth_info_t *auth_info)
{
    int rv = OGS_OK;
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL;
    bson_error_t error;
    const bson_t *document;
    bson_iter_t iter;
    bson_iter_t inner_iter;
    char buf[OGS_KEY_LEN];
    char *utf8 = NULL;
    uint32_t length = 0;

    ogs_assert(id_type);
    ogs_assert(ue_id);
    ogs_assert(auth_info);

    query = BCON_NEW(id_type, BCON_UTF8(ue_id));
#if MONGOC_MAJOR_VERSION >= 1 && MONGOC_MINOR_VERSION >= 5
    cursor = mongoc_collection_find_with_opts(
            ogs_mongoc()->collection.subscriber, query, NULL, NULL);
#else
    cursor = mongoc_collection_find(ogs_mongoc()->collection.subscriber,
            MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
#endif

    if (!mongoc_cursor_next(cursor, &document)) {
        ogs_warn("Cannot find IMSI in DB : %s-%s", id_type, ue_id);

        rv = OGS_ERROR;
        goto out;
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ogs_error("Cursor Failure: %s", error.message);

        rv = OGS_ERROR;
        goto out;
    }

    if (!bson_iter_init_find(&iter, document, "security")) {
        ogs_error("No 'security' field in this document");

        rv = OGS_ERROR;
        goto out;
    }

    memset(auth_info, 0, sizeof(ogs_dbi_auth_info_t));
    bson_iter_recurse(&iter, &inner_iter);
    while (bson_iter_next(&inner_iter)) {
        const char *key = bson_iter_key(&inner_iter);

        if (!strcmp(key, "k") && BSON_ITER_HOLDS_UTF8(&inner_iter)) {
            utf8 = (char *)bson_iter_utf8(&inner_iter, &length);
            memcpy(auth_info->k, OGS_HEX(utf8, length, buf), OGS_KEY_LEN);
        } else if (!strcmp(key, "opc") && BSON_ITER_HOLDS_UTF8(&inner_iter)) {
            utf8 = (char *)bson_iter_utf8(&inner_iter, &length);
            auth_info->use_opc = 1;
            memcpy(auth_info->opc, OGS_HEX(utf8, length, buf), OGS_KEY_LEN);
        } else if (!strcmp(key, "op") && BSON_ITER_HOLDS_UTF8(&inner_iter)) {
            utf8 = (char *)bson_iter_utf8(&inner_iter, &length);
            memcpy(auth_info->op, OGS_HEX(utf8, length, buf), OGS_KEY_LEN);
        } else if (!strcmp(key, "amf") && BSON_ITER_HOLDS_UTF8(&inner_iter)) {
            utf8 = (char *)bson_iter_utf8(&inner_iter, &length);
            memcpy(auth_info->amf, OGS_HEX(utf8, length, buf), OGS_AMF_LEN);
        } else if (!strcmp(key, "rand") && BSON_ITER_HOLDS_UTF8(&inner_iter)) {
            utf8 = (char *)bson_iter_utf8(&inner_iter, &length);
            memcpy(auth_info->rand, OGS_HEX(utf8, length, buf), OGS_RAND_LEN);
        } else if (!strcmp(key, "sqn") && BSON_ITER_HOLDS_INT64(&inner_iter)) {
            auth_info->sqn = bson_iter_int64(&inner_iter);
        }
    }

out:
    if (query) bson_destroy(query);
    if (cursor) mongoc_cursor_destroy(cursor);

    return rv;
}

int ogs_dbi_update_sqn(const char *id_type, const char *ue_id, uint64_t sqn)
{
    int rv = OGS_OK;
    bson_t *query = NULL;
    bson_t *update = NULL;
    bson_error_t error;
    char printable_rand[OGS_KEYSTRLEN(OGS_RAND_LEN)];

    ogs_assert(id_type);
    ogs_assert(ue_id);
    ogs_hex_to_ascii(rand,
            OGS_RAND_LEN, printable_rand, sizeof(printable_rand));

    query = BCON_NEW(id_type, BCON_UTF8(ue_id));
    update = BCON_NEW("$set",
            "{",
                "security.sqn", BCON_INT64(sqn),
            "}");

    if (!mongoc_collection_update(ogs_mongoc()->collection.subscriber,
            MONGOC_UPDATE_NONE, query, update, NULL, &error)) {
        ogs_error("mongoc_collection_update() failure: %s", error.message);

        rv = OGS_ERROR;
    }

    if (query) bson_destroy(query);
    if (update) bson_destroy(update);

    return rv;
}

int ogs_dbi_increment_sqn(const char *id_type, const char *ue_id)
{
    int rv = OGS_OK;
    bson_t *query = NULL;
    bson_t *update = NULL;
    bson_error_t error;
    uint64_t max_sqn = OGS_MAX_SQN;

    ogs_assert(id_type);
    ogs_assert(ue_id);

    query = BCON_NEW(id_type, BCON_UTF8(ue_id));
    update = BCON_NEW("$inc",
            "{",
                "security.sqn", BCON_INT64(32),
            "}");
    if (!mongoc_collection_update(ogs_mongoc()->collection.subscriber,
            MONGOC_UPDATE_NONE, query, update, NULL, &error)) {
        ogs_error("mongoc_collection_update() failure: %s", error.message);

        rv = OGS_ERROR;
        goto out;
    }
    bson_destroy(update);

    update = BCON_NEW("$bit",
            "{",
                "security.sqn", 
                "{", "and", BCON_INT64(max_sqn), "}",
            "}");
    if (!mongoc_collection_update(ogs_mongoc()->collection.subscriber,
            MONGOC_UPDATE_NONE, query, update, NULL, &error)) {
        ogs_error("mongoc_collection_update() failure: %s", error.message);

        rv = OGS_ERROR;
    }

out:
    if (query) bson_destroy(query);
    if (update) bson_destroy(update);

    return rv;
}

int ogs_dbi_subscription_data(const char *id_type, const char *ue_id,
        ogs_dbi_subscription_data_t *subscription_data)
{
    int rv = OGS_OK;
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL;
    bson_error_t error;
    const bson_t *document;
    bson_iter_t iter;
    bson_iter_t child1_iter, child2_iter, child3_iter, child4_iter;
    const char *utf8 = NULL;
    uint32_t length = 0;

    ogs_assert(id_type);
    ogs_assert(ue_id);
    ogs_assert(subscription_data);

    query = BCON_NEW(id_type, BCON_UTF8(ue_id));
#if MONGOC_MAJOR_VERSION >= 1 && MONGOC_MINOR_VERSION >= 5
    cursor = mongoc_collection_find_with_opts(
            ogs_mongoc()->collection.subscriber, query, NULL, NULL);
#else
    cursor = mongoc_collection_find(ogs_mongoc()->collection.subscriber,
            MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
#endif

    if (!mongoc_cursor_next(cursor, &document)) {
        ogs_error("Cannot find IMSI in DB : %s-%s", id_type, ue_id);

        rv = OGS_ERROR;
        goto out;
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ogs_error("Cursor Failure: %s", error.message);

        rv = OGS_ERROR;
        goto out;
    }

    if (!bson_iter_init(&iter, document)) {
        ogs_error("bson_iter_init failed in this document");

        rv = OGS_ERROR;
        goto out;
    }

    memset(subscription_data, 0, sizeof(ogs_dbi_subscription_data_t));
    while (bson_iter_next(&iter)) {
        const char *key = bson_iter_key(&iter);
        if (!strcmp(key, "access_restriction_data") &&
            BSON_ITER_HOLDS_INT32(&iter)) {
            subscription_data->access_restriction_data =
                bson_iter_int32(&iter);

        } else if (!strcmp(key, "subscriber_status") &&
            BSON_ITER_HOLDS_INT32(&iter)) {
            subscription_data->subscriber_status =
                bson_iter_int32(&iter);
        } else if (!strcmp(key, "network_access_mode") &&
            BSON_ITER_HOLDS_INT32(&iter)) {
            subscription_data->network_access_mode =
                bson_iter_int32(&iter);
        } else if (!strcmp(key, "subscribed_rau_tau_timer") &&
            BSON_ITER_HOLDS_INT32(&iter)) {
            subscription_data->subscribed_rau_tau_timer =
                bson_iter_int32(&iter);
        } else if (!strcmp(key, "ambr") &&
            BSON_ITER_HOLDS_DOCUMENT(&iter)) {
            bson_iter_recurse(&iter, &child1_iter);
            while (bson_iter_next(&child1_iter)) {
                const char *child1_key = bson_iter_key(&child1_iter);
                if (!strcmp(child1_key, "uplink") &&
                    BSON_ITER_HOLDS_INT64(&child1_iter)) {
                    subscription_data->ambr.uplink =
                        bson_iter_int64(&child1_iter) * 1024;
                } else if (!strcmp(child1_key, "downlink") &&
                    BSON_ITER_HOLDS_INT64(&child1_iter)) {
                    subscription_data->ambr.downlink =
                        bson_iter_int64(&child1_iter) * 1024;
                }
            }
        } else if (!strcmp(key, "pdn") &&
            BSON_ITER_HOLDS_ARRAY(&iter)) {
            int pdn_index = 0;

            bson_iter_recurse(&iter, &child1_iter);
            while (bson_iter_next(&child1_iter)) {
                const char *child1_key = bson_iter_key(&child1_iter);
                ogs_pdn_t *pdn = NULL;

                ogs_assert(child1_key);
                pdn_index = atoi(child1_key);
                ogs_assert(pdn_index < OGS_MAX_NUM_OF_SESS);

                pdn = &subscription_data->pdn[pdn_index];

                bson_iter_recurse(&child1_iter, &child2_iter);
                while (bson_iter_next(&child2_iter)) {
                    const char *child2_key = bson_iter_key(&child2_iter);
                    if (!strcmp(child2_key, "apn") &&
                        BSON_ITER_HOLDS_UTF8(&child2_iter)) {
                        utf8 = bson_iter_utf8(&child2_iter, &length);
                        ogs_cpystrn(pdn->apn, utf8,
                            ogs_min(length, OGS_MAX_APN_LEN)+1);
                    } else if (!strcmp(child2_key, "type") &&
                        BSON_ITER_HOLDS_INT32(&child2_iter)) {
                        pdn->pdn_type = bson_iter_int32(&child2_iter);
                    } else if (!strcmp(child2_key, "qos") &&
                        BSON_ITER_HOLDS_DOCUMENT(&child2_iter)) {
                        bson_iter_recurse(&child2_iter, &child3_iter);
                        while (bson_iter_next(&child3_iter)) {
                            const char *child3_key =
                                bson_iter_key(&child3_iter);
                            if (!strcmp(child3_key, "qci") &&
                                BSON_ITER_HOLDS_INT32(&child3_iter)) {
                                pdn->qos.qci = bson_iter_int32(&child3_iter);
                            } else if (!strcmp(child3_key, "arp") &&
                                BSON_ITER_HOLDS_DOCUMENT(&child3_iter)) {
                                bson_iter_recurse(&child3_iter, &child4_iter);
                                while (bson_iter_next(&child4_iter)) {
                                    const char *child4_key =
                                        bson_iter_key(&child4_iter);
                                    if (!strcmp(child4_key, "priority_level") &&
                                        BSON_ITER_HOLDS_INT32(&child4_iter)) {
                                        pdn->qos.arp.priority_level =
                                            bson_iter_int32(&child4_iter);
                                    } else if (!strcmp(child4_key,
                                                "pre_emption_capability") &&
                                        BSON_ITER_HOLDS_INT32(&child4_iter)) {
                                        pdn->qos.arp.pre_emption_capability =
                                            bson_iter_int32(&child4_iter);
                                    } else if (!strcmp(child4_key,
                                                "pre_emption_vulnerability") &&
                                        BSON_ITER_HOLDS_INT32(&child4_iter)) {
                                        pdn->qos.arp.pre_emption_vulnerability =
                                            bson_iter_int32(&child4_iter);
                                    }
                                }
                            }
                        }
                    } else if (!strcmp(child2_key, "ambr") &&
                        BSON_ITER_HOLDS_DOCUMENT(&child2_iter)) {
                        bson_iter_recurse(&child2_iter, &child3_iter);
                        while (bson_iter_next(&child3_iter)) {
                            const char *child3_key =
                                bson_iter_key(&child3_iter);
                            if (!strcmp(child3_key, "uplink") &&
                                BSON_ITER_HOLDS_INT64(&child3_iter)) {
                                pdn->ambr.uplink =
                                    bson_iter_int64(&child3_iter) * 1024;
                            } else if (!strcmp(child3_key, "downlink") &&
                                BSON_ITER_HOLDS_INT64(&child3_iter)) {
                                pdn->ambr.downlink =
                                    bson_iter_int64(&child3_iter) * 1024;
                            }
                        }
                    } else if (!strcmp(child2_key, "pgw") &&
                        BSON_ITER_HOLDS_DOCUMENT(&child2_iter)) {
                        bson_iter_recurse(&child2_iter, &child3_iter);
                        while (bson_iter_next(&child3_iter)) {
                            const char *child3_key =
                                bson_iter_key(&child3_iter);
                            if (!strcmp(child3_key, "addr") &&
                                BSON_ITER_HOLDS_UTF8(&child3_iter)) {
                                ogs_ipsubnet_t ipsub;
                                const char *v = 
                                    bson_iter_utf8(&child3_iter, &length);
                                rv = ogs_ipsubnet(&ipsub, v, NULL);
                                if (rv == OGS_OK) {
                                    pdn->pgw_ip.ipv4 = 1;
                                    pdn->pgw_ip.both.addr = ipsub.sub[0];
                                }
                            } else if (!strcmp(child3_key, "addr6") &&
                                BSON_ITER_HOLDS_UTF8(&child3_iter)) {
                                ogs_ipsubnet_t ipsub;
                                const char *v = 
                                    bson_iter_utf8(&child3_iter, &length);
                                rv = ogs_ipsubnet(&ipsub, v, NULL);
                                if (rv == OGS_OK) {
                                    pdn->pgw_ip.ipv6 = 1;
                                    memcpy(pdn->pgw_ip.both.addr6,
                                            ipsub.sub, sizeof(ipsub.sub));
                                }
                            }
                        }
                    } else if (!strcmp(child2_key, "ue") &&
                        BSON_ITER_HOLDS_DOCUMENT(&child2_iter)) {
                        bson_iter_recurse(&child2_iter, &child3_iter);
                        while (bson_iter_next(&child3_iter)) {
                            const char *child3_key =
                                bson_iter_key(&child3_iter);
                            if (!strcmp(child3_key, "addr") &&
                                BSON_ITER_HOLDS_UTF8(&child3_iter)) {
                                ogs_ipsubnet_t ipsub;
                                const char *v = 
                                    bson_iter_utf8(&child3_iter, &length);
                                rv = ogs_ipsubnet(&ipsub, v, NULL);
                                if (rv == OGS_OK) {
                                    if (pdn->paa.pdn_type ==
                                            OGS_GTP_PDN_TYPE_IPV6) {
                                        pdn->paa.pdn_type =
                                            OGS_GTP_PDN_TYPE_IPV4V6;
                                    } else {
                                        pdn->paa.pdn_type =
                                            OGS_GTP_PDN_TYPE_IPV4;
                                    }
                                    pdn->paa.both.addr = ipsub.sub[0];
                                }
                            } else if (!strcmp(child3_key, "addr6") &&
                                BSON_ITER_HOLDS_UTF8(&child3_iter)) {
                                ogs_ipsubnet_t ipsub;
                                const char *v = 
                                    bson_iter_utf8(&child3_iter, &length);
                                rv = ogs_ipsubnet(&ipsub, v, NULL);
                                if (rv == OGS_OK) {
                                    if (pdn->paa.pdn_type ==
                                            OGS_GTP_PDN_TYPE_IPV4) {
                                        pdn->paa.pdn_type =
                                            OGS_GTP_PDN_TYPE_IPV4V6;
                                    } else {
                                        pdn->paa.pdn_type =
                                            OGS_GTP_PDN_TYPE_IPV6;
                                    }
                                    memcpy(&(pdn->paa.both.addr6),
                                            ipsub.sub, OGS_IPV6_LEN);
                                }

                            }
                        }
                    }
                }
                pdn_index++;
            }
            subscription_data->num_of_pdn = pdn_index;
        }
    }

out:
    if (query) bson_destroy(query);
    if (cursor) mongoc_cursor_destroy(cursor);

    return rv;
}