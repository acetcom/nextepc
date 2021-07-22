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

#include "fd-path.h"

static struct session_handler *smf_gx_reg = NULL;
static struct disp_hdl *hdl_gx_fb = NULL; 
static struct disp_hdl *hdl_gx_rar = NULL; 

struct sess_state {
    os0_t       gx_sid;             /* Gx Session-Id */

#define MAX_CC_REQUEST_NUMBER 32
    smf_sess_t *sess;
    ogs_gtp_xact_t *xact[MAX_CC_REQUEST_NUMBER];

    uint32_t cc_request_type;
    uint32_t cc_request_number;

    struct timespec ts; /* Time of sending the message */
};

static OGS_POOL(sess_state_pool, struct sess_state);
static ogs_thread_mutex_t sess_state_mutex;

static int decode_pcc_rule_definition(
        ogs_pcc_rule_t *pcc_rule, struct avp *avpch1, int *perror);
static void smf_gx_cca_cb(void *data, struct msg **msg);

static __inline__ struct sess_state *new_state(os0_t sid)
{
    struct sess_state *new = NULL;

    ogs_thread_mutex_lock(&sess_state_mutex);
    ogs_pool_alloc(&sess_state_pool, &new);
    ogs_expect_or_return_val(new, NULL);
    ogs_thread_mutex_unlock(&sess_state_mutex);

    new->gx_sid = (os0_t)ogs_strdup((char *)sid);
    ogs_expect_or_return_val(new->gx_sid, NULL);

    return new;
}

static void state_cleanup(struct sess_state *sess_data, os0_t sid, void *opaque)
{
    if (sess_data->gx_sid)
        ogs_free(sess_data->gx_sid);

    ogs_thread_mutex_lock(&sess_state_mutex);
    ogs_pool_free(&sess_state_pool, sess_data);
    ogs_thread_mutex_unlock(&sess_state_mutex);
}

void smf_gx_send_ccr(smf_sess_t *sess, ogs_gtp_xact_t *xact,
        uint32_t cc_request_type)
{
    int ret;
    smf_ue_t *smf_ue = NULL;

    struct msg *req = NULL;
    struct avp *avp;
    struct avp *avpch1, *avpch2;
    union avp_value val;
    struct sess_state *sess_data = NULL, *svg;
    struct session *session = NULL;
    int new;
    ogs_paa_t paa; /* For changing Framed-IPv6-Prefix Length to 128 */
    char buf[OGS_PLMNIDSTRLEN];
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    uint32_t charing_id;

    ogs_assert(xact);
    ogs_assert(sess);

    ogs_assert(sess->ipv4 || sess->ipv6);
    smf_ue = sess->smf_ue;
    ogs_assert(smf_ue);

    ogs_debug("[Credit-Control-Request]");

    /* Create the request */
    ret = fd_msg_new(ogs_diam_gx_cmd_ccr, MSGFL_ALLOC_ETEID, &req);
    ogs_assert(ret == 0);

    /* Find Diameter Gx Session */
    if (sess->gx_sid) {
        /* Retrieve session by Session-Id */
        size_t sidlen = strlen(sess->gx_sid);
		ret = fd_sess_fromsid_msg((os0_t)sess->gx_sid, sidlen, &session, &new);
        ogs_assert(ret == 0);
        ogs_assert(new == 0);

        ogs_debug("    Found GX Session-Id: [%s]", sess->gx_sid);

        /* Add Session-Id to the message */
        ret = ogs_diam_message_session_id_set(req, (os0_t)sess->gx_sid, sidlen);
        ogs_assert(ret == 0);
        /* Save the session associated with the message */
        ret = fd_msg_sess_set(req, session);
    } else {
        /* Create a new session */
        #define OGS_DIAM_GX_APP_SID_OPT  "app_gx"
        ret = fd_msg_new_session(req, (os0_t)OGS_DIAM_GX_APP_SID_OPT, 
                CONSTSTRLEN(OGS_DIAM_GX_APP_SID_OPT));
        ogs_assert(ret == 0);
        ret = fd_msg_sess_get(fd_g_config->cnf_dict, req, &session, NULL);
        ogs_assert(ret == 0);
        ogs_debug("    Create a New Session");
    }

    /* Retrieve session state in this session */
    ret = fd_sess_state_retrieve(smf_gx_reg, session, &sess_data);
    if (!sess_data) {
        os0_t sid;
        size_t sidlen;

        ret = fd_sess_getsid(session, &sid, &sidlen);
        ogs_assert(ret == 0);

        /* Allocate new session state memory */
        sess_data = new_state(sid);
        ogs_assert(sess_data);

        ogs_debug("    Allocate new session: [%s]", sess_data->gx_sid);

        /* Save Session-Id to SMF Session Context */
        sess->gx_sid = (char *)sess_data->gx_sid;
    } else
        ogs_debug("    Retrieve session: [%s]", sess_data->gx_sid);

    /* 
     * 8.2.  CC-Request-Number AVP
     *
     *  The CC-Request-Number AVP (AVP Code 415) is of type Unsigned32 and
     *  identifies this request within one session.  As Session-Id AVPs are
     * globally unique, the combination of Session-Id and CC-Request-Number
     * AVPs is also globally unique and can be used in matching credit-
     * control messages with confirmations.  An easy way to produce unique
     * numbers is to set the value to 0 for a credit-control request of type
     * INITIAL_REQUEST and EVENT_REQUEST and to set the value to 1 for the
     * first UPDATE_REQUEST, to 2 for the second, and so on until the value
     * for TERMINATION_REQUEST is one more than for the last UPDATE_REQUEST.
     */

    sess_data->cc_request_type = cc_request_type;
    if (cc_request_type == OGS_DIAM_GX_CC_REQUEST_TYPE_INITIAL_REQUEST ||
        cc_request_type == OGS_DIAM_GX_CC_REQUEST_TYPE_EVENT_REQUEST)
        sess_data->cc_request_number = 0;
    else
        sess_data->cc_request_number++;

    ogs_debug("    CC Request Type[%d] Number[%d]", 
        sess_data->cc_request_type, sess_data->cc_request_number);
    ogs_assert(sess_data->cc_request_number <= MAX_CC_REQUEST_NUMBER);

    /* Update session state */
    sess_data->sess = sess;
    sess_data->xact[sess_data->cc_request_number] = xact;

    /* Set Origin-Host & Origin-Realm */
    ret = fd_msg_add_origin(req, 0);
    ogs_assert(ret == 0);
    
    /* Set the Destination-Realm AVP */
    ret = fd_msg_avp_new(ogs_diam_destination_realm, 0, &avp);
    ogs_assert(ret == 0);
    val.os.data = (unsigned char *)(fd_g_config->cnf_diamrlm);
    val.os.len = strlen(fd_g_config->cnf_diamrlm);
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Set the Auth-Application-Id AVP */
    ret = fd_msg_avp_new(ogs_diam_auth_application_id, 0, &avp);
    ogs_assert(ret == 0);
    val.i32 = OGS_DIAM_GX_APPLICATION_ID;
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Set CC-Request-Type, CC-Request-Number */
    ret = fd_msg_avp_new(ogs_diam_gx_cc_request_type, 0, &avp);
    ogs_assert(ret == 0);
    val.i32 = sess_data->cc_request_type;
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    ret = fd_msg_avp_new(ogs_diam_gx_cc_request_number, 0, &avp);
    ogs_assert(ret == 0);
    val.i32 = sess_data->cc_request_number;
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Set Subscription-Id */
    ret = fd_msg_avp_new(ogs_diam_subscription_id, 0, &avp);
    ogs_assert(ret == 0);

    ret = fd_msg_avp_new(ogs_diam_subscription_id_type, 0, &avpch1);
    ogs_assert(ret == 0);
    val.i32 = OGS_DIAM_SUBSCRIPTION_ID_TYPE_END_USER_IMSI;
    ret = fd_msg_avp_setvalue (avpch1, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, avpch1);
    ogs_assert(ret == 0);

    ret = fd_msg_avp_new(ogs_diam_subscription_id_data, 0, &avpch1);
    ogs_assert(ret == 0);
    val.os.data = (uint8_t *)smf_ue->imsi_bcd;
    val.os.len = strlen(smf_ue->imsi_bcd);
    ret = fd_msg_avp_setvalue (avpch1, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, avpch1);
    ogs_assert(ret == 0);

    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    if (cc_request_type != OGS_DIAM_GX_CC_REQUEST_TYPE_TERMINATION_REQUEST) {
        /* Set Supported-Features */
        ret = fd_msg_avp_new(ogs_diam_gx_supported_features, 0, &avp);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_new(ogs_diam_gx_feature_list_id, 0, &avpch1);
        ogs_assert(ret == 0);
        val.i32 = 1;
        ret = fd_msg_avp_setvalue (avpch1, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, avpch1);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_new(ogs_diam_gx_feature_list, 0, &avpch1);
        ogs_assert(ret == 0);
        val.u32 = 0x0000000b;
        ret = fd_msg_avp_setvalue (avpch1, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, avpch1);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);

        /* Set Network-Request-Support */
        ret = fd_msg_avp_new(ogs_diam_gx_network_request_support, 0, &avp);
        ogs_assert(ret == 0);
        val.i32 = 1;
        ret = fd_msg_avp_setvalue(avp, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);

        /* Set Framed-IP-Address */
        if (sess->ipv4) {
            ret = fd_msg_avp_new(ogs_diam_gx_framed_ip_address, 0, &avp);
            ogs_assert(ret == 0);
            val.os.data = (uint8_t*)&sess->ipv4->addr;
            val.os.len = OGS_IPV4_LEN;
            ret = fd_msg_avp_setvalue(avp, &val);
            ogs_assert(ret == 0);
            ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
            ogs_assert(ret == 0);
        }

        /* Set Framed-IPv6-Prefix */
        if (sess->ipv6) {
            ret = fd_msg_avp_new(ogs_diam_gx_framed_ipv6_prefix, 0, &avp);
            ogs_assert(ret == 0);
            memcpy(&paa, &sess->session.paa, OGS_PAA_IPV6_LEN);
#define FRAMED_IPV6_PREFIX_LENGTH 128  /* from spec document */
            paa.len = FRAMED_IPV6_PREFIX_LENGTH; 
            val.os.data = (uint8_t*)&paa;
            val.os.len = OGS_PAA_IPV6_LEN;
            ret = fd_msg_avp_setvalue(avp, &val);
            ogs_assert(ret == 0);
            ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
            ogs_assert(ret == 0);
        }

        /* Set IP-Can-Type */
        ret = fd_msg_avp_new(ogs_diam_gx_ip_can_type, 0, &avp);
        ogs_assert(ret == 0);

        switch (sess->gtp_rat_type) {
        case OGS_GTP_RAT_TYPE_EUTRAN:
            val.i32 = OGS_DIAM_GX_IP_CAN_TYPE_3GPP_EPS;
            break;
        case OGS_GTP_RAT_TYPE_WLAN:
            val.i32 = OGS_DIAM_GX_IP_CAN_TYPE_NON_3GPP_EPS;
            break;
        default:
            ogs_error("Unknown RAT Type [%d]", sess->gtp_rat_type);
            ogs_assert_if_reached();
        }

        ret = fd_msg_avp_setvalue(avp, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);

        /* Set RAT-Type */
        ret = fd_msg_avp_new(ogs_diam_rat_type, 0, &avp);
        ogs_assert(ret == 0);

        switch (sess->gtp_rat_type) {
        case OGS_GTP_RAT_TYPE_EUTRAN:
            val.i32 = OGS_DIAM_RAT_TYPE_EUTRAN;
            break;
        case OGS_GTP_RAT_TYPE_WLAN:
            val.i32 = OGS_DIAM_RAT_TYPE_WLAN;
            break;
        default:
            ogs_error("Unknown RAT Type [%d]", sess->gtp_rat_type);
            ogs_assert_if_reached();
        }

        ret = fd_msg_avp_setvalue(avp, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);

        /* Set QoS-Information */
        if (sess->session.ambr.downlink || sess->session.ambr.uplink) {
            ret = fd_msg_avp_new(ogs_diam_gx_qos_information, 0, &avp);
            ogs_assert(ret == 0);

            if (sess->session.ambr.uplink) {
                ret = fd_msg_avp_new(ogs_diam_gx_apn_aggregate_max_bitrate_ul,
                        0, &avpch1);
                ogs_assert(ret == 0);
                val.u32 = sess->session.ambr.uplink;
                ret = fd_msg_avp_setvalue (avpch1, &val);
                ogs_assert(ret == 0);
                ret = fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, avpch1);
                ogs_assert(ret == 0);
            }
            
            if (sess->session.ambr.downlink) {
                ret = fd_msg_avp_new(
                        ogs_diam_gx_apn_aggregate_max_bitrate_dl, 0, &avpch1);
                ogs_assert(ret == 0);
                val.u32 = sess->session.ambr.downlink;
                ret = fd_msg_avp_setvalue (avpch1, &val);
                ogs_assert(ret == 0);
                ret = fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, avpch1);
                ogs_assert(ret == 0);
            }

            ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
            ogs_assert(ret == 0);
        }

        /* Set Default-EPS-Bearer-QoS */
        ret = fd_msg_avp_new(ogs_diam_gx_default_eps_bearer_qos, 0, &avp);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_new(ogs_diam_gx_qos_class_identifier, 0, &avpch1);
        ogs_assert(ret == 0);
        val.u32 = sess->session.qos.index;
        ret = fd_msg_avp_setvalue (avpch1, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, avpch1);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_new(
                ogs_diam_gx_allocation_retention_priority, 0, &avpch1);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_new(ogs_diam_gx_priority_level, 0, &avpch2);
        ogs_assert(ret == 0);
        val.u32 = sess->session.qos.arp.priority_level;
        ret = fd_msg_avp_setvalue (avpch2, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add (avpch1, MSG_BRW_LAST_CHILD, avpch2);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_new(ogs_diam_gx_pre_emption_capability, 0, &avpch2);
        ogs_assert(ret == 0);
        val.u32 = sess->session.qos.arp.pre_emption_capability;
        ret = fd_msg_avp_setvalue (avpch2, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add (avpch1, MSG_BRW_LAST_CHILD, avpch2);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_new(ogs_diam_gx_pre_emption_vulnerability, 0, &avpch2);
        ogs_assert(ret == 0);
        val.u32 = sess->session.qos.arp.pre_emption_vulnerability;
        ret = fd_msg_avp_setvalue (avpch2, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add (avpch1, MSG_BRW_LAST_CHILD, avpch2);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, avpch1);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);

        /* Set 3GPP-User-Location-Info */
        if (sess->gtp.user_location_information.presence) {
            ogs_gtp_uli_t uli;
            int16_t uli_len;

            uint8_t uli_buf[OGS_GTP_MAX_ULI_LEN];

            uli_len = ogs_gtp_parse_uli(
                    &uli, &sess->gtp.user_location_information);
            ogs_assert(sess->gtp.user_location_information.len == uli_len);

            ogs_assert(sess->gtp.user_location_information.data);
            ogs_assert(sess->gtp.user_location_information.len);
            memcpy(&uli_buf, sess->gtp.user_location_information.data,
                    sess->gtp.user_location_information.len);

            /* Update Gx ULI Type */
            if (uli.flags.tai && uli.flags.e_cgi)
                uli_buf[0] =
                    OGS_DIAM_GX_3GPP_USER_LOCATION_INFO_TYPE_TAI_AND_ECGI;
            else if (uli.flags.tai)
                uli_buf[0] = OGS_DIAM_GX_3GPP_USER_LOCATION_INFO_TYPE_TAI;
            else if (uli.flags.e_cgi)
                uli_buf[0] = OGS_DIAM_GX_3GPP_USER_LOCATION_INFO_TYPE_ECGI;

            if (uli_buf[0]) {
                ret = fd_msg_avp_new(
                        ogs_diam_gx_3gpp_user_location_info, 0, &avp);
                ogs_assert(ret == 0);
                val.os.data = (uint8_t *)&uli_buf;
                val.os.len = sess->gtp.user_location_information.len;
                ret = fd_msg_avp_setvalue(avp, &val);
                ogs_assert(ret == 0);
                ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
                ogs_assert(ret == 0);
            }
        }

        /* Set 3GPP-MS-Timezone */
        if (sess->gtp.ue_timezone.presence &&
                sess->gtp.ue_timezone.len && sess->gtp.ue_timezone.data) {
            ret = fd_msg_avp_new(ogs_diam_gx_3gpp_ms_timezone, 0, &avp);
            ogs_assert(ret == 0);
            val.os.data = sess->gtp.ue_timezone.data;
            val.os.len = sess->gtp.ue_timezone.len;
            ret = fd_msg_avp_setvalue(avp, &val);
            ogs_assert(ret == 0);
            ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
            ogs_assert(ret == 0);
        }

        /* Set 3GPP-SGSN-MCC-MNC */
        ret = fd_msg_avp_new(ogs_diam_gx_3gpp_sgsn_mcc_mnc, 0, &avp);
        ogs_assert(ret == 0);
        val.os.data = (uint8_t *)ogs_plmn_id_to_string(&sess->plmn_id, buf);
        val.os.len = strlen(buf);
        ret = fd_msg_avp_setvalue(avp, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);

        /* Set AN-GW-Address - Upto 2 address */
        if (sess->sgw_s5c_ip.ipv4) {
            ret = fd_msg_avp_new(ogs_diam_gx_an_gw_address, 0, &avp);
            ogs_assert(ret == 0);
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = sess->sgw_s5c_ip.addr;
            ret = fd_msg_avp_value_encode(&sin, avp);
            ogs_assert(ret == 0);
            ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
            ogs_assert(ret == 0);
        }
        if (sess->sgw_s5c_ip.ipv6) {
            ret = fd_msg_avp_new(ogs_diam_gx_an_gw_address, 0, &avp);
            ogs_assert(ret == 0);
            sin6.sin6_family = AF_INET6;
            memcpy(sin6.sin6_addr.s6_addr,
                    sess->sgw_s5c_ip.addr6, OGS_IPV6_LEN);
            ret = fd_msg_avp_value_encode(&sin6, avp);
            ogs_assert(ret == 0);
            ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
            ogs_assert(ret == 0);
        }
    }

    /* Set Called-Station-Id */
    ret = fd_msg_avp_new(ogs_diam_gx_called_station_id, 0, &avp);
    ogs_assert(ret == 0);
    ogs_assert(sess->session.name);
    val.os.data = (uint8_t*)sess->session.name;
    val.os.len = strlen(sess->session.name);
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    if (cc_request_type != OGS_DIAM_GX_CC_REQUEST_TYPE_TERMINATION_REQUEST) {
        /* Set Online to DISABLE */
        ret = fd_msg_avp_new(ogs_diam_gx_online, 0, &avp);
        ogs_assert(ret == 0);
        val.u32 = OGS_DIAM_GX_DISABLE_ONLINE;
        ret = fd_msg_avp_setvalue(avp, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);

        /* Set Offline to ENABLE */
        ret = fd_msg_avp_new(ogs_diam_gx_offline, 0, &avp);
        ogs_assert(ret == 0);
        val.u32 = OGS_DIAM_GX_ENABLE_OFFLINE;
        ret = fd_msg_avp_setvalue(avp, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);

        /* Set Access-Network-Charging-Address - Only 1 address */
        if (ogs_gtp_self()->gtpc_addr) {
            ret = fd_msg_avp_new(
                    ogs_diam_gx_access_network_charging_address, 0, &avp);
            ogs_assert(ret == 0);
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr =
                ogs_gtp_self()->gtpc_addr->sin.sin_addr.s_addr;
            ret = fd_msg_avp_value_encode(&sin, avp);
            ogs_assert(ret == 0);
            ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
            ogs_assert(ret == 0);
        } else if (ogs_gtp_self()->gtpc_addr6) {
            ret = fd_msg_avp_new(
                    ogs_diam_gx_access_network_charging_address, 0, &avp);
            ogs_assert(ret == 0);
            sin6.sin6_family = AF_INET6;
            memcpy(sin6.sin6_addr.s6_addr,
                    ogs_gtp_self()->gtpc_addr6->sin6.sin6_addr.s6_addr,
                    OGS_IPV6_LEN);
            ret = fd_msg_avp_value_encode(&sin6, avp);
            ogs_assert(ret == 0);
            ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
            ogs_assert(ret == 0);
        }

        /* Set Access-Network-Charging-Identitifer-Gx */
        ret = fd_msg_avp_new(
                ogs_diam_gx_access_network_charging_identifier_gx, 0, &avp);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_new(
                ogs_diam_gx_access_network_charging_identifier_value, 0,
                &avpch1);
        ogs_assert(ret == 0);
        charing_id = htobe32(sess->charging.id);
        val.os.data = (uint8_t *)&charing_id;
        val.os.len = sizeof(charing_id);
        ret = fd_msg_avp_setvalue (avpch1, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, avpch1);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);

        ret = fd_msg_avp_new(ogs_diam_gx_an_trusted, 0, &avp);
        ogs_assert(ret == 0);
        val.u32 = OGS_DIAM_GX_AN_UNTRUSTED;
        ret = fd_msg_avp_setvalue (avp, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);
    }
    
    ret = clock_gettime(CLOCK_REALTIME, &sess_data->ts);
    
    /* Keep a pointer to the session data for debug purpose, 
     * in real life we would not need it */
    svg = sess_data;
    
    /* Store this value in the session */
    ret = fd_sess_state_store(smf_gx_reg, session, &sess_data);
    ogs_assert(ret == 0);
    ogs_assert(sess_data == NULL);
    
    /* Send the request */
    ret = fd_msg_send(&req, smf_gx_cca_cb, svg);
    ogs_assert(ret == 0);

    /* Increment the counter */
    ogs_assert(pthread_mutex_lock(&ogs_diam_logger_self()->stats_lock) == 0);
    ogs_diam_logger_self()->stats.nb_sent++;
    ogs_assert(pthread_mutex_unlock(&ogs_diam_logger_self()->stats_lock) == 0);
}

static void smf_gx_cca_cb(void *data, struct msg **msg)
{
    int rv;
    int ret;

    struct sess_state *sess_data = NULL;
    struct timespec ts;
    struct session *session;
    struct avp *avp, *avpch1, *avpch2;
    struct avp_hdr *hdr;
    unsigned long dur;
    int error = 0;
    int new;

    smf_event_t *e = NULL;
    ogs_gtp_xact_t *xact = NULL;
    smf_sess_t *sess = NULL;
    ogs_pcc_rule_t *pcc_rule = NULL;
    ogs_pkbuf_t *gxbuf = NULL;
    ogs_diam_gx_message_t *gx_message = NULL;
    uint16_t gxbuf_len = 0;
    uint32_t cc_request_number = 0;

    ogs_debug("[Credit-Control-Answer]");
    
    ret = clock_gettime(CLOCK_REALTIME, &ts);
    ogs_assert(ret == 0);

    /* Search the session, retrieve its data */
    ret = fd_msg_sess_get(fd_g_config->cnf_dict, *msg, &session, &new);
    ogs_assert(ret == 0);
    ogs_assert(new == 0);

    ogs_debug("    Search the session");
    
    ret = fd_sess_state_retrieve(smf_gx_reg, session, &sess_data);
    ogs_assert(ret == 0);
    ogs_assert(sess_data);
    ogs_assert((void *)sess_data == data);

    ogs_debug("    Retrieve its data: [%s]", sess_data->gx_sid);

    /* Value of CC-Request-Number */
    ret = fd_msg_search_avp(*msg, ogs_diam_gx_cc_request_number, &avp);
    ogs_assert(ret == 0);
    if (avp) {
        ret = fd_msg_avp_hdr(avp, &hdr);
        ogs_assert(ret == 0);
        cc_request_number = hdr->avp_value->i32;
    } else {
        ogs_error("no_CC-Request-Number");
        ogs_assert_if_reached();
    }

    ogs_debug("    CC-Request-Number[%d]", cc_request_number);

    xact = sess_data->xact[cc_request_number];
    ogs_assert(xact);
    sess = sess_data->sess;
    ogs_assert(sess);

    gxbuf_len = sizeof(ogs_diam_gx_message_t);
    ogs_assert(gxbuf_len < 8192);
    gxbuf = ogs_pkbuf_alloc(NULL, gxbuf_len);
    ogs_assert(gxbuf);
    ogs_pkbuf_put(gxbuf, gxbuf_len);
    gx_message = (ogs_diam_gx_message_t *)gxbuf->data;
    ogs_assert(gx_message);

    /* Set Credit Control Command */
    memset(gx_message, 0, gxbuf_len);
    gx_message->cmd_code = OGS_DIAM_GX_CMD_CODE_CREDIT_CONTROL;
    
    /* Value of Result Code */
    ret = fd_msg_search_avp(*msg, ogs_diam_result_code, &avp);
    ogs_assert(ret == 0);
    if (avp) {
        ret = fd_msg_avp_hdr(avp, &hdr);
        ogs_assert(ret == 0);
        gx_message->result_code = hdr->avp_value->i32;
        gx_message->err = &gx_message->result_code;
        ogs_debug("    Result Code: %d", hdr->avp_value->i32);
    } else {
        ret = fd_msg_search_avp(*msg, ogs_diam_experimental_result, &avp);
        ogs_assert(ret == 0);
        if (avp) {
            ret = fd_avp_search_avp(
                    avp, ogs_diam_experimental_result_code, &avpch1);
            ogs_assert(ret == 0);
            if (avpch1) {
                ret = fd_msg_avp_hdr(avpch1, &hdr);
                ogs_assert(ret == 0);
                gx_message->result_code = hdr->avp_value->i32;
                gx_message->exp_err = &gx_message->result_code;
                ogs_debug("    Experimental Result Code: %d",
                        gx_message->result_code);
            }
        } else {
            ogs_error("no Result-Code");
            error++;
        }
    }

    /* Value of Origin-Host */
    ret = fd_msg_search_avp(*msg, ogs_diam_origin_host, &avp);
    ogs_assert(ret == 0);
    if (avp) {
        ret = fd_msg_avp_hdr(avp, &hdr);
        ogs_assert(ret == 0);
        ogs_debug("    From '%.*s'",
                (int)hdr->avp_value->os.len, hdr->avp_value->os.data);
    } else {
        ogs_error("no_Origin-Host");
        error++;
    }

    /* Value of Origin-Realm */
    ret = fd_msg_search_avp(*msg, ogs_diam_origin_realm, &avp);
    ogs_assert(ret == 0);
    if (avp) {
        ret = fd_msg_avp_hdr(avp, &hdr);
        ogs_assert(ret == 0);
        ogs_debug("         ('%.*s')",
                (int)hdr->avp_value->os.len, hdr->avp_value->os.data);
    } else {
        ogs_error("no_Origin-Realm");
        error++;
    }

    /* Value of CC-Request-Type */
    ret = fd_msg_search_avp(*msg, ogs_diam_gx_cc_request_type, &avp);
    ogs_assert(ret == 0);
    if (avp) {
        ret = fd_msg_avp_hdr(avp, &hdr);
        ogs_assert(ret == 0);
        gx_message->cc_request_type = hdr->avp_value->i32;
    } else {
        ogs_error("no_CC-Request-Type");
        error++;
    }

    if (gx_message->result_code != ER_DIAMETER_SUCCESS) {
        ogs_warn("ERROR DIAMETER Result Code(%d)", gx_message->result_code);
        goto out;
    }

    ret = fd_msg_search_avp(*msg, ogs_diam_gx_qos_information, &avp);
    ogs_assert(ret == 0);
    if (avp) {
        ret = fd_avp_search_avp(
                avp, ogs_diam_gx_apn_aggregate_max_bitrate_ul, &avpch1);
        ogs_assert(ret == 0);
        if (avpch1) {
            ret = fd_msg_avp_hdr(avpch1, &hdr);
            ogs_assert(ret == 0);
            gx_message->session_data.session.ambr.uplink = hdr->avp_value->u32;
        }
        ret = fd_avp_search_avp(
                avp, ogs_diam_gx_apn_aggregate_max_bitrate_dl, &avpch1);
        ogs_assert(ret == 0);
        if (avpch1) {
            ret = fd_msg_avp_hdr(avpch1, &hdr);
            ogs_assert(ret == 0);
            gx_message->session_data.session.ambr.downlink =
                hdr->avp_value->u32;
        }
    }

    ret = fd_msg_search_avp(*msg, ogs_diam_gx_default_eps_bearer_qos, &avp);
    ogs_assert(ret == 0);
    if (avp) {
        ret = fd_avp_search_avp(avp, ogs_diam_gx_qos_class_identifier, &avpch1);
        ogs_assert(ret == 0);
        if (avpch1) {
            ret = fd_msg_avp_hdr(avpch1, &hdr);
            ogs_assert(ret == 0);
            gx_message->session_data.session.qos.index = hdr->avp_value->u32;
        }

        ret = fd_avp_search_avp(
                avp, ogs_diam_gx_allocation_retention_priority, &avpch1);
        ogs_assert(ret == 0);
        if (avpch1) {
            ret = fd_avp_search_avp(
                    avpch1, ogs_diam_gx_priority_level, &avpch2);
            ogs_assert(ret == 0);
            if (avpch2) {
                ret = fd_msg_avp_hdr(avpch2, &hdr);
                ogs_assert(ret == 0);
                gx_message->session_data.session.qos.arp.priority_level =
                    hdr->avp_value->u32;
            }

            /*
             * Ch 7.3.40 Allocation-Retenion-Proirty in TS 29.272 V15.9.0
             *
             * If the Pre-emption-Capability AVP is not present in the
             * Allocation-Retention-Priority AVP, the default value shall be
             * PRE-EMPTION_CAPABILITY_DISABLED (1).
             *
             * If the Pre-emption-Vulnerability AVP is not present in the
             * Allocation-Retention-Priority AVP, the default value shall be
             * PRE-EMPTION_VULNERABILITY_ENABLED (0).
             *
             * However, to easily set up VoLTE service,
             * enable Pre-emption Capability/Vulnerablility
             * in Default Bearer
             */
            ret = fd_avp_search_avp(
                    avpch1, ogs_diam_gx_pre_emption_capability, &avpch2);
            ogs_assert(ret == 0);
            if (avpch2) {
                ret = fd_msg_avp_hdr(avpch2, &hdr);
                ogs_assert(ret == 0);
                gx_message->session_data.
                    session.qos.arp.pre_emption_capability =
                        hdr->avp_value->u32;
            } else {
                gx_message->session_data.
                    session.qos.arp.pre_emption_capability =
                        OGS_EPC_PRE_EMPTION_DISABLED;
            }

            ret = fd_avp_search_avp(avpch1,
                        ogs_diam_gx_pre_emption_vulnerability, &avpch2);
            ogs_assert(ret == 0);
            if (avpch2) {
                ret = fd_msg_avp_hdr(avpch2, &hdr);
                ogs_assert(ret == 0);
                gx_message->session_data.
                    session.qos.arp.pre_emption_vulnerability =
                        hdr->avp_value->u32;
            } else {
                gx_message->session_data.
                    session.qos.arp.pre_emption_vulnerability =
                        OGS_EPC_PRE_EMPTION_ENABLED;
            }
        }
    }

    ret = fd_msg_browse(*msg, MSG_BRW_FIRST_CHILD, &avp, NULL);
    ogs_assert(ret == 0);
    while (avp) {
        ret = fd_msg_avp_hdr(avp, &hdr);
        ogs_assert(ret == 0);
        switch (hdr->avp_code) {
        case AC_SESSION_ID:
        case AC_ORIGIN_HOST:
        case AC_ORIGIN_REALM:
        case AC_DESTINATION_REALM:
        case AC_RESULT_CODE:
        case AC_ROUTE_RECORD:
        case AC_PROXY_INFO:
        case AC_AUTH_APPLICATION_ID:
            break;
        case OGS_DIAM_GX_AVP_CODE_CC_REQUEST_TYPE:
        case OGS_DIAM_GX_AVP_CODE_CC_REQUEST_NUMBER:
        case OGS_DIAM_GX_AVP_CODE_SUPPORTED_FEATURES:
            break;
        case OGS_DIAM_GX_AVP_CODE_QOS_INFORMATION:
        case OGS_DIAM_GX_AVP_CODE_DEFAULT_EPS_BEARER_QOS:
            break;
        case OGS_DIAM_GX_AVP_CODE_CHARGING_RULE_INSTALL:
            ret = fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &avpch1, NULL);
            ogs_assert(ret == 0);
            while (avpch1) {
                ret = fd_msg_avp_hdr(avpch1, &hdr);
                ogs_assert(ret == 0);
                switch (hdr->avp_code) {
                case OGS_DIAM_GX_AVP_CODE_CHARGING_RULE_DEFINITION:
                    pcc_rule = &gx_message->session_data.pcc_rule
                            [gx_message->session_data.num_of_pcc_rule];

                    rv = decode_pcc_rule_definition(pcc_rule, avpch1, &error);
                    ogs_assert(rv == OGS_OK);

                    pcc_rule->type = OGS_PCC_RULE_TYPE_INSTALL;
                    gx_message->session_data.num_of_pcc_rule++;
                    break;
                default:
                    ogs_error("Not supported(%d)", hdr->avp_code);
                    break;
                }
                fd_msg_browse(avpch1, MSG_BRW_NEXT, &avpch1, NULL);
            }
            break;
        default:
            ogs_warn("Not supported(%d)", hdr->avp_code);
            break;
        }
        fd_msg_browse(avp, MSG_BRW_NEXT, &avp, NULL);
    }

out:
    if (!error) {
        e = smf_event_new(SMF_EVT_GX_MESSAGE);
        ogs_assert(e);

        e->sess = sess;
        e->pkbuf = gxbuf;
        e->gtp_xact = xact;
        rv = ogs_queue_push(ogs_app()->queue, e);
        if (rv != OGS_OK) {
            ogs_warn("ogs_queue_push() failed:%d", (int)rv);
            ogs_session_data_free(&gx_message->session_data);
            ogs_pkbuf_free(e->pkbuf);
            smf_event_free(e);
        } else {
            ogs_pollset_notify(ogs_app()->pollset);
        }
    } else {
        ogs_session_data_free(&gx_message->session_data);
        ogs_pkbuf_free(gxbuf);
    }

    /* Free the message */
    ogs_assert(pthread_mutex_lock(&ogs_diam_logger_self()->stats_lock) == 0);
    dur = ((ts.tv_sec - sess_data->ts.tv_sec) * 1000000) + 
        ((ts.tv_nsec - sess_data->ts.tv_nsec) / 1000);
    if (ogs_diam_logger_self()->stats.nb_recv) {
        /* Ponderate in the avg */
        ogs_diam_logger_self()->stats.avg = (ogs_diam_logger_self()->stats.avg * 
            ogs_diam_logger_self()->stats.nb_recv + dur) /
            (ogs_diam_logger_self()->stats.nb_recv + 1);
        /* Min, max */
        if (dur < ogs_diam_logger_self()->stats.shortest)
            ogs_diam_logger_self()->stats.shortest = dur;
        if (dur > ogs_diam_logger_self()->stats.longest)
            ogs_diam_logger_self()->stats.longest = dur;
    } else {
        ogs_diam_logger_self()->stats.shortest = dur;
        ogs_diam_logger_self()->stats.longest = dur;
        ogs_diam_logger_self()->stats.avg = dur;
    }
    if (error)
        ogs_diam_logger_self()->stats.nb_errs++;
    else 
        ogs_diam_logger_self()->stats.nb_recv++;

    ogs_assert(pthread_mutex_unlock(&ogs_diam_logger_self()->stats_lock) == 0);
    
    /* Display how long it took */
    if (ts.tv_nsec > sess_data->ts.tv_nsec)
        ogs_trace("in %d.%06ld sec", 
                (int)(ts.tv_sec - sess_data->ts.tv_sec),
                (long)(ts.tv_nsec - sess_data->ts.tv_nsec) / 1000);
    else
        ogs_trace("in %d.%06ld sec", 
                (int)(ts.tv_sec + 1 - sess_data->ts.tv_sec),
                (long)(1000000000 + ts.tv_nsec - sess_data->ts.tv_nsec) / 1000);

    ogs_debug("    CC-Request-Type[%d] Number[%d] in Session Data", 
        sess_data->cc_request_type, sess_data->cc_request_number);
    ogs_debug("    Current CC-Request-Number[%d]", cc_request_number);
    if (sess_data->cc_request_type ==
            OGS_DIAM_GX_CC_REQUEST_TYPE_TERMINATION_REQUEST &&
        sess_data->cc_request_number <= cc_request_number) {
        ogs_debug("    [LAST] state_cleanup(): [%s]", sess_data->gx_sid);
        state_cleanup(sess_data, NULL, NULL);
    } else {
        ogs_debug("    fd_sess_state_store(): [%s]", sess_data->gx_sid);
        ret = fd_sess_state_store(smf_gx_reg, session, &sess_data);
        ogs_assert(ret == 0);
        ogs_assert(sess_data == NULL);
    }

    ret = fd_msg_free(*msg);
    ogs_assert(ret == 0);
    *msg = NULL;
    
    return;
}

static int smf_gx_fb_cb(struct msg **msg, struct avp *avp, 
        struct session *sess, void *opaque, enum disp_action *act)
{
	/* This CB should never be called */
	ogs_warn("Unexpected message received!");
	
	return ENOTSUP;
}

static int smf_gx_rar_cb( struct msg **msg, struct avp *avp, 
        struct session *session, void *opaque, enum disp_action *act)
{
    int rv;
    int ret;

	struct msg *ans, *qry;
    struct avp *avpch1;
    struct avp_hdr *hdr;
    union avp_value val;
    struct sess_state *sess_data = NULL;

    smf_event_t *e = NULL;
    uint16_t gxbuf_len = 0;
    ogs_pkbuf_t *gxbuf = NULL;
    smf_sess_t *sess = NULL;
    ogs_diam_gx_message_t *gx_message = NULL;
    ogs_pcc_rule_t *pcc_rule = NULL;

    uint32_t result_code = OGS_DIAM_UNKNOWN_SESSION_ID;
	
    ogs_assert(msg);

    ogs_debug("Re-Auth-Request");

    gxbuf_len = sizeof(ogs_diam_gx_message_t);
    ogs_assert(gxbuf_len < 8192);
    gxbuf = ogs_pkbuf_alloc(NULL, gxbuf_len);
    ogs_assert(gxbuf);
    ogs_pkbuf_put(gxbuf, gxbuf_len);
    gx_message = (ogs_diam_gx_message_t *)gxbuf->data;
    ogs_assert(gx_message);

    /* Set Credit Control Command */
    memset(gx_message, 0, gxbuf_len);
    gx_message->cmd_code = OGS_DIAM_GX_CMD_RE_AUTH;

	/* Create answer header */
	qry = *msg;
	ret = fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0);
    ogs_assert(ret == 0);
    ans = *msg;

    ret = fd_sess_state_retrieve(smf_gx_reg, session, &sess_data);
    ogs_assert(ret == 0);
    if (!sess_data) {
        ogs_error("No Session Data");
        goto out;
    }

    /* Get Session Information */
    sess = sess_data->sess;
    ogs_assert(sess);

    ret = fd_msg_browse(qry, MSG_BRW_FIRST_CHILD, &avp, NULL);
    ogs_assert(ret == 0);
    while (avp) {
        ret = fd_msg_avp_hdr(avp, &hdr);
        ogs_assert(ret == 0);
        switch(hdr->avp_code) {
        case AC_SESSION_ID:
        case AC_ORIGIN_HOST:
        case AC_ORIGIN_REALM:
        case AC_DESTINATION_REALM:
        case AC_DESTINATION_HOST:
        case AC_ROUTE_RECORD:
        case AC_PROXY_INFO:
        case AC_AUTH_APPLICATION_ID:
            break;
        case OGS_DIAM_GX_AVP_CODE_RE_AUTH_REQUEST_TYPE:
            break;
        case OGS_DIAM_GX_AVP_CODE_CHARGING_RULE_INSTALL:
            ret = fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &avpch1, NULL);
            ogs_assert(ret == 0);
            while(avpch1) {
                ret = fd_msg_avp_hdr(avpch1, &hdr);
                ogs_assert(ret == 0);
                switch(hdr->avp_code) {
                case OGS_DIAM_GX_AVP_CODE_CHARGING_RULE_DEFINITION:
                    pcc_rule = &gx_message->session_data.pcc_rule
                            [gx_message->session_data.num_of_pcc_rule];

                    rv = decode_pcc_rule_definition(pcc_rule, avpch1, NULL);
                    ogs_assert(rv == OGS_OK);

                    pcc_rule->type = OGS_PCC_RULE_TYPE_INSTALL;
                    gx_message->session_data.num_of_pcc_rule++;
                    break;
                default:
                    ogs_error("Not supported(%d)", hdr->avp_code);
                    break;
                }
                fd_msg_browse(avpch1, MSG_BRW_NEXT, &avpch1, NULL);
            }
            break;
        case OGS_DIAM_GX_AVP_CODE_CHARGING_RULE_REMOVE:
            ret = fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &avpch1, NULL);
            ogs_assert(ret == 0);
            while (avpch1) {
                ret = fd_msg_avp_hdr(avpch1, &hdr);
                ogs_assert(ret == 0);
                switch (hdr->avp_code) {
                case OGS_DIAM_GX_AVP_CODE_CHARGING_RULE_NAME:
                    pcc_rule = &gx_message->session_data.pcc_rule
                            [gx_message->session_data.num_of_pcc_rule];

                    pcc_rule->name = ogs_strdup((char*)hdr->avp_value->os.data);
                    ogs_assert(pcc_rule->name);

                    pcc_rule->type = OGS_PCC_RULE_TYPE_REMOVE;
                    gx_message->session_data.num_of_pcc_rule++;
                    break;
                default:
                    ogs_error("Not supported(%d)", hdr->avp_code);
                    break;
                }
                fd_msg_browse(avpch1, MSG_BRW_NEXT, &avpch1, NULL);
            }
            break;
        default:
            ogs_warn("Not supported(%d)", hdr->avp_code);
            break;
        }
        fd_msg_browse(avp, MSG_BRW_NEXT, &avp, NULL);
    }

    /* Send Gx Event to SMF State Machine */
    e = smf_event_new(SMF_EVT_GX_MESSAGE);
    ogs_assert(e);

    e->sess = sess;
    e->pkbuf = gxbuf;
    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_warn("ogs_queue_push() failed:%d", (int)rv);
        ogs_session_data_free(&gx_message->session_data);
        ogs_pkbuf_free(e->pkbuf);
        smf_event_free(e);
    } else {
        ogs_pollset_notify(ogs_app()->pollset);
    }

    /* Set the Auth-Application-Id AVP */
    ret = fd_msg_avp_new(ogs_diam_auth_application_id, 0, &avp);
    ogs_assert(ret == 0);
    val.i32 = OGS_DIAM_GX_APPLICATION_ID;
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

	/* Set the Origin-Host, Origin-Realm, andResult-Code AVPs */
	ret = fd_msg_rescode_set(ans, (char *)"DIAMETER_SUCCESS", NULL, NULL, 1);
    ogs_assert(ret == 0);

    /* Store this value in the session */
    ret = fd_sess_state_store(smf_gx_reg, session, &sess_data);
    ogs_assert(ret == 0);
    ogs_assert(sess_data == NULL);

	/* Send the answer */
	ret = fd_msg_send(msg, NULL, NULL);
    ogs_assert(ret == 0);

    ogs_debug("Re-Auth-Answer");

	/* Add this value to the stats */
	ogs_assert(pthread_mutex_lock(&ogs_diam_logger_self()->stats_lock) == 0);
	ogs_diam_logger_self()->stats.nb_echoed++;
	ogs_assert(pthread_mutex_unlock(&ogs_diam_logger_self()->stats_lock) == 0);

    return 0;

out:
    if (result_code == OGS_DIAM_UNKNOWN_SESSION_ID) {
        ret = fd_msg_rescode_set(ans,
                    (char *)"DIAMETER_UNKNOWN_SESSION_ID", NULL, NULL, 1);
        ogs_assert(ret == 0);
    } else {
        ret = ogs_diam_message_experimental_rescode_set(ans, result_code);
        ogs_assert(ret == 0);
    }

    /* Store this value in the session */
    if (sess_data) {
        ret = fd_sess_state_store(smf_gx_reg, session, &sess_data);
        ogs_assert(ret == 0);
        ogs_assert(sess_data == NULL);
    }

    ret = fd_msg_send(msg, NULL, NULL);
    ogs_assert(ret == 0);

    ogs_session_data_free(&gx_message->session_data);
    ogs_pkbuf_free(gxbuf);

    return 0;
}

int smf_gx_init(void)
{
    int ret;
	struct disp_when data;

    ogs_thread_mutex_init(&sess_state_mutex);
    ogs_pool_init(&sess_state_pool, ogs_app()->pool.sess);

	/* Install objects definitions for this application */
	ret = ogs_diam_gx_init();
    ogs_assert(ret == 0);

    /* Create handler for sessions */
	ret = fd_sess_handler_create(&smf_gx_reg, state_cleanup, NULL, NULL);
    ogs_assert(ret == 0);

	memset(&data, 0, sizeof(data));
	data.app = ogs_diam_gx_application;

	ret = fd_disp_register(smf_gx_fb_cb, DISP_HOW_APPID, &data, NULL,
                &hdl_gx_fb);
    ogs_assert(ret == 0);

	data.command = ogs_diam_gx_cmd_rar;
	ret = fd_disp_register(smf_gx_rar_cb, DISP_HOW_CC, &data, NULL,
                &hdl_gx_rar);
    ogs_assert(ret == 0);

	/* Advertise the support for the application in the peer */
	ret = fd_disp_app_support(ogs_diam_gx_application, ogs_diam_vendor, 1, 0);
    ogs_assert(ret == 0);

	return OGS_OK;
}

void smf_gx_final(void)
{
    int ret;

	ret = fd_sess_handler_destroy(&smf_gx_reg, NULL);
    ogs_assert(ret == 0);

	if (hdl_gx_fb)
		(void) fd_disp_unregister(&hdl_gx_fb, NULL);
	if (hdl_gx_rar)
		(void) fd_disp_unregister(&hdl_gx_rar, NULL);

    ogs_pool_final(&sess_state_pool);
    ogs_thread_mutex_destroy(&sess_state_mutex);
}

static int decode_pcc_rule_definition(
        ogs_pcc_rule_t *pcc_rule, struct avp *avpch1, int *perror)
{
    int ret = 0, error = 0;
    struct avp *avpch2, *avpch3, *avpch4;
    struct avp_hdr *hdr;

    ogs_assert(pcc_rule);
    ogs_assert(avpch1);

    ret = fd_msg_browse(avpch1, MSG_BRW_FIRST_CHILD, &avpch2, NULL);
    ogs_assert(ret == 0);
    while (avpch2) {
        ogs_flow_t *flow = NULL;

        ret = fd_msg_avp_hdr(avpch2, &hdr);
        ogs_assert(ret == 0);
        switch (hdr->avp_code) {
        case OGS_DIAM_GX_AVP_CODE_CHARGING_RULE_NAME:
            if (pcc_rule->name) {
                ogs_error("PCC Rule Name has already been defined");
                ogs_free(pcc_rule->name);
            }
            pcc_rule->name = ogs_strdup((char*)hdr->avp_value->os.data);
            ogs_assert(pcc_rule->name);
            break;
        case OGS_DIAM_GX_AVP_CODE_FLOW_INFORMATION:
            flow = &pcc_rule->flow[pcc_rule->num_of_flow];

            ret = fd_avp_search_avp(
                    avpch2, ogs_diam_gx_flow_direction, &avpch3);
            ogs_assert(ret == 0);
            if (avpch3) {
                ret = fd_msg_avp_hdr( avpch3, &hdr);
                ogs_assert(ret == 0);
                flow->direction = hdr->avp_value->i32;
            }

            ret = fd_avp_search_avp(
                    avpch2, ogs_diam_gx_flow_description, &avpch3);
            ogs_assert(ret == 0);
            if (avpch3) {
                ret = fd_msg_avp_hdr(avpch3, &hdr);
                ogs_assert(ret == 0);
                flow->description = ogs_malloc(hdr->avp_value->os.len+1);
                ogs_assert(flow->description);
                ogs_cpystrn(flow->description,
                    (char*)hdr->avp_value->os.data,
                    hdr->avp_value->os.len+1);
            }

            pcc_rule->num_of_flow++;
            break;
        case OGS_DIAM_GX_AVP_CODE_FLOW_STATUS:
            pcc_rule->flow_status = hdr->avp_value->i32;
            break;
        case OGS_DIAM_GX_AVP_CODE_QOS_INFORMATION:
            ret = fd_avp_search_avp(avpch2,
                ogs_diam_gx_qos_class_identifier, &avpch3);
            ogs_assert(ret == 0);
            if (avpch3) {
                ret = fd_msg_avp_hdr(avpch3, &hdr);
                ogs_assert(ret == 0);
                pcc_rule->qos.index = hdr->avp_value->u32;
            } else {
                ogs_error("no_QCI");
                error++;
            }

            ret = fd_avp_search_avp(avpch2,
                ogs_diam_gx_allocation_retention_priority, &avpch3);
            ogs_assert(ret == 0);
            if (avpch3) {
                ret = fd_avp_search_avp(
                        avpch3, ogs_diam_gx_priority_level, &avpch4);
                ogs_assert(ret == 0);
                if (avpch4) {
                    ret = fd_msg_avp_hdr(avpch4, &hdr);
                    ogs_assert(ret == 0);
                    pcc_rule->qos.arp.priority_level = hdr->avp_value->u32;
                } else {
                    ogs_error("no_Priority-Level");
                    error++;
                }

                /*
                 * Ch 7.3.40 Allocation-Retenion-Proirty in TS 29.272 V15.9.0
                 *
                 * If the Pre-emption-Capability AVP is not present in the
                 * Allocation-Retention-Priority AVP, the default value shall be
                 * PRE-EMPTION_CAPABILITY_DISABLED (1).
                 *
                 * If the Pre-emption-Vulnerability AVP is not present in the
                 * Allocation-Retention-Priority AVP, the default value shall be
                 * PRE-EMPTION_VULNERABILITY_ENABLED (0).
                 *
                 * However, to easily set up VoLTE service,
                 * enable Pre-emption Capability/Vulnerablility
                 * in Default Bearer
                 */
                ret = fd_avp_search_avp(avpch3,
                    ogs_diam_gx_pre_emption_capability, &avpch4);
                ogs_assert(ret == 0);
                if (avpch4) {
                    ret = fd_msg_avp_hdr(avpch4, &hdr);
                    ogs_assert(ret == 0);
                    pcc_rule->qos.arp.pre_emption_capability =
                            hdr->avp_value->u32;
                } else {
                    pcc_rule->qos.arp.pre_emption_capability =
                        OGS_EPC_PRE_EMPTION_DISABLED;
                }

                ret = fd_avp_search_avp(avpch3,
                        ogs_diam_gx_pre_emption_vulnerability, &avpch4);
                ogs_assert(ret == 0);
                if (avpch4) {
                    ret = fd_msg_avp_hdr(avpch4, &hdr);
                    ogs_assert(ret == 0);
                    pcc_rule->qos.arp.pre_emption_vulnerability =
                            hdr->avp_value->u32;
                } else {
                    pcc_rule->qos.arp.pre_emption_vulnerability =
                        OGS_EPC_PRE_EMPTION_ENABLED;

                }
            } else {
                ogs_error("no_ARP");
                error++;
            }

            ret = fd_avp_search_avp(avpch2,
                    ogs_diam_gx_max_requested_bandwidth_ul, &avpch3);
            ogs_assert(ret == 0);
            if (avpch3) {
                ret = fd_msg_avp_hdr(avpch3, &hdr);
                ogs_assert(ret == 0);
                pcc_rule->qos.mbr.uplink = hdr->avp_value->u32;
            }
            ret = fd_avp_search_avp(avpch2,
                ogs_diam_gx_max_requested_bandwidth_dl, &avpch3);
            ogs_assert(ret == 0);
            if (avpch3) {
                ret = fd_msg_avp_hdr(avpch3, &hdr);
                ogs_assert(ret == 0);
                pcc_rule->qos.mbr.downlink = hdr->avp_value->u32;
            }
            ret = fd_avp_search_avp(avpch2,
                    ogs_diam_gx_guaranteed_bitrate_ul, &avpch3);
            ogs_assert(ret == 0);
            if (avpch3) {
                ret = fd_msg_avp_hdr(avpch3, &hdr);
                ogs_assert(ret == 0);
                pcc_rule->qos.gbr.uplink = hdr->avp_value->u32;
            }
            ret = fd_avp_search_avp(avpch2,
                ogs_diam_gx_guaranteed_bitrate_dl, &avpch3);
            ogs_assert(ret == 0);
            if (avpch3) {
                ret = fd_msg_avp_hdr(avpch3, &hdr);
                ogs_assert(ret == 0);
                pcc_rule->qos.gbr.downlink = hdr->avp_value->u32;
            }
            break;
        case OGS_DIAM_GX_AVP_CODE_PRECEDENCE:
            pcc_rule->precedence = hdr->avp_value->i32;
            break;
        default:
            ogs_error("Not implemented(%d)", hdr->avp_code);
            break;
        }
        fd_msg_browse(avpch2, MSG_BRW_NEXT, &avpch2, NULL);
    }

    if (perror)
        *perror = error;

    return OGS_OK;
}
