/* Copyright (c) 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "physical.h"
#include "match.h"
#include "ofctrl.h"
#include "ofp-actions.h"
#include "ofpbuf.h"
#include "ovn-controller.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "openvswitch/vlog.h"
#include "pipeline.h"
#include "simap.h"
#include "sset.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(physical);

void
physical_init(struct controller_ctx *ctx)
{
    ovsdb_idl_add_table(ctx->ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ctx->ovs_idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_port_col_external_ids);

    ovsdb_idl_add_table(ctx->ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_interface_col_external_ids);
}

/* Maps from a chassis to the OpenFlow port number of the tunnel that can be
 * used to reach that chassis. */
struct chassis_tunnel {
    struct hmap_node hmap_node;
    const char *chassis_id;
    ofp_port_t ofport;
    enum chassis_tunnel_type { GENEVE, STT } type;
};

static struct chassis_tunnel *
chassis_tunnel_find(struct hmap *tunnels, const char *chassis_id)
{
    struct chassis_tunnel *tun;
    HMAP_FOR_EACH_WITH_HASH (tun, hmap_node, hash_string(chassis_id, 0),
                             tunnels) {
        if (!strcmp(tun->chassis_id, chassis_id)) {
            return tun;
        }
    }
    return NULL;
}

static void
put_load(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_SET_FIELD(ofpacts);
    sf->field = mf_from_id(dst);
    sf->flow_has_vlan = false;

    ovs_be64 n_value = htonll(value);
    bitwise_copy(&n_value, 8, 0, &sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(&sf->mask, sf->field->n_bytes, ofs, n_bits);
}

static void
put_move(enum mf_field_id src, int src_ofs,
         enum mf_field_id dst, int dst_ofs,
         int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_reg_move *move = ofpact_put_REG_MOVE(ofpacts);
    move->src.field = mf_from_id(src);
    move->src.ofs = src_ofs;
    move->src.n_bits = n_bits;
    move->dst.field = mf_from_id(dst);
    move->dst.ofs = dst_ofs;
    move->dst.n_bits = n_bits;
}

static void
put_resubmit(uint8_t table_id, struct ofpbuf *ofpacts)
{
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(ofpacts);
    resubmit->in_port = OFPP_IN_PORT;
    resubmit->table_id = table_id;
}

static void
put_encapsulation(const struct chassis_tunnel *tun,
                  const struct sbrec_datapath_binding *datapath,
                  uint16_t outport, struct ofpbuf *ofpacts)
{
    if (tun->type == GENEVE) {
        put_load(datapath->tunnel_key, MFF_TUN_ID, 0, 24, ofpacts);
        put_load(outport, MFF_TUN_METADATA0, 0, 32, ofpacts);
        put_move(MFF_LOG_INPORT, 0, MFF_TUN_METADATA0, 16, 15, ofpacts);
    } else if (tun->type == STT) {
        put_load(datapath->tunnel_key | (outport << 24), MFF_TUN_ID, 0, 64,
                 ofpacts);
        put_move(MFF_LOG_INPORT, 0, MFF_TUN_ID, 40, 15, ofpacts);
    } else {
        OVS_NOT_REACHED();
    }
}

void
physical_run(struct controller_ctx *ctx)
{
    struct simap lport_to_ofport = SIMAP_INITIALIZER(&lport_to_ofport);
    struct hmap tunnels = HMAP_INITIALIZER(&tunnels);
    for (int i = 0; i < ctx->br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = ctx->br_int->ports[i];
        if (!strcmp(port_rec->name, ctx->br_int_name)) {
            continue;
        }

        const char *chassis_id = smap_get(&port_rec->external_ids,
                                          "ovn-chassis-id");
        if (chassis_id && !strcmp(chassis_id, ctx->chassis_id)) {
            continue;
        }

        for (int j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec = port_rec->interfaces[j];

            /* Get OpenFlow port number. */
            if (!iface_rec->n_ofport) {
                continue;
            }
            int64_t ofport = iface_rec->ofport[0];
            if (ofport < 1 || ofport > ofp_to_u16(OFPP_MAX)) {
                continue;
            }

            /* Record as chassis or local logical port. */
            if (chassis_id) {
                enum chassis_tunnel_type tunnel_type;
                if (!strcmp(iface_rec->type, "geneve")) {
                    tunnel_type = GENEVE;
                } else if (!strcmp(iface_rec->type, "stt")) {
                    tunnel_type = STT;
                } else {
                    continue;
                }

                struct chassis_tunnel *tun = xmalloc(sizeof *tun);
                hmap_insert(&tunnels, &tun->hmap_node,
                            hash_string(chassis_id, 0));
                tun->chassis_id = chassis_id;
                tun->ofport = u16_to_ofp(ofport);
                tun->type = tunnel_type;
                break;
            } else {
                const char *iface_id = smap_get(&iface_rec->external_ids,
                                                "iface-id");
                if (iface_id) {
                    simap_put(&lport_to_ofport, iface_id, ofport);
                }
            }
        }
    }

    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);

    /* Set up flows in table 0 for physical-to-logical translation and in table
     * 64 for logical-to-physical translation. */
    const struct sbrec_port_binding *binding;
    SBREC_PORT_BINDING_FOR_EACH (binding, ctx->ovnsb_idl) {
        /* Find the Openflow port for the logical port, as 'ofport'.  If it's
         * on a remote chassis, this is the OpenFlow port for the tunnel to
         * that chassis (and set 'local' to false).  Otherwise, if it's on the
         * chassis we're managing, this is the OpenFlow port for the vif itself
         * (and set 'local' to true). When 'parent_port' is set for a binding,
         * it implies a container sitting inside a VM reachable via a 'tag'.
         */

        int tag = 0;
        ofp_port_t ofport;
        if (binding->parent_port) {
            ofport = u16_to_ofp(simap_get(&lport_to_ofport,
                                          binding->parent_port));
            if (ofport && binding->tag) {
                tag = *binding->tag;
            }
        } else {
            ofport = u16_to_ofp(simap_get(&lport_to_ofport,
                                          binding->logical_port));
        }

        const struct chassis_tunnel *tun = NULL;
        if (!ofport) {
            if (!binding->chassis) {
                continue;
            }
            tun = chassis_tunnel_find(&tunnels, binding->chassis->name);
            if (!tun) {
                continue;
            }
            ofport = tun->ofport;
        }

        struct match match;
        if (!tun) {
            /*
             * Packets that arrive from a vif can belong to a VM or
             * to a container located inside that VM. Packets that
             * arrive from containers have a tag (vlan) associated with them.
             *
             * Table 0, Priority 150 and 100.
             * ==============================
             * Priority 150 is for traffic belonging to containers. For such
             * traffic, match on the tags and then strip the tag.
             * Priority 100 is for traffic belonging to VMs.
             *
             * For both types of traffic: set MFF_LOG_INPORT to the logical
             * input port, MFF_LOG_DATAPATH to the logical datapath, and
             * resubmit into the logical pipeline starting at table 16. */
            match_init_catchall(&match);
            ofpbuf_clear(&ofpacts);
            match_set_in_port(&match, ofport);
            if (tag) {
                match_set_dl_vlan(&match, htons(tag));
            }

            /* Set MFF_LOG_DATAPATH and MFF_LOG_INPORT. */
            put_load(binding->datapath->tunnel_key, MFF_LOG_DATAPATH, 0, 64,
                     &ofpacts);
            put_load(binding->tunnel_key, MFF_LOG_INPORT, 0, 32, &ofpacts);

            /* Strip vlans. */
            if (tag) {
                ofpact_put_STRIP_VLAN(&ofpacts);
            }

            /* Resubmit to first logical pipeline table. */
            put_resubmit(16, &ofpacts);
            ofctrl_add_flow(0, tag ? 150 : 100, &match, &ofpacts);

            /* Table 33, priority 100.
             * =======================
             *
             * Implements output to local hypervisor.  Each flow matches a
             * logical output port on the local hypervisor, and resubmits to
             * table 34.
             *
             * XXX multicast groups
             */

            match_init_catchall(&match);
            ofpbuf_clear(&ofpacts);

            /* Match MFF_LOG_DATAPATH, MFF_LOG_OUTPORT. */
            match_set_metadata(&match, htonll(binding->datapath->tunnel_key));
            match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0,
                          binding->tunnel_key);

            /* Resubmit to table 34. */
            put_resubmit(34, &ofpacts);
            ofctrl_add_flow(34, 100, &match, &ofpacts);
        } else {
            /* Table 0, priority 100.
             * ======================
             *
             * For packets that arrive from a remote hypervisor (by matching a
             * tunnel in_port), set MFF_LOG_DATAPATH, MFF_LOG_INPORT, and
             * MFF_LOG_OUTPORT from the tunnel key data, then resubmit to table
             * 33 to handle packets to the local hypervisor. */

            match_init_catchall(&match);
            match_set_in_port(&match, tun->ofport);

            ofpbuf_clear(&ofpacts);
            if (tun->type == GENEVE) {
                put_move(MFF_TUN_ID, 0,  MFF_LOG_DATAPATH, 0, 24, &ofpacts);
                put_move(MFF_TUN_METADATA0, 16, MFF_LOG_INPORT, 0, 15,
                         &ofpacts);
                put_move(MFF_TUN_METADATA0, 0, MFF_LOG_OUTPORT, 0, 16,
                         &ofpacts);
            } else if (tun->type == STT) {
                put_move(MFF_TUN_ID, 40, MFF_LOG_INPORT,   0, 15, &ofpacts);
                put_move(MFF_TUN_ID, 24, MFF_LOG_OUTPORT,  0, 16, &ofpacts);
                put_move(MFF_TUN_ID,  0, MFF_LOG_DATAPATH, 0, 24, &ofpacts);
            } else {
                OVS_NOT_REACHED();
            }
            put_resubmit(33, &ofpacts);

            ofctrl_add_flow(0, 100, &match, &ofpacts);

            /* Table 32, priority 100.
             * =======================
             *
             * Implements output to remote hypervisors.  Each flow matches an
             * output port that includes a logical port on a remote hypervisor,
             * and tunnels the packet to that hypervisor.
             *
             * XXX multicast groups
             */

            match_init_catchall(&match);
            ofpbuf_clear(&ofpacts);

            /* Match MFF_LOG_DATAPATH, MFF_LOG_OUTPORT. */
            match_set_metadata(&match, htonll(binding->datapath->tunnel_key));
            match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0,
                          binding->tunnel_key);

            put_encapsulation(tun, binding->datapath,
                              binding->tunnel_key, &ofpacts);

            /* Output to tunnel. */
            ofpact_put_OUTPUT(&ofpacts)->port = ofport;
            ofctrl_add_flow(32, 100, &match, &ofpacts);
        }

        /* Table 34, Priority 100.
         * =======================
         *
         * Drop packets whose logical inport and outport are the same. */
        match_init_catchall(&match);
        ofpbuf_clear(&ofpacts);
        match_set_metadata(&match, htonll(binding->datapath->tunnel_key));
        match_set_reg(&match, MFF_LOG_INPORT - MFF_REG0, binding->tunnel_key);
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, binding->tunnel_key);
        ofctrl_add_flow(34, 100, &match, &ofpacts);

        /* Table 64, Priority 100.
         * ======================
         *
         * Deliver the packet to the local vif. */
        match_init_catchall(&match);
        ofpbuf_clear(&ofpacts);
        match_set_metadata(&match, htonll(binding->datapath->tunnel_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, binding->tunnel_key);
        if (tag) {
            /* For containers sitting behind a local vif, tag the packets
             * before delivering them. */
            struct ofpact_vlan_vid *vlan_vid;
            vlan_vid = ofpact_put_SET_VLAN_VID(&ofpacts);
            vlan_vid->vlan_vid = tag;
            vlan_vid->push_vlan_if_needed = true;

            /* A packet might need to hair-pin back into its ingress OpenFlow
             * port (to a different logical port, which we already checked back
             * in table 34), so set the in_port to zero. */
            put_load(0, MFF_IN_PORT, 0, 16, &ofpacts);
        }
        ofpact_put_OUTPUT(&ofpacts)->port = ofport;
        ofctrl_add_flow(64, 100, &match, &ofpacts);
    }

    const struct sbrec_multicast_group *mc;
    SBREC_MULTICAST_GROUP_FOR_EACH (mc, ctx->ovnsb_idl) {
        struct sset remote_chassis = SSET_INITIALIZER(&remote_chassis);
        struct match match;

        match_init_catchall(&match);
        match_set_metadata(&match, htonll(mc->datapath->tunnel_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, mc->tunnel_key);

        ofpbuf_clear(&ofpacts);
        for (size_t i = 0; i < mc->n_ports; i++) {
            struct sbrec_port_binding *port = mc->ports[i];

            if (port->datapath != mc->datapath) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, UUID_FMT": multicast group contains ports "
                             "in wrong datapath",
                             UUID_ARGS(&mc->header_.uuid));
                continue;
            }

            if (simap_contains(&lport_to_ofport, port->logical_port)) {
                put_load(port->tunnel_key, MFF_LOG_OUTPORT, 0, 32, &ofpacts);
                put_resubmit(34, &ofpacts);
            } else if (port->chassis) {
                sset_add(&remote_chassis, port->chassis->name);
            }
        }

        bool local_ports = ofpacts.size > 0;
        if (local_ports) {
            ofctrl_add_flow(33, 100, &match, &ofpacts);
        }

        if (!sset_is_empty(&remote_chassis)) {
            ofpbuf_clear(&ofpacts);

            const char *chassis;
            const struct chassis_tunnel *prev = NULL;
            SSET_FOR_EACH (chassis, &remote_chassis) {
                const struct chassis_tunnel *tun
                    = chassis_tunnel_find(&tunnels, chassis);
                if (!tun) {
                    continue;
                }

                if (!prev || tun->type != prev->type) {
                    put_encapsulation(tun, mc->datapath, mc->tunnel_key,
                                      &ofpacts);
                    prev = tun;
                }
                ofpact_put_OUTPUT(&ofpacts)->port = tun->ofport;
            }

            if (ofpacts.size) {
                if (local_ports) {
                    put_resubmit(33, &ofpacts);
                }
                ofctrl_add_flow(32, 100, &match, &ofpacts);
            }
        }
        sset_destroy(&remote_chassis);
    }

    /* Table 34, Priority 0.
     * =======================
     *
     * Resubmit packets that don't output to the ingress port to the egress
     * pipeline. */
    struct match match;
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);
    put_resubmit(48, &ofpacts);
    ofctrl_add_flow(34, 0, &match, &ofpacts);

    ofpbuf_uninit(&ofpacts);
    simap_destroy(&lport_to_ofport);
    struct chassis_tunnel *tun, *tun_next;
    HMAP_FOR_EACH_SAFE (tun, tun_next, hmap_node, &tunnels) {
        hmap_remove(&tunnels, &tun->hmap_node);
        free(tun);
    }
    hmap_destroy(&tunnels);
}
