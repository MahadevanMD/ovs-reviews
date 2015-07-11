/*
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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "hmap.h"
#include "json.h"
#include "ovn/lib/lex.h"
#include "ovn/lib/ovn-nb-idl.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "poll-loop.h"
#include "smap.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_northd);

static unixctl_cb_func ovn_northd_exit;

struct northd_context {
    struct ovsdb_idl *ovnnb_idl;
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl_txn *ovnnb_txn;
    struct ovsdb_idl_txn *ovnsb_txn;
};

static const char *ovnnb_db;
static const char *ovnsb_db;

static const char *default_db(void);

static void
usage(void)
{
    printf("\
%s: OVN northbound management daemon\n\
usage: %s [OPTIONS]\n\
\n\
Options:\n\
  --ovnnb-db=DATABASE       connect to ovn-nb database at DATABASE\n\
                            (default: %s)\n\
  --ovnsb-db=DATABASE       connect to ovn-sb database at DATABASE\n\
                            (default: %s)\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_db(), default_db());
    daemon_usage();
    vlog_usage();
    stream_usage("database", true, true, false);
}

struct key_node {
    struct hmap_node hmap_node;
    uint32_t key;
};

static void
keys_destroy(struct hmap *keys)
{
    struct key_node *node, *next;
    HMAP_FOR_EACH_SAFE (node, next, hmap_node, keys) {
        hmap_remove(keys, &node->hmap_node);
        free(node);
    }
    hmap_destroy(keys);
}

static void
add_key(struct hmap *set, uint32_t key)
{
    struct key_node *node = xmalloc(sizeof *node);
    hmap_insert(set, &node->hmap_node, hash_int(key, 0));
    node->key = key;
}

static bool
key_in_use(const struct hmap *set, uint32_t key)
{
    const struct key_node *node;
    HMAP_FOR_EACH_IN_BUCKET (node, hmap_node, hash_int(key, 0), set) {
        if (node->key == key) {
            return true;
        }
    }
    return false;
}

static uint32_t
allocate_key(struct hmap *set, const char *name, uint32_t max, uint32_t *prev)
{
    for (uint32_t key = *prev + 1; key != *prev;
         key = key + 1 <= max ? key + 1 : 1) {
        if (!key_in_use(set, key)) {
            add_key(set, key);
            *prev = key;
            return key;
        }
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    VLOG_WARN_RL(&rl, "all %s tunnel keys exhausted", name);
    return 0;
}

/* The 'key' comes from nb->header_.uuid or sb->external_ids's ' */
struct ovn_datapath {
    struct hmap_node key_node;  /* Index on 'key'. */
    struct uuid key;            /* nb->header_.uuid. */

    const struct nbrec_logical_switch *nb;   /* May be NULL. */
    const struct sbrec_datapath_binding *sb; /* May be NULL. */

    struct ovs_list list;       /* In list of similar records. */

    struct hmap port_keys;
    uint32_t max_port_key;

    bool has_unknown;
};

static struct ovn_datapath *
ovn_datapath_create(struct hmap *dp_map, const struct uuid *key,
                    const struct nbrec_logical_switch *nb,
                    const struct sbrec_datapath_binding *sb)
{
    struct ovn_datapath *od = xzalloc(sizeof *od);
    od->key = *key;
    od->sb = sb;
    od->nb = nb;
    hmap_init(&od->port_keys);
    od->max_port_key = 0;
    hmap_insert(dp_map, &od->key_node, uuid_hash(&od->key));
    return od;
}

static void
ovn_datapath_destroy(struct hmap *dp_map, struct ovn_datapath *od)
{
    if (od) {
        /* Don't remove od->list, it's only safe and only used within
         * build_datapaths(). */
        hmap_remove(dp_map, &od->key_node);
        keys_destroy(&od->port_keys);
        free(od);
    }
}

static struct ovn_datapath *
ovn_datapath_find(struct hmap *dp_map, const struct uuid *uuid)
{
    struct ovn_datapath *od;

    HMAP_FOR_EACH_WITH_HASH (od, key_node, uuid_hash(uuid), dp_map) {
        if (uuid_equals(uuid, &od->key)) {
            return od;
        }
    }
    return NULL;
}

static struct ovn_datapath *
ovn_datapath_from_sbrec(struct hmap *dp_map,
                        const struct sbrec_datapath_binding *sb)
{
    struct uuid key;

    if (!smap_get_uuid(&sb->external_ids, "logical-switch", &key)) {
        return NULL;
    }
    return ovn_datapath_find(dp_map, &key);
}

static void
join_datapaths(struct northd_context *ctx, struct hmap *dp_map,
               struct ovs_list *sb_only, struct ovs_list *nb_only,
               struct ovs_list *both)
{
    hmap_init(dp_map);
    list_init(sb_only);
    list_init(nb_only);
    list_init(both);

    const struct sbrec_datapath_binding *sb, *sb_next;
    SBREC_DATAPATH_BINDING_FOR_EACH_SAFE (sb, sb_next, ctx->ovnsb_idl) {
        struct uuid key;
        if (!smap_get_uuid(&sb->external_ids, "logical-switch", &key)) {
            ovsdb_idl_txn_add_comment(ctx->ovnsb_txn,
                                      "deleting Datapath_Binding "UUID_FMT" that "
                                      "lacks external-ids:logical-switch",
                         UUID_ARGS(&sb->header_.uuid));
            sbrec_datapath_binding_delete(sb);
            continue;
        }

        if (ovn_datapath_find(dp_map, &key)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl, "deleting Datapath_Binding "UUID_FMT" with "
                         "duplicate external-ids:logical-switch "UUID_FMT,
                         UUID_ARGS(&sb->header_.uuid), UUID_ARGS(&key));
            sbrec_datapath_binding_delete(sb);
            continue;
        }

        struct ovn_datapath *od = ovn_datapath_create(dp_map, &key, NULL, sb);
        list_push_back(sb_only, &od->list);
    }

    const struct nbrec_logical_switch *nb;
    NBREC_LOGICAL_SWITCH_FOR_EACH (nb, ctx->ovnnb_idl) {
        struct ovn_datapath *od = ovn_datapath_find(dp_map, &nb->header_.uuid);
        if (od) {
            od->nb = nb;
            list_remove(&od->list);
            list_push_back(both, &od->list);
        } else {
            od = ovn_datapath_create(dp_map, &nb->header_.uuid, nb, NULL);
            list_push_back(nb_only, &od->list);
        }
    }
}

static uint32_t
ovn_datapath_allocate_key(struct hmap *dp_keys)
{
    static uint32_t prev;
    return allocate_key(dp_keys, "datapath", (1u << 24) - 1, &prev);
}

static void
build_datapaths(struct northd_context *ctx, struct hmap *dp_map)
{
    struct ovs_list sb_dps, nb_dps, both_dps;

    join_datapaths(ctx, dp_map, &sb_dps, &nb_dps, &both_dps);

    if (!list_is_empty(&nb_dps)) {
        /* First index the in-use datapath tunnel keys. */
        struct hmap dp_keys = HMAP_INITIALIZER(&dp_keys);
        struct ovn_datapath *od;
        LIST_FOR_EACH (od, list, &both_dps) {
            add_key(&dp_keys, od->sb->tunnel_key);
        }

        /* Add southbound record for each unmatched northbound record. */
        LIST_FOR_EACH (od, list, &nb_dps) {
            uint16_t tunnel_key = ovn_datapath_allocate_key(&dp_keys);
            if (!tunnel_key) {
                break;
            }

            od->sb = sbrec_datapath_binding_insert(ctx->ovnsb_txn);

            struct smap external_ids = SMAP_INITIALIZER(&external_ids);
            char uuid_s[UUID_LEN + 1];
            sprintf(uuid_s, UUID_FMT, UUID_ARGS(&od->nb->header_.uuid));
            smap_add(&external_ids, "logical-switch", uuid_s);
            sbrec_datapath_binding_set_external_ids(od->sb, &external_ids);
            smap_destroy(&external_ids);

            sbrec_datapath_binding_set_tunnel_key(od->sb, tunnel_key);
        }
    }

    /* Delete southbound records without northbound matches. */
    struct ovn_datapath *od, *next;
    LIST_FOR_EACH_SAFE (od, next, list, &sb_dps) {
        list_remove(&od->list);
        sbrec_datapath_binding_delete(od->sb);
        ovn_datapath_destroy(dp_map, od);
    }
}

struct ovn_port {
    struct hmap_node key_node;  /* Index on 'key'. */
    const char *key;            /* nb->name and sb->logical_port */

    const struct nbrec_logical_port *nb; /* May be NULL. */
    const struct sbrec_port_binding *sb; /* May be NULL. */

    struct ovn_datapath *od;

    struct ovs_list list;       /* In list of similar records. */
};

static struct ovn_port *
ovn_port_create(struct hmap *port_map, const char *key,
                const struct nbrec_logical_port *nb,
                const struct sbrec_port_binding *sb)
{
    struct ovn_port *op = xzalloc(sizeof *op);
    op->key = key;
    op->sb = sb;
    op->nb = nb;
    hmap_insert(port_map, &op->key_node, hash_string(op->key, 0));
    return op;
}

static void
ovn_port_destroy(struct hmap *port_map, struct ovn_port *port)
{
    if (port) {
        /* Don't remove port->list, it's only safe and only used within
         * build_ports(). */
        hmap_remove(port_map, &port->key_node);
        free(port);
    }
}

static struct ovn_port *
ovn_port_find(struct hmap *port_map, const char *name)
{
    struct ovn_port *op;

    HMAP_FOR_EACH_WITH_HASH (op, key_node, hash_string(name, 0), port_map) {
        if (!strcmp(op->key, name)) {
            return op;
        }
    }
    return NULL;
}

static uint32_t
ovn_port_allocate_key(struct ovn_datapath *od)
{
    return allocate_key(&od->port_keys, "port",
                        (1u << 16) - 1, &od->max_port_key);
}

static void
join_logical_ports(struct northd_context *ctx,
                   struct hmap *dp_map, struct hmap *port_map,
                   struct ovs_list *sb_only, struct ovs_list *nb_only,
                   struct ovs_list *both)
{
    hmap_init(port_map);
    list_init(sb_only);
    list_init(nb_only);
    list_init(both);

    const struct sbrec_port_binding *sb;
    SBREC_PORT_BINDING_FOR_EACH (sb, ctx->ovnsb_idl) {
        struct ovn_port *op = ovn_port_create(port_map, sb->logical_port,
                                              NULL, sb);
        list_push_back(sb_only, &op->list);
    }

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, dp_map) {
        for (size_t i = 0; i < od->nb->n_ports; i++) {
            const struct nbrec_logical_port *nb = od->nb->ports[i];
            struct ovn_port *op = ovn_port_find(port_map, nb->name);
            if (op) {
                op->nb = nb;
                list_remove(&op->list);
                list_push_back(both, &op->list);
            } else {
                op = ovn_port_create(port_map, nb->name, nb, NULL);
                list_push_back(nb_only, &op->list);
            }
            op->od = od;
        }
    }
}

static void
ovn_port_update_sbrec(const struct ovn_port *op)
{
    sbrec_port_binding_set_datapath(op->sb, op->od->sb);
    sbrec_port_binding_set_parent_port(op->sb, op->nb->parent_name);
    sbrec_port_binding_set_tag(op->sb, op->nb->tag, op->nb->n_tag);
    sbrec_port_binding_set_mac(op->sb, (const char **) op->nb->macs,
                               op->nb->n_macs);
}

static void
build_ports(struct northd_context *ctx, struct hmap *dp_map,
            struct hmap *port_map)
{
    struct ovs_list sb_ports, nb_ports, both_ports;

    join_logical_ports(ctx, dp_map, port_map,
                       &sb_ports, &nb_ports, &both_ports);

    /* For logical ports that are in both databases, update the southbound
     * record based on northbound data.  Also index the in-use tunnel_keys. */
    struct ovn_port *op, *next;
    LIST_FOR_EACH_SAFE (op, next, list, &both_ports) {
        ovn_port_update_sbrec(op);

        add_key(&op->od->port_keys, op->sb->tunnel_key);
        if (op->sb->tunnel_key > op->od->max_port_key) {
            op->od->max_port_key = op->sb->tunnel_key;
        }
    }

    /* Add southbound record for each unmatched northbound record. */
    LIST_FOR_EACH_SAFE (op, next, list, &nb_ports) {
        uint16_t tunnel_key = ovn_port_allocate_key(op->od);
        if (!tunnel_key) {
            continue;
        }

        op->sb = sbrec_port_binding_insert(ctx->ovnsb_txn);
        ovn_port_update_sbrec(op);

        sbrec_port_binding_set_logical_port(op->sb, op->key);
        sbrec_port_binding_set_tunnel_key(op->sb, tunnel_key);
    }

    /* Delete southbound records without northbound matches. */
    LIST_FOR_EACH_SAFE(op, next, list, &sb_ports) {
        list_remove(&op->list);
        sbrec_port_binding_delete(op->sb);
        ovn_port_destroy(port_map, op);
    }
}

#define OVN_MIN_MULTICAST 32768
#define OVN_MAX_MULTICAST 65535

struct multicast_group {
    const char *name;
    uint16_t key;               /* OVN_MIN_MULTICAST...OVN_MAX_MULTICAST. */
};

#define MC_FLOOD "_MC_flood"
static const struct multicast_group mc_flood = { MC_FLOOD, 65535 };

#define MC_UNKNOWN "_MC_unknown"
static const struct multicast_group mc_unknown = { MC_UNKNOWN, 65534 };

static bool
multicast_group_equal(const struct multicast_group *a,
                      const struct multicast_group *b)
{
    return !strcmp(a->name, b->name) && a->key == b->key;
}

/* Multicast group entry. */
struct ovn_multicast {
    struct hmap_node hmap_node; /* Index on 'datapath', 'key', */
    struct ovn_datapath *datapath;
    const struct multicast_group *group;

    struct ovn_port **ports;
    size_t n_ports, allocated_ports;
};

static uint32_t
ovn_multicast_hash(const struct ovn_datapath *datapath,
                   const struct multicast_group *group)
{
    return hash_pointer(datapath, group->key);
}

static struct ovn_multicast *
ovn_multicast_find(struct hmap *mcgroups, struct ovn_datapath *datapath,
                   const struct multicast_group *group)
{
    struct ovn_multicast *mc;

    HMAP_FOR_EACH_WITH_HASH (mc, hmap_node,
                             ovn_multicast_hash(datapath, group), mcgroups) {
        if (mc->datapath == datapath
            && multicast_group_equal(mc->group, group)) {
            return mc;
        }
    }
    return NULL;
}

static void
ovn_multicast_add(struct hmap *mcgroups, const struct multicast_group *group,
                  struct ovn_port *port)
{
    struct ovn_datapath *od = port->od;
    struct ovn_multicast *mc = ovn_multicast_find(mcgroups, od, group);
    if (!mc) {
        mc = xmalloc(sizeof *mc);
        hmap_insert(mcgroups, &mc->hmap_node, ovn_multicast_hash(od, group));
        mc->datapath = od;
        mc->group = group;
        mc->n_ports = 0;
        mc->allocated_ports = 4;
        mc->ports = xmalloc(mc->allocated_ports * sizeof *mc->ports);
    }
    if (mc->n_ports >= mc->allocated_ports) {
        mc->ports = x2nrealloc(mc->ports, &mc->allocated_ports,
                               sizeof *mc->ports);
    }
    mc->ports[mc->n_ports++] = port;
}

static void
ovn_multicast_destroy(struct hmap *mcgroups, struct ovn_multicast *mc)
{
    if (mc) {
        hmap_remove(mcgroups, &mc->hmap_node);
        free(mc->ports);
        free(mc);
    }
}

static void
ovn_multicast_update_sbrec(const struct ovn_multicast *mc,
                           const struct sbrec_multicast_group *sb)
{
    struct sbrec_port_binding **ports = xmalloc(mc->n_ports * sizeof *ports);
    for (size_t i = 0; i < mc->n_ports; i++) {
        ports[i] = CONST_CAST(struct sbrec_port_binding *, mc->ports[i]->sb);
    }
    sbrec_multicast_group_set_ports(sb, ports, mc->n_ports);
    free(ports);
}

/* Rule generation.
 *
 * This code generates the Rule table in the southbound database, as a function
 * of most of the northbound database.
 */

struct ovn_rule {
    struct hmap_node hmap_node;

    struct ovn_datapath *od;
    enum ovn_pipeline { P_IN, P_OUT } pipeline;
    uint8_t table_id;
    uint16_t priority;
    char *match;
    char *actions;
};

static size_t
ovn_rule_hash(const struct ovn_rule *rule)
{
    size_t hash = uuid_hash(&rule->od->key);
    hash = hash_2words((rule->table_id << 16) | rule->priority, hash);
    hash = hash_string(rule->match, hash);
    return hash_string(rule->actions, hash);
}

static bool
ovn_rule_equal(const struct ovn_rule *a, const struct ovn_rule *b)
{
    return (a->od == b->od
            && a->pipeline == b->pipeline
            && a->table_id == b->table_id
            && a->priority == b->priority
            && !strcmp(a->match, b->match)
            && !strcmp(a->actions, b->actions));
}

static void
ovn_rule_init(struct ovn_rule *rule, struct ovn_datapath *od,
              enum ovn_pipeline pipeline, uint8_t table_id, uint16_t priority,
              char *match, char *actions)
{
    rule->od = od;
    rule->pipeline = pipeline;
    rule->table_id = table_id;
    rule->priority = priority;
    rule->match = match;
    rule->actions = actions;
}

/* Adds a row with the specified contents to the Rule table. */
static void
rule_add(struct hmap *rule_map, struct ovn_datapath *od,
         enum ovn_pipeline pipeline, uint8_t table_id, uint16_t priority,
         const char *match, const char *actions)
{
    struct ovn_rule *rule = xmalloc(sizeof *rule);
    ovn_rule_init(rule, od, pipeline, table_id, priority,
                  xstrdup(match), xstrdup(actions));
    hmap_insert(rule_map, &rule->hmap_node, ovn_rule_hash(rule));
}

static struct ovn_rule *
ovn_rule_find(struct hmap *rules, struct ovn_datapath *od,
              enum ovn_pipeline pipeline, uint8_t table_id, uint16_t priority,
              const char *match, const char *actions)
{
    struct ovn_rule target;
    ovn_rule_init(&target, od, pipeline, table_id, priority,
                  CONST_CAST(char *, match), CONST_CAST(char *, actions));

    struct ovn_rule *rule;
    HMAP_FOR_EACH_WITH_HASH (rule, hmap_node, ovn_rule_hash(&target), rules) {
        if (ovn_rule_equal(rule, &target)) {
            return rule;
        }
    }
    return NULL;
}

static void
ovn_rule_destroy(struct hmap *rules, struct ovn_rule *rule)
{
    if (rule) {
        hmap_remove(rules, &rule->hmap_node);
        free(rule->match);
        free(rule->actions);
        free(rule);
    }
}

/* Appends port security constraints on L2 address field 'eth_addr_field'
 * (e.g. "eth.src" or "eth.dst") to 'match'.  'port_security', with
 * 'n_port_security' elements, is the collection of port_security constraints
 * from an OVN_NB Logical_Port row. */
static void
build_port_security(const char *eth_addr_field,
                    char **port_security, size_t n_port_security,
                    struct ds *match)
{
    size_t base_len = match->length;
    ds_put_format(match, " && %s == {", eth_addr_field);

    size_t n = 0;
    for (size_t i = 0; i < n_port_security; i++) {
        uint8_t ea[ETH_ADDR_LEN];

        if (eth_addr_from_string(port_security[i], ea)) {
            ds_put_format(match, ETH_ADDR_FMT, ETH_ADDR_ARGS(ea));
            ds_put_char(match, ' ');
            n++;
        }
    }
    ds_chomp(match, ' ');
    ds_put_cstr(match, "}");

    if (!n) {
        match->length = base_len;
    }
}

static bool
lport_is_enabled(const struct nbrec_logical_port *lport)
{
    return !lport->enabled || *lport->enabled;
}

/* Updates the Rule and Multicast_Group tables in the OVN_SB database,
 * constructing their contents based on the OVN_NB database. */
static void
build_rule(struct northd_context *ctx, struct hmap *datapaths,
           struct hmap *ports)
{
    struct hmap rules = HMAP_INITIALIZER(&rules);
    struct hmap mcgroups = HMAP_INITIALIZER(&mcgroups);

    /* Ingress table 0: Admission control framework. */
    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, datapaths) {
        /* Logical VLANs not supported. */
        rule_add(&rules, od, P_IN, 0, 100, "vlan.present", "drop;");

        /* Broadcast/multicast source address is invalid. */
        rule_add(&rules, od, P_IN, 0, 100, "eth.src[40]", "drop;");

        /* Port security flows have priority 50 (see below) and will continue
         * to the next table if packet source is acceptable. */

        /* Otherwise drop the packet. */
        rule_add(&rules, od, P_IN, 0, 0, "1", "drop;");
    }

    /* Ingress table 0: Ingress port security. */
    struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, ports) {
        struct ds match = DS_EMPTY_INITIALIZER;
        ds_put_cstr(&match, "inport == ");
        json_string_escape(op->key, &match);
        build_port_security("eth.src",
                            op->nb->port_security, op->nb->n_port_security,
                            &match);
        rule_add(&rules, op->od, P_IN, 0, 50, ds_cstr(&match),
                 lport_is_enabled(op->nb) ? "next;" : "drop;");
        ds_destroy(&match);
    }

    /* Ingress table 1: Destination lookup, broadcast and multicast handling
     * (priority 100). */
    HMAP_FOR_EACH (op, key_node, ports) {
        if (lport_is_enabled(op->nb)) {
            ovn_multicast_add(&mcgroups, &mc_flood, op);
        }
    }
    HMAP_FOR_EACH (od, key_node, datapaths) {
        rule_add(&rules, od, P_IN, 1, 100, "eth.dst[40]",
                 "outport = \""MC_FLOOD"\"; output;");
    }

    /* Ingress table 1: Destination lookup, unicast handling (priority 50), */
    HMAP_FOR_EACH (op, key_node, ports) {
        for (size_t i = 0; i < op->nb->n_macs; i++) {
            uint8_t mac[ETH_ADDR_LEN];

            if (eth_addr_from_string(op->nb->macs[i], mac)) {
                struct ds match, actions;

                ds_init(&match);
                ds_put_format(&match, "eth.dst == %s", op->nb->macs[i]);

                ds_init(&actions);
                ds_put_cstr(&actions, "outport = ");
                json_string_escape(op->nb->name, &actions);
                ds_put_cstr(&actions, "; output;");
                rule_add(&rules, op->od, P_IN, 1, 50,
                         ds_cstr(&match), ds_cstr(&actions));
                ds_destroy(&actions);
                ds_destroy(&match);
            } else if (!strcmp(op->nb->macs[i], "unknown")) {
                ovn_multicast_add(&mcgroups, &mc_unknown, op);
                op->od->has_unknown = true;
            } else {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

                VLOG_INFO_RL(&rl, "%s: invalid syntax '%s' in macs column",
                             op->nb->name, op->nb->macs[i]);
            }
        }
    }

    /* Ingress table 1: Destination lookup for unknown MACs (priority 0). */
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (od->has_unknown) {
            rule_add(&rules, od, P_IN, 1, 0, "1",
                     "outport = \""MC_UNKNOWN"\"; output;");
        }
    }

    /* Egress table 0: ACLs. */
    HMAP_FOR_EACH (od, key_node, datapaths) {
        for (size_t i = 0; i < od->nb->n_acls; i++) {
            const struct nbrec_acl *acl = od->nb->acls[i];
            const char *action;

            action = (!strcmp(acl->action, "allow") ||
                      !strcmp(acl->action, "allow-related"))
                ? "next;" : "drop;";
            rule_add(&rules, od, P_OUT, 0, acl->priority, acl->match, action);
        }
    }
    HMAP_FOR_EACH (od, key_node, datapaths) {
        rule_add(&rules, od, P_OUT, 0, 0, "1", "next;");
    }

    /* Egress table 1: Egress port security. */
    HMAP_FOR_EACH (od, key_node, datapaths) {
        rule_add(&rules, od, P_OUT, 1, 100, "eth.dst[40]", "output;");
    }
    HMAP_FOR_EACH (op, key_node, ports) {
        struct ds match;

        ds_init(&match);
        ds_put_cstr(&match, "outport == ");
        json_string_escape(op->key, &match);
        build_port_security("eth.dst",
                            op->nb->port_security, op->nb->n_port_security,
                            &match);

        rule_add(&rules, op->od, P_OUT, 1, 50, ds_cstr(&match),
                 lport_is_enabled(op->nb) ? "output;" : "drop;");

        ds_destroy(&match);
    }

    /* Push changes to the Rule table to database. */
    const struct sbrec_rule *sbrule, *next_sbrule;
    SBREC_RULE_FOR_EACH_SAFE (sbrule, next_sbrule, ctx->ovnsb_idl) {
        struct ovn_datapath *od
            = ovn_datapath_from_sbrec(datapaths, sbrule->logical_datapath);
        if (!od) {
            sbrec_rule_delete(sbrule);
            continue;
        }

        struct ovn_rule *rule = ovn_rule_find(
            &rules, od, (!strcmp(sbrule->pipeline, "ingress") ? P_IN : P_OUT),
            sbrule->table_id, sbrule->priority,
            sbrule->match, sbrule->actions);
        if (rule) {
            ovn_rule_destroy(&rules, rule);
        } else {
            sbrec_rule_delete(sbrule);
        }
    }
    struct ovn_rule *rule, *next_rule;
    HMAP_FOR_EACH_SAFE (rule, next_rule, hmap_node, &rules) {
        sbrule = sbrec_rule_insert(ctx->ovnsb_txn);
        sbrec_rule_set_logical_datapath(sbrule, rule->od->sb);
        sbrec_rule_set_pipeline(sbrule,
                                rule->pipeline == P_IN ? "ingress" : "egress");
        sbrec_rule_set_table_id(sbrule, rule->table_id);
        sbrec_rule_set_priority(sbrule, rule->priority);
        sbrec_rule_set_match(sbrule, rule->match);
        sbrec_rule_set_actions(sbrule, rule->actions);
        ovn_rule_destroy(&rules, rule);
    }
    hmap_destroy(&rules);

    /* Push changes to the Multicast_Group table to database. */
    const struct sbrec_multicast_group *sbmc, *next_sbmc;
    SBREC_MULTICAST_GROUP_FOR_EACH_SAFE (sbmc, next_sbmc, ctx->ovnsb_idl) {
        struct ovn_datapath *od = ovn_datapath_from_sbrec(datapaths,
                                                          sbmc->datapath);
        if (!od) {
            sbrec_multicast_group_delete(sbmc);
            continue;
        }

        struct multicast_group group = { .name = sbmc->name,
                                         .key = sbmc->tunnel_key };
        struct ovn_multicast *mc = ovn_multicast_find(&mcgroups, od, &group);
        if (mc) {
            ovn_multicast_update_sbrec(mc, sbmc);
            ovn_multicast_destroy(&mcgroups, mc);
        } else {
            sbrec_multicast_group_delete(sbmc);
        }
    }
    struct ovn_multicast *mc, *next_mc;
    HMAP_FOR_EACH_SAFE (mc, next_mc, hmap_node, &mcgroups) {
        sbmc = sbrec_multicast_group_insert(ctx->ovnsb_txn);
        sbrec_multicast_group_set_datapath(sbmc, mc->datapath->sb);
        sbrec_multicast_group_set_name(sbmc, mc->group->name);
        sbrec_multicast_group_set_tunnel_key(sbmc, mc->group->key);
        ovn_multicast_update_sbrec(mc, sbmc);
        ovn_multicast_destroy(&mcgroups, mc);
    }
    hmap_destroy(&mcgroups);
}

static void
ovnnb_db_changed(struct northd_context *ctx)
{
    VLOG_DBG("ovn-nb db contents have changed.");

    struct hmap datapaths, ports;
    build_datapaths(ctx, &datapaths);
    build_ports(ctx, &datapaths, &ports);
    build_rule(ctx, &datapaths, &ports);
}

/*
 * The only change we get notified about is if the 'chassis' column of the
 * 'Port_Binding' table changes.  When this column is not empty, it means we
 * need to set the corresponding logical port as 'up' in the northbound DB.
 */
static void
ovnsb_db_changed(struct northd_context *ctx)
{
    struct hmap lports_hmap;
    const struct sbrec_port_binding *sb;
    const struct nbrec_logical_port *nb;

    struct lport_hash_node {
        struct hmap_node node;
        const struct nbrec_logical_port *nb;
    } *hash_node, *hash_node_next;

    VLOG_DBG("Recalculating port up states for ovn-nb db.");

    hmap_init(&lports_hmap);

    NBREC_LOGICAL_PORT_FOR_EACH(nb, ctx->ovnnb_idl) {
        hash_node = xzalloc(sizeof *hash_node);
        hash_node->nb = nb;
        hmap_insert(&lports_hmap, &hash_node->node, hash_string(nb->name, 0));
    }

    SBREC_PORT_BINDING_FOR_EACH(sb, ctx->ovnsb_idl) {
        nb = NULL;
        HMAP_FOR_EACH_WITH_HASH(hash_node, node,
                                hash_string(sb->logical_port, 0),
                                &lports_hmap) {
            if (!strcmp(sb->logical_port, hash_node->nb->name)) {
                nb = hash_node->nb;
                break;
            }
        }

        if (!nb) {
            /* The logical port doesn't exist for this port binding.  This can
             * happen under normal circumstances when ovn-northd hasn't gotten
             * around to pruning the Port_Binding yet. */
            continue;
        }

        if (sb->chassis && (!nb->up || !*nb->up)) {
            bool up = true;
            nbrec_logical_port_set_up(nb, &up, 1);
        } else if (!sb->chassis && (!nb->up || *nb->up)) {
            bool up = false;
            nbrec_logical_port_set_up(nb, &up, 1);
        }
    }

    HMAP_FOR_EACH_SAFE(hash_node, hash_node_next, node, &lports_hmap) {
        hmap_remove(&lports_hmap, &hash_node->node);
        free(hash_node);
    }
    hmap_destroy(&lports_hmap);
}

static const char *
default_db(void)
{
    static char *def;
    if (!def) {
        def = xasprintf("unix:%s/db.sock", ovs_rundir());
    }
    return def;
}

static void
parse_options(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum {
        DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"ovnsb-db", required_argument, NULL, 'd'},
        {"ovnnb-db", required_argument, NULL, 'D'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        DAEMON_OPTION_HANDLERS;
        VLOG_OPTION_HANDLERS;
        STREAM_SSL_OPTION_HANDLERS;

        case 'd':
            ovnsb_db = optarg;
            break;

        case 'D':
            ovnnb_db = optarg;
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        default:
            break;
        }
    }

    if (!ovnsb_db) {
        ovnsb_db = default_db();
    }

    if (!ovnnb_db) {
        ovnnb_db = default_db();
    }

    free(short_options);
}

static void
add_column_noalert(struct ovsdb_idl *idl,
                   const struct ovsdb_idl_column *column)
{
    ovsdb_idl_add_column(idl, column);
    ovsdb_idl_omit_alert(idl, column);
}

int
main(int argc, char *argv[])
{
    extern struct vlog_module VLM_reconnect;
    struct ovsdb_idl *ovnnb_idl, *ovnsb_idl;
    unsigned int ovnnb_seqno, ovn_seqno;
    int res = EXIT_SUCCESS;
    struct northd_context ctx = {
        .ovnsb_txn = NULL,
    };
    bool ovnnb_changes_pending = false;
    bool ovn_changes_pending = false;
    struct unixctl_server *unixctl;
    int retval;
    bool exiting;

    fatal_ignore_sigpipe();
    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels(&VLM_reconnect, VLF_ANY_DESTINATION, VLL_WARN);
    parse_options(argc, argv);

    daemonize_start();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_northd_exit, &exiting);

    daemonize_complete();

    nbrec_init();
    sbrec_init();

    /* We want to detect all changes to the ovn-nb db. */
    ctx.ovnnb_idl = ovnnb_idl = ovsdb_idl_create(ovnnb_db,
            &nbrec_idl_class, true, true);

    ctx.ovnsb_idl = ovnsb_idl = ovsdb_idl_create(ovnsb_db,
            &sbrec_idl_class, false, true);

    ovsdb_idl_add_table(ovnsb_idl, &sbrec_table_rule);
    add_column_noalert(ovnsb_idl, &sbrec_rule_col_logical_datapath);
    add_column_noalert(ovnsb_idl, &sbrec_rule_col_pipeline);
    add_column_noalert(ovnsb_idl, &sbrec_rule_col_table_id);
    add_column_noalert(ovnsb_idl, &sbrec_rule_col_priority);
    add_column_noalert(ovnsb_idl, &sbrec_rule_col_match);
    add_column_noalert(ovnsb_idl, &sbrec_rule_col_actions);

    ovsdb_idl_add_table(ovnsb_idl, &sbrec_table_multicast_group);
    add_column_noalert(ovnsb_idl, &sbrec_multicast_group_col_datapath);
    add_column_noalert(ovnsb_idl, &sbrec_multicast_group_col_tunnel_key);
    add_column_noalert(ovnsb_idl, &sbrec_multicast_group_col_name);
    add_column_noalert(ovnsb_idl, &sbrec_multicast_group_col_ports);

    ovsdb_idl_add_table(ovnsb_idl, &sbrec_table_datapath_binding);
    add_column_noalert(ovnsb_idl, &sbrec_datapath_binding_col_tunnel_key);
    add_column_noalert(ovnsb_idl, &sbrec_datapath_binding_col_external_ids);

    ovsdb_idl_add_table(ovnsb_idl, &sbrec_table_port_binding);
    add_column_noalert(ovnsb_idl, &sbrec_port_binding_col_datapath);
    add_column_noalert(ovnsb_idl, &sbrec_port_binding_col_logical_port);
    add_column_noalert(ovnsb_idl, &sbrec_port_binding_col_tunnel_key);
    add_column_noalert(ovnsb_idl, &sbrec_port_binding_col_parent_port);
    add_column_noalert(ovnsb_idl, &sbrec_port_binding_col_tag);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_port_binding_col_chassis);
    add_column_noalert(ovnsb_idl, &sbrec_port_binding_col_mac);

    /*
     * The loop here just runs the IDL in a loop waiting for the seqno to
     * change, which indicates that the contents of the db have changed.
     *
     * If the contents of the ovn-nb db change, the mappings to the ovn-sb
     * db must be recalculated.
     *
     * If the contents of the ovn-sb db change, it means the 'up' state of
     * a port may have changed, as that's the only type of change ovn-northd is
     * watching for.
     */

    ovnnb_seqno = ovsdb_idl_get_seqno(ovnnb_idl);
    ovn_seqno = ovsdb_idl_get_seqno(ovnsb_idl);
    exiting = false;
    while (!exiting) {
        ovsdb_idl_run(ovnnb_idl);
        ovsdb_idl_run(ovnsb_idl);
        unixctl_server_run(unixctl);

        if (!ovsdb_idl_is_alive(ovnnb_idl)) {
            int retval = ovsdb_idl_get_last_error(ovnnb_idl);
            VLOG_ERR("%s: database connection failed (%s)",
                    ovnnb_db, ovs_retval_to_string(retval));
            res = EXIT_FAILURE;
            break;
        }

        if (!ovsdb_idl_is_alive(ovnsb_idl)) {
            int retval = ovsdb_idl_get_last_error(ovnsb_idl);
            VLOG_ERR("%s: database connection failed (%s)",
                    ovnsb_db, ovs_retval_to_string(retval));
            res = EXIT_FAILURE;
            break;
        }

        if (ovnnb_seqno != ovsdb_idl_get_seqno(ovnnb_idl)) {
            ovnnb_seqno = ovsdb_idl_get_seqno(ovnnb_idl);
            ovnnb_changes_pending = true;
        }

        if (ovn_seqno != ovsdb_idl_get_seqno(ovnsb_idl)) {
            ovn_seqno = ovsdb_idl_get_seqno(ovnsb_idl);
            ovn_changes_pending = true;
        }

        /*
         * If there are any pending changes, we delay recalculating the
         * necessary updates until after an existing transaction finishes.
         * This avoids the possibility of rapid updates causing ovn-northd to
         * never be able to successfully make the corresponding updates to the
         * other db.  Instead, pending changes are batched up until the next
         * time we get a chance to calculate the new state and apply it.
         */

        if (ovnnb_changes_pending && !ctx.ovnsb_txn) {
            /*
             * The OVN-nb db contents have changed, so create a transaction for
             * updating the OVN-sb DB.
             */
            ctx.ovnsb_txn = ovsdb_idl_txn_create(ctx.ovnsb_idl);
            ovsdb_idl_txn_add_comment(ctx.ovnsb_txn,
                                      "ovn-northd: northbound db changed");
            ovnnb_db_changed(&ctx);
            ovnnb_changes_pending = false;
        }

        if (ovn_changes_pending && !ctx.ovnnb_txn) {
            /*
             * The OVN-sb db contents have changed, so create a transaction for
             * updating the northbound DB.
             */
            ctx.ovnnb_txn = ovsdb_idl_txn_create(ctx.ovnnb_idl);
            ovsdb_idl_txn_add_comment(ctx.ovnnb_txn,
                                      "ovn-northd: southbound db changed");
            ovnsb_db_changed(&ctx);
            ovn_changes_pending = false;
        }

        if (ctx.ovnnb_txn) {
            enum ovsdb_idl_txn_status txn_status;
            txn_status = ovsdb_idl_txn_commit(ctx.ovnnb_txn);
            switch (txn_status) {
            case TXN_UNCOMMITTED:
            case TXN_INCOMPLETE:
                /* Come back around and try to commit this transaction again */
                break;
            case TXN_ABORTED:
            case TXN_TRY_AGAIN:
            case TXN_NOT_LOCKED:
            case TXN_ERROR:
                /* Something went wrong, so try creating a new transaction. */
                ovn_changes_pending = true;
            case TXN_UNCHANGED:
            case TXN_SUCCESS:
                ovsdb_idl_txn_destroy(ctx.ovnnb_txn);
                ctx.ovnnb_txn = NULL;
            }
        }

        if (ctx.ovnsb_txn) {
            enum ovsdb_idl_txn_status txn_status;
            txn_status = ovsdb_idl_txn_commit(ctx.ovnsb_txn);
            switch (txn_status) {
            case TXN_UNCOMMITTED:
            case TXN_INCOMPLETE:
                /* Come back around and try to commit this transaction again */
                break;
            case TXN_ABORTED:
            case TXN_TRY_AGAIN:
            case TXN_NOT_LOCKED:
            case TXN_ERROR:
                /* Something went wrong, so try creating a new transaction. */
                ovnnb_changes_pending = true;
            case TXN_UNCHANGED:
            case TXN_SUCCESS:
                ovsdb_idl_txn_destroy(ctx.ovnsb_txn);
                ctx.ovnsb_txn = NULL;
            }
        }

        if (ovnnb_seqno == ovsdb_idl_get_seqno(ovnnb_idl) &&
                ovn_seqno == ovsdb_idl_get_seqno(ovnsb_idl)) {
            ovsdb_idl_wait(ovnnb_idl);
            ovsdb_idl_wait(ovnsb_idl);
            if (ctx.ovnnb_txn) {
                ovsdb_idl_txn_wait(ctx.ovnnb_txn);
            }
            if (ctx.ovnsb_txn) {
                ovsdb_idl_txn_wait(ctx.ovnsb_txn);
            }
            unixctl_server_wait(unixctl);
            if (exiting) {
                poll_immediate_wake();
            }
            poll_block();
        }
    }

    unixctl_server_destroy(unixctl);
    ovsdb_idl_destroy(ovnsb_idl);
    ovsdb_idl_destroy(ovnnb_idl);

    exit(res);
}

static void
ovn_northd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}
