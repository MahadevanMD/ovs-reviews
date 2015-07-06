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

static struct ovn_datapath *find_datapath_by_uuid(struct hmap *datapaths,
                                                  const struct uuid *);

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

static int
compare_strings(const void *a_, const void *b_)
{
    char *const *a = a_;
    char *const *b = b_;
    return strcmp(*a, *b);
}

/*
 * Determine whether 2 arrays of MAC addresses are the same.  It's possible that
 * the lists could be *very* long and this check is being done a lot (every
 * time the OVN_Northbound database changes).
 */
static bool
macs_equal(char **binding_macs_, size_t b_n_macs,
           char **lport_macs_, size_t l_n_macs)
{
    char **binding_macs, **lport_macs;
    size_t bytes, i;

    if (b_n_macs != l_n_macs) {
        return false;
    }

    bytes = b_n_macs * sizeof binding_macs_[0];
    binding_macs = xmalloc(bytes);
    lport_macs = xmalloc(bytes);

    memcpy(binding_macs, binding_macs_, bytes);
    memcpy(lport_macs, lport_macs_, bytes);

    qsort(binding_macs, b_n_macs, sizeof binding_macs[0], compare_strings);
    qsort(lport_macs, l_n_macs, sizeof lport_macs[0], compare_strings);

    for (i = 0; i < b_n_macs; i++) {
        if (strcmp(binding_macs[i], lport_macs[i])) {
            break;
        }
    }

    free(binding_macs);
    free(lport_macs);

    return (i == b_n_macs) ? true : false;
}

struct key_node {
    struct hmap_node hmap_node;
    uint32_t key;
};

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
find_datapath_by_uuid(struct hmap *uuid_map, const struct uuid *uuid)
{
    struct ovn_datapath *od;

    HMAP_FOR_EACH_WITH_HASH (od, key_node, uuid_hash(uuid), uuid_map) {
        if (uuid_equals(uuid, &od->key)) {
            return od;
        }
    }
    return NULL;
}

static void
join_datapaths(struct northd_context *ctx, struct hmap *uuid_map,
               struct ovs_list *sb_only, struct ovs_list *nb_only,
               struct ovs_list *both)
{
    hmap_init(uuid_map);
    list_init(sb_only);
    list_init(nb_only);
    list_init(both);

    const struct sbrec_datapath_binding *sb, *sb_next;
    SBREC_DATAPATH_BINDING_FOR_EACH_SAFE (sb, sb_next, ctx->ovnsb_idl) {
        struct uuid key;
        if (!smap_get_uuid(&sb->external_ids, "logical-switch", &key)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl, "deleting Datapath_Binding missing "
                         "external-ids:logical-switch");
            sbrec_datapath_binding_delete(sb);
            continue;
        }

        struct ovn_datapath *od = xzalloc(sizeof *od);
        od->key = key;
        od->sb = sb;
        od->nb = NULL;
        hmap_init(&od->port_keys);
        od->max_port_key = 0;
        hmap_insert(uuid_map, &od->key_node, uuid_hash(&od->key));
        list_push_back(sb_only, &od->list);
    }

    const struct nbrec_logical_switch *nb;
    NBREC_LOGICAL_SWITCH_FOR_EACH (nb, ctx->ovnnb_idl) {
        struct ovn_datapath *od = find_datapath_by_uuid(uuid_map,
                                                        &nb->header_.uuid);
        if (od) {
            od->nb = nb;
            list_remove(&od->list);
            list_push_back(both, &od->list);
        } else {
            od = xzalloc(sizeof *od);
            od->key = nb->header_.uuid;
            od->sb = NULL;
            od->nb = nb;
            hmap_init(&od->port_keys);
            od->max_port_key = 0;
            hmap_insert(uuid_map, &od->key_node, uuid_hash(&od->key));
            list_push_back(nb_only, &od->list);
        }
    }
}

static uint32_t
allocate_datapath_key(struct hmap *dp_keys)
{
    static uint32_t prev;
    return allocate_key(dp_keys, "datapath", (1u << 24) - 1, &prev);
}

static uint32_t
allocate_port_key(struct ovn_datapath *dj)
{
    return allocate_key(&dj->port_keys, "port",
                        (1u << 16) - 1, &dj->max_port_key);
}

/*
 * When a change has occurred in the OVN_Northbound database, we go through and
 * make sure that the contents of the Port_Binding table in the OVN_Southbound
 * database are up to date with the logical ports defined in the
 * OVN_Northbound database.
 */
static void
build_bindings(struct northd_context *ctx, struct hmap *dp_map,
               struct hmap *port_map)
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
            uint16_t tunnel_key = allocate_datapath_key(&dp_keys);
            if (!tunnel_key) {
                break;
            }

            od->sb = sbrec_datapath_binding_insert(ctx->ovnsb_txn);
            sbrec_datapath_binding_set_logical_datapath(
                od->sb, od->nb->header_.uuid);
            sbrec_datapath_binding_set_tunnel_key(od->sb, tunnel_key);
        }
    }

    /* Delete southbound records without northbound matches. */
    struct ovn_datapath *od;
    LIST_FOR_EACH (od, list, &sb_dps) {
        sbrec_datapath_binding_delete(od->sb);
    }

    struct ovs_list sb_ports, nb_ports, both_ports;

    join_logical_ports(ctx, port_map, &sb_ports, &nb_ports, &both_ports);

    /* For logical ports that are in both databases, update the southbound
     * record based on northbound data.  Also index the in-use tunnel_keys. */
    struct ovn_port *op;
    LIST_FOR_EACH (op, list, &both_ports) {
        if (!macs_equal(op->sb->mac, op->sb->n_mac,
                        op->nb->macs, op->nb->n_macs)) {
            sbrec_port_binding_set_mac(op->sb, (const char **) op->nb->macs,
                                       op->nb->n_macs);
        }
        if (!parents_equal(op->sb, op->nb)) {
            sbrec_port_binding_set_parent_port(op->sb, op->nb->parent_name);
        }
        if (!tags_equal(op->sb, op->nb)) {
            sbrec_port_binding_set_tag(op->sb, op->nb->tag, op->nb->n_tag);
        }

        od = find_datapath_by_uuid(dp_map, &op->nb->header_.uuid);
        if (!od || !od->sb) {
            /* XXX delete southbound port */
        } else {
            if (op->sb->logical_datapath != od->sb) {
                sbrec_port_binding_set_logical_datapath(op->sb, od->sb);
            }
            add_key(&od->port_keys, op->sb->tunnel_key);
            if (op->sb->tunnel_key > od->max_port_key) {
                od->max_port_key = op->sb->tunnel_key;
            }
        }
    }

    /* Add southbound record for each unmatched northbound record. */
    LIST_FOR_EACH (op, list, &nb_ports) {
        od = find_datapath_by_uuid(dp_map, &op->nb->header_.uuid);
        if (!od || !od->sb) {
            continue;
        }

        uint16_t tunnel_key = allocate_port_key(od);
        if (!tunnel_key) {
            continue;
        }

        op->sb = sbrec_port_binding_insert(ctx->ovnsb_txn);
        sbrec_port_binding_set_logical_port(op->sb, op->nb->name);
        sbrec_port_binding_set_mac(op->sb, (const char **) op->nb->macs,
                                   op->nb->n_macs);
        if (op->nb->parent_name && op->nb->n_tag > 0) {
            sbrec_port_binding_set_parent_port(op->sb, op->nb->parent_name);
            sbrec_port_binding_set_tag(op->sb, op->nb->tag, op->nb->n_tag);
        }

        sbrec_port_binding_set_tunnel_key(op->sb, tunnel_key);
        sbrec_port_binding_set_logical_datapath(op->sb, od->sb);
    }

    /* Delete southbound records without northbound matches. */
    LIST_FOR_EACH (op, list, &sb_ports) {
        sbrec_port_binding_delete(op->sb);
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
find_port_by_name(struct hmap *name_map, const char *name)
{
    struct ovn_port *op;

    HMAP_FOR_EACH_WITH_HASH (op, key_node, hash_string(name, 0), name_map) {
        if (!strcmp(op->key, name)) {
            return op;
        }
    }
    return NULL;
}

/* Pipeline generation.
 *
 * This code generates the Pipeline table in the southbound database, as a
 * function of most of the northbound database.
 */

/* Enough context to add a Pipeline row, using pipeline_add(). */
struct pipeline_ctx {
    /* From northd_context. */
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl_txn *ovnsb_txn;

    /* Contains "struct pipeline_hash_node"s.  Used to figure out what existing
     * Pipeline rows should be deleted: we index all of the Pipeline rows into
     * this data structure, then as existing rows are generated we remove them.
     * After generating all the rows, any remaining in 'pipeline_hmap' must be
     * deleted from the database. */
    struct hmap pipeline_hmap;

    /* Contains ovn_datapaths. */
    struct hmap *datapaths;
};

struct ovn_pipeline {
    struct hmap_node hmap_node;

    struct ovn_datapath *od;
    uint8_t table_id;
    uint16_t priority;
    const char *match;
    const char *actions;
};

static size_t
pipeline_hash(const struct ovn_pipeline *pipeline)
{
    size_t hash = uuid_hash(&pipeline->od->key);
    hash = hash_2words((pipeline->table_id << 16) | pipeline->priority, hash);
    hash = hash_string(pipeline->match, hash);
    return hash_string(pipeline->actions, hash);
}

/* Adds a row with the specified contents to the Pipeline table. */
static void
pipeline_add(struct pipeline_ctx *ctx, struct ovn_datapath *od,
             uint8_t table_id, uint16_t priority,
             const char *match, const char *actions)
{
    struct ovn_pipeline *pipeline = xmalloc(sizeof *pipeline);
    pipeline->od = od;
    pipeline->table_id = table_id;
    pipeline->priority = priority;
    pipeline->match = xstrdup(match);
    pipeline->actions = xstrdup(actions);
    hmap_insert(&ctx->pipeline_hmap, &pipeline->hmap_node,
                pipeline_hash(pipeline));
}

static void
multicast_add(struct pipeline_ctx *ctx, const char *multicast_group,
              const struct ovn_datapath *od, const struct ovn_port *op);

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

static bool
parents_equal(const struct sbrec_port_binding *binding,
              const struct nbrec_logical_port *lport)
{
    if (!!binding->parent_port != !!lport->parent_name) {
        /* One is set and the other is not. */
        return false;
    }

    if (binding->parent_port) {
        /* Both are set. */
        return strcmp(binding->parent_port, lport->parent_name) ? false : true;
    }

    /* Both are NULL. */
    return true;
}

static bool
tags_equal(const struct sbrec_port_binding *binding,
           const struct nbrec_logical_port *lport)
{
    if (binding->n_tag != lport->n_tag) {
        return false;
    }

    return binding->n_tag ? (binding->tag[0] == lport->tag[0]) : true;
}

static struct ovn_port *
ovn_port_create(struct hmap *name_map, const struct nbrec_logical_port *nb,
                const struct sbrec_port_binding *sb)
{
    struct ovn_port *op = xzalloc(sizeof *op);
    op->key = nb ? nb->name : sb->logical_port;
    op->sb = sb;
    op->nb = nb;
    hmap_insert(name_map, &op->key_node, hash_string(op->key, 0));
    return op;
}

static void
join_logical_ports(struct northd_context *ctx, struct hmap *name_map,
                   struct ovs_list *sb_only, struct ovs_list *nb_only,
                   struct ovs_list *both)
{
    hmap_init(name_map);
    list_init(sb_only);
    list_init(nb_only);
    list_init(both);

    const struct sbrec_port_binding *sb;
    SBREC_PORT_BINDING_FOR_EACH (sb, ctx->ovnsb_idl) {
        struct ovn_port *op = ovn_port_create(name_map, NULL, sb);
        list_push_back(sb_only, &op->list);
    }

    const struct nbrec_logical_port *nb;
    NBREC_LOGICAL_PORT_FOR_EACH (nb, ctx->ovnnb_idl) {
        struct ovn_port *op = find_port_by_name(name_map, nb->name);
        if (op) {
            op->nb = nb;
            list_remove(&op->list);
            list_push_back(both, &op->list);
        } else {
            op = ovn_port_create(name_map, nb, NULL);
            list_push_back(nb_only, &op->list);
        }
    }
}

static void
ovnnb_db_changed(struct northd_context *ctx)
{
    VLOG_DBG("ovn-nb db contents have changed.");

    struct hmap datapaths, ports;
    build_bindings(ctx, &datapaths, &ports);
    build_pipeline(ctx, &datapaths, &ports);
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
    const struct sbrec_port_binding *binding;
    const struct nbrec_logical_port *lport;

    struct lport_hash_node {
        struct hmap_node node;
        const struct nbrec_logical_port *lport;
    } *hash_node, *hash_node_next;

    VLOG_DBG("Recalculating port up states for ovn-nb db.");

    hmap_init(&lports_hmap);

    NBREC_LOGICAL_PORT_FOR_EACH(lport, ctx->ovnnb_idl) {
        hash_node = xzalloc(sizeof *hash_node);
        hash_node->lport = lport;
        hmap_insert(&lports_hmap, &hash_node->node,
                hash_string(lport->name, 0));
    }

    SBREC_PORT_BINDING_FOR_EACH(binding, ctx->ovnsb_idl) {
        lport = NULL;
        HMAP_FOR_EACH_WITH_HASH(hash_node, node,
                hash_string(binding->logical_port, 0), &lports_hmap) {
            if (!strcmp(binding->logical_port, hash_node->lport->name)) {
                lport = hash_node->lport;
                break;
            }
        }

        if (!lport) {
            /* The logical port doesn't exist for this port binding.  This can
             * happen under normal circumstances when ovn-northd hasn't gotten
             * around to pruning the Port_Binding yet. */
            continue;
        }

        if (binding->chassis && (!lport->up || !*lport->up)) {
            bool up = true;
            nbrec_logical_port_set_up(lport, &up, 1);
        } else if (!binding->chassis && (!lport->up || *lport->up)) {
            bool up = false;
            nbrec_logical_port_set_up(lport, &up, 1);
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

    /* There is only a small subset of changes to the ovn-sb db that ovn-northd
     * has to care about, so we'll enable monitoring those directly. */
    ctx.ovnsb_idl = ovnsb_idl = ovsdb_idl_create(ovnsb_db,
            &sbrec_idl_class, false, true);
    ovsdb_idl_add_table(ovnsb_idl, &sbrec_table_port_binding);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_port_binding_col_logical_port);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_port_binding_col_chassis);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_port_binding_col_mac);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_port_binding_col_tag);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_port_binding_col_parent_port);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_port_binding_col_logical_datapath);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_port_binding_col_tunnel_key);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_pipeline_col_logical_datapath);
    ovsdb_idl_omit_alert(ovnsb_idl, &sbrec_pipeline_col_logical_datapath);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_pipeline_col_table_id);
    ovsdb_idl_omit_alert(ovnsb_idl, &sbrec_pipeline_col_table_id);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_pipeline_col_priority);
    ovsdb_idl_omit_alert(ovnsb_idl, &sbrec_pipeline_col_priority);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_pipeline_col_match);
    ovsdb_idl_omit_alert(ovnsb_idl, &sbrec_pipeline_col_match);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_pipeline_col_actions);
    ovsdb_idl_omit_alert(ovnsb_idl, &sbrec_pipeline_col_actions);

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
