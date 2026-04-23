/*
 * corsaro_subnetasn.c
 *
 * (C) 2026 Georgia Tech Research Corporation.
 * All Rights Reserved.
 *
 * This file is part of corsaro.
 */

#include "corsaro_subnetasn.h"
#include "config.h"
#include "khash.h"
#include "libcorsaro.h"
#include "libcorsaro_common.h"
#include "libcorsaro_plugin.h"
#include <arpa/inet.h>
#include <libipmeta.h>
#include <limits.h>
#include <zlib.h>
#include "libcorsaro_libtimeseries.h"
#define CORSARO_SUBNETASN_DEFAULT_PROVIDER "pfx2as"

typedef struct subnet_asn_entry {
  uint32_t *asns;
  int asn_cnt;
} subnet_asn_entry_t;

KHASH_MAP_INIT_INT(subnet, subnet_asn_entry_t *)
KHASH_MAP_INIT_INT(asn_count, uint64_t)

typedef struct corsaro_subnetasn_config {
  corsaro_plugin_proc_options_t basic;
  char *asn_provider;
  char *asn_provider_args;
  char *output_dir;
  corsaro_output_format_t outformat;
  char *outlabel;
} corsaro_subnetasn_config_t;

typedef struct corsaro_subnetasn_state {
  khash_t(subnet) * subnet_hash;
  ipmeta_t *ipmeta;
  ipmeta_provider_t *prov;
  uint32_t last_rotation;
} corsaro_subnetasn_state_t;

typedef struct corsaro_subnetasn_merge_state {
  khash_t(subnet) * subnet_hash;
  uint32_t timestamp;
  timeseries_t *timeseries;
  timeseries_kp_t *kp;
  Pvoid_t metrickp_keys;
} corsaro_subnetasn_merge_state_t;

static corsaro_plugin_t corsaro_subnetasn_plugin = {
  "subnetasn",
  CORSARO_PLUGIN_ID_SUBNETASN,
  0x010203,
  CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_subnetasn),
  CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_subnetasn),
  CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_subnetasn),
  CORSARO_PLUGIN_GENERATE_TAIL};

corsaro_plugin_t *corsaro_subnetasn_alloc(void)
{
  return &corsaro_subnetasn_plugin;
}

static void subnet_asn_entry_free(subnet_asn_entry_t *entry)
{
  if (entry) {
    if (entry->asns) {
      free(entry->asns);
    }
    free(entry);
  }
}

static void destroy_subnet_hash(khash_t(subnet) * h)
{
  if (h) {
    subnet_asn_entry_t *val;
    kh_foreach_value(h, val, subnet_asn_entry_free(val));
    kh_destroy(subnet, h);
  }
}

/* --- Configuration --- */

int corsaro_subnetasn_parse_config(corsaro_plugin_t *p, yaml_document_t *doc,
                                   yaml_node_t *options)
{
  corsaro_subnetasn_config_t *conf;
  yaml_node_pair_t *pair;

  conf = calloc(1, sizeof(corsaro_subnetasn_config_t));
  if (!conf) {
    return -1;
  }

  CORSARO_INIT_PLUGIN_PROC_OPTS(conf->basic);
  conf->asn_provider = strdup(CORSARO_SUBNETASN_DEFAULT_PROVIDER);
  conf->outformat = CORSARO_OUTPUT_CSV;
  conf->outlabel = NULL;

  if (options->type != YAML_MAPPING_NODE) {
    corsaro_log(p->logger, "subnetasn plugin config must be a map.");
    free(conf);
    return -1;
  }

  for (pair = options->data.mapping.pairs.start;
       pair < options->data.mapping.pairs.top; pair++) {
    yaml_node_t *key = yaml_document_get_node(doc, pair->key);
    yaml_node_t *value = yaml_document_get_node(doc, pair->value);
    char *key_str = (char *)key->data.scalar.value;
    char *val_str = (char *)value->data.scalar.value;

    if (!strcmp(key_str, "asn_provider")) {
      free(conf->asn_provider);
      conf->asn_provider = strdup(val_str);
    } else if (!strcmp(key_str, "asn_provider_args")) {
      if (conf->asn_provider_args) {
        free(conf->asn_provider_args);
      }
      conf->asn_provider_args = strdup(val_str);
    } else if (!strcmp(key_str, "output_dir")) {
      if (conf->output_dir) {
        free(conf->output_dir);
      }
      conf->output_dir = strdup(val_str);
    } else if (!strcmp(key_str, "output_format")) {
      if (!strcmp(val_str, "csv")) {
        conf->outformat = CORSARO_OUTPUT_CSV;
      } else if (!strcmp(val_str, "libtimeseries")) {
        conf->outformat = CORSARO_OUTPUT_LIBTIMESERIES;
      } else {
        corsaro_log(p->logger, "subnetasn: unknown output format '%s', using csv", val_str);
        conf->outformat = CORSARO_OUTPUT_CSV;
      }
    } else if (!strcmp(key_str, "output_row_label")) {
      if (conf->outlabel) free(conf->outlabel);
      conf->outlabel = strdup(val_str);
    }
  }

  p->config = conf;
  return 0;
}

int corsaro_subnetasn_finalise_config(corsaro_plugin_t *p,
                                      corsaro_plugin_proc_options_t *stdopts,
                                      void *zmq_ctxt)
{
  corsaro_subnetasn_config_t *conf = (corsaro_subnetasn_config_t *)p->config;
  conf->basic.template = stdopts->template;
  conf->basic.monitorid = stdopts->monitorid;
  conf->basic.libtskafka = stdopts->libtskafka;

  if (conf->outlabel == NULL && conf->basic.monitorid != NULL) {
    conf->outlabel = strdup(conf->basic.monitorid);
  }

  return 0;
}

void corsaro_subnetasn_destroy_self(corsaro_plugin_t *p)
{
  corsaro_subnetasn_config_t *conf = (corsaro_subnetasn_config_t *)p->config;
  if (conf) {
    if (conf->asn_provider) {
      free(conf->asn_provider);
    }
    if (conf->asn_provider_args) {
      free(conf->asn_provider_args);
    }
    if (conf->output_dir) {
      free(conf->output_dir);
    }
    if (conf->outlabel) {
      free(conf->outlabel);
    }
    free(conf);
    p->config = NULL;
  }
}

/* --- Processing --- */

void *corsaro_subnetasn_init_processing(corsaro_plugin_t *p, int threadid)
{
  corsaro_subnetasn_config_t *conf = (corsaro_subnetasn_config_t *)p->config;
  corsaro_subnetasn_state_t *state =
    calloc(1, sizeof(corsaro_subnetasn_state_t));
  if (!state) {
    return NULL;
  }

  state->subnet_hash = kh_init(subnet);

  state->ipmeta = ipmeta_init(IPMETA_DS_DEFAULT);
  if (!state->ipmeta) {
    corsaro_log(p->logger, "Failed to initialize ipmeta");
    kh_destroy(subnet, state->subnet_hash);
    free(state);
    return NULL;
  }

  state->prov = ipmeta_get_provider_by_name(state->ipmeta, conf->asn_provider);
  if (!state->prov) {
    corsaro_log(p->logger, "Failed to find provider '%s'", conf->asn_provider);
    ipmeta_free(state->ipmeta);
    kh_destroy(subnet, state->subnet_hash);
    free(state);
    return NULL;
  }

  if (ipmeta_enable_provider(state->ipmeta, state->prov,
                             conf->asn_provider_args) != 0) {
    corsaro_log(p->logger, "Failed to enable provider '%s'",
                conf->asn_provider);
    ipmeta_free(state->ipmeta);
    kh_destroy(subnet, state->subnet_hash);
    free(state);
    return NULL;
  }

  return state;
}

int corsaro_subnetasn_halt_processing(corsaro_plugin_t *p, void *local)
{
  corsaro_subnetasn_state_t *state = (corsaro_subnetasn_state_t *)local;
  if (state) {
    destroy_subnet_hash(state->subnet_hash);
    if (state->ipmeta) {
      ipmeta_free(state->ipmeta);
    }
    free(state);
  }
  return 0;
}

int corsaro_subnetasn_start_interval(corsaro_plugin_t *p, void *local,
                                     corsaro_interval_t *int_start)
{
  corsaro_subnetasn_state_t *state = (corsaro_subnetasn_state_t *)local;
  if (state) {
    state->last_rotation = int_start->time;
  }
  return 0;
}

void *corsaro_subnetasn_end_interval(corsaro_plugin_t *p, void *local,
                                     corsaro_interval_t *int_end,
                                     uint8_t complete)
{
  corsaro_subnetasn_state_t *state = (corsaro_subnetasn_state_t *)local;
  if (!state) {
    return NULL;
  }

  khash_t(subnet) *snapshot = state->subnet_hash;
  state->subnet_hash = kh_init(subnet);

  return (void *)snapshot;
}

int corsaro_subnetasn_process_packet(corsaro_plugin_t *p, void *local,
                                     libtrace_packet_t *packet,
                                     corsaro_packet_tags_t *tags)
{
  corsaro_subnetasn_state_t *state = (corsaro_subnetasn_state_t *)local;
  struct sockaddr_storage addr;
  struct sockaddr_in *v4;
  uint32_t src_ip, subnet_ip;
  int ret;
  khiter_t k;

  if (trace_get_source_address(packet, (struct sockaddr *)&addr) == NULL) {
    return 0;
  }

  if (addr.ss_family != AF_INET) {
    return 0;
  }

  v4 = (struct sockaddr_in *)&addr;
  src_ip = ntohl(v4->sin_addr.s_addr);
  subnet_ip = src_ip & 0xFFFFFF00;

  k = kh_get(subnet, state->subnet_hash, subnet_ip);
  if (k == kh_end(state->subnet_hash)) {
    ipmeta_record_set_t *records = ipmeta_record_set_init();
    struct in_addr lookup_addr;
    lookup_addr.s_addr = htonl(src_ip);

    int prov_mask = IPMETA_PROV_TO_MASK(ipmeta_get_provider_id(state->prov));
    ipmeta_lookup_addr(state->ipmeta, AF_INET, &lookup_addr, prov_mask,
                       records);

    subnet_asn_entry_t *entry = calloc(1, sizeof(subnet_asn_entry_t));
    if (!entry) {
      ipmeta_record_set_free(&records);
      return -1;
    }

    ipmeta_record_t *rec;
    uint64_t num_ips;
    ipmeta_record_set_rewind(records);
    while ((rec = ipmeta_record_set_next(records, &num_ips))) {
      if (rec->asn_cnt > 0) {
        uint32_t *new_asns = realloc(
          entry->asns, (entry->asn_cnt + rec->asn_cnt) * sizeof(uint32_t));
        if (!new_asns) {
          continue;
        }
        entry->asns = new_asns;
        memcpy(entry->asns + entry->asn_cnt, rec->asn,
               rec->asn_cnt * sizeof(uint32_t));
        entry->asn_cnt += rec->asn_cnt;
      }
    }
    ipmeta_record_set_free(&records);

    k = kh_put(subnet, state->subnet_hash, subnet_ip, &ret);
    if (ret < 0) {
      subnet_asn_entry_free(entry);
      return -1;
    }
    kh_value(state->subnet_hash, k) = entry;
  }

  return 0;
}

char *corsaro_subnetasn_derive_output_name(corsaro_plugin_t *p, void *local,
                                           uint32_t timestamp, int threadid)
{
  return NULL;
}

/* --- Merging --- */

void *corsaro_subnetasn_init_merging(corsaro_plugin_t *p, int sources)
{
  corsaro_subnetasn_config_t *conf = (corsaro_subnetasn_config_t *)p->config;
  corsaro_subnetasn_merge_state_t *state =
    calloc(1, sizeof(corsaro_subnetasn_merge_state_t));
  if (!state) {
    return NULL;
  }
  state->subnet_hash = kh_init(subnet);

  if (conf->outformat == CORSARO_OUTPUT_LIBTIMESERIES) {
    state->timeseries = timeseries_init();
    if (state->timeseries == NULL) {
      corsaro_log(p->logger, "subnetasn: unable to initialize libtimeseries");
      kh_destroy(subnet, state->subnet_hash);
      free(state);
      return NULL;
    }
    if (enable_libts_kafka_backend(p->logger, state->timeseries, conf->basic.libtskafka) != 0) {
      corsaro_log(p->logger, "subnetasn: unable to enable kafka backend");
    }
    state->kp = timeseries_kp_init(state->timeseries, TIMESERIES_KP_RESET);
    if (state->kp == NULL) {
      corsaro_log(p->logger, "subnetasn: unable to initialize libtimeseries key package");
      timeseries_free(&(state->timeseries));
      kh_destroy(subnet, state->subnet_hash);
      free(state);
      return NULL;
    }
    state->metrickp_keys = (Pvoid_t)NULL;
  }

  return state;
}

int corsaro_subnetasn_halt_merging(corsaro_plugin_t *p, void *local)
{
  corsaro_subnetasn_merge_state_t *state =
    (corsaro_subnetasn_merge_state_t *)local;
  if (state) {
    destroy_subnet_hash(state->subnet_hash);
    if (state->timeseries) {
      timeseries_kp_free(&(state->kp));
      timeseries_free(&(state->timeseries));
    }
    if (state->metrickp_keys) {
      Word_t freed;
      JLFA(freed, state->metrickp_keys);
    }
    free(state);
  }
  return 0;
}

int compare_uint32(const void *a, const void *b)
{
  return (*(uint32_t *)a - *(uint32_t *)b);
}

static void merge_asns(subnet_asn_entry_t *dst, subnet_asn_entry_t *src)
{
  if (!src || src->asn_cnt == 0) {
    return;
  }

  int old_cnt = dst->asn_cnt;
  uint32_t *new_asns =
    realloc(dst->asns, (dst->asn_cnt + src->asn_cnt) * sizeof(uint32_t));
  if (!new_asns) {
    return;
  }
  dst->asns = new_asns;
  memcpy(dst->asns + old_cnt, src->asns, src->asn_cnt * sizeof(uint32_t));
  dst->asn_cnt += src->asn_cnt;

  qsort(dst->asns, dst->asn_cnt, sizeof(uint32_t), compare_uint32);

  int j = 0;
  for (int i = 0; i < dst->asn_cnt; i++) {
    if (i == 0 || dst->asns[i] != dst->asns[i - 1]) {
      dst->asns[j++] = dst->asns[i];
    }
  }
  dst->asn_cnt = j;
}

int corsaro_subnetasn_merge_interval_results(corsaro_plugin_t *p, void *local,
                                             void **tomerge,
                                             corsaro_fin_interval_t *fin,
                                             void *tagsock)
{
  corsaro_subnetasn_merge_state_t *mstate =
    (corsaro_subnetasn_merge_state_t *)local;
  int i;

  if (!mstate) {
    return -1;
  }

  mstate->timestamp = fin->timestamp;

  for (i = 0; i < fin->threads_ended; i++) {
    khash_t(subnet) *thash = (khash_t(subnet) *)tomerge[i];
    if (!thash) {
      continue;
    }

    subnet_asn_entry_t *src_val;
    uint32_t subnet_key;

    kh_foreach(thash, subnet_key, src_val, {
      int ret;
      khiter_t k = kh_put(subnet, mstate->subnet_hash, subnet_key, &ret);
      if (ret < 0) {
        continue;
      }
      if (ret != 0) {
        subnet_asn_entry_t *new_entry = calloc(1, sizeof(subnet_asn_entry_t));
        if (new_entry) {
          kh_value(mstate->subnet_hash, k) = new_entry;
          merge_asns(new_entry, src_val);
        } else {
          kh_del(subnet, mstate->subnet_hash, k);
        }
      } else {
        merge_asns(kh_value(mstate->subnet_hash, k), src_val);
      }
    });

    destroy_subnet_hash(thash);
  }

  return CORSARO_MERGE_SUCCESS;
}

int corsaro_subnetasn_rotate_output(corsaro_plugin_t *p, void *local)
{
  corsaro_subnetasn_merge_state_t *mstate =
    (corsaro_subnetasn_merge_state_t *)local;
  corsaro_subnetasn_config_t *conf = (corsaro_subnetasn_config_t *)p->config;
  uint32_t subnet_key;
  subnet_asn_entry_t *entry;

  if (!mstate || kh_size(mstate->subnet_hash) == 0) {
    return 0;
  }

  /* Aggregate asn -> unique subnet count */
  khash_t(asn_count) *ac = kh_init(asn_count);
  khiter_t k_ac;
  int ret;

  kh_foreach(mstate->subnet_hash, subnet_key, entry, {
    for (int i = 0; i < entry->asn_cnt; i++) {
      uint32_t asn = entry->asns[i];
      k_ac = kh_put(asn_count, ac, asn, &ret);
      if (ret == 0) {
        kh_value(ac, k_ac)++;
      } else {
        kh_value(ac, k_ac) = 1;
      }
    }
  });

  if (conf->outformat == CORSARO_OUTPUT_CSV) {
    gzFile f;
    char filename[PATH_MAX];
    struct in_addr addr;

    if (conf->output_dir) {
      snprintf(filename, sizeof(filename), "%s/%s_%u_subnetasn.csv.gz",
               conf->output_dir,
               conf->basic.monitorid ? conf->basic.monitorid : "unknown",
               mstate->timestamp);
    } else {
      snprintf(filename, sizeof(filename), "%s_%u_subnetasn.csv.gz",
               conf->basic.monitorid ? conf->basic.monitorid : "unknown",
               mstate->timestamp);
    }

    f = gzopen(filename, "wb");
    if (!f) {
      corsaro_log(p->logger, "Failed to open output file %s", filename);
      kh_destroy(asn_count, ac);
      return -1;
    }

    kh_foreach(mstate->subnet_hash, subnet_key, entry, {
      addr.s_addr = htonl(subnet_key);
      char *ip_str = inet_ntoa(addr);
      for (int i = 0; i < entry->asn_cnt; i++) {
        gzprintf(f, "%u,%s\n", entry->asns[i], ip_str);
      }
    });

    gzclose(f);
  }

  if (conf->outformat == CORSARO_OUTPUT_LIBTIMESERIES && mstate->kp) {
    uint32_t asn;
    uint64_t count;
    char keyname[512];
    PWord_t pval;

    kh_foreach(ac, asn, count, {
      snprintf(keyname, 512, "subnetasn.%s.%u", conf->outlabel, asn);

      JLG(pval, mstate->metrickp_keys, (Word_t)asn);
      int keyid = -1;
      if (pval == NULL) {
        keyid = timeseries_kp_add_key(mstate->kp, keyname);
        if (keyid != -1) {
          JLI(pval, mstate->metrickp_keys, (Word_t)asn);
          *pval = (Word_t)keyid;
        }
      } else {
        keyid = (int)*pval;
      }

      if (keyid != -1) {
        timeseries_kp_set(mstate->kp, keyid, count);
      }
    });

    timeseries_kp_flush(mstate->kp, mstate->timestamp);
  }

  kh_destroy(asn_count, ac);
  destroy_subnet_hash(mstate->subnet_hash);
  mstate->subnet_hash = kh_init(subnet);

  return 0;
}
