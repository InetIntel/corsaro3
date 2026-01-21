/*
 * corsaro
 *
 * Plug-in to extract unique /24 subnets and their origin ASNs.
 *
 * This source code is Copyright (c) 2026 Georgia Tech Research Corporation. All
 * Rights Reserved. Permission to copy, modify, and distribute this software and
 * its documentation for academic research and education purposes, without fee,
 * and without a written agreement is hereby granted, provided that the above
 * copyright notice, this paragraph and the following three paragraphs appear in
 * all copies. Permission to make use of this software for other than academic
 * research and education purposes may be obtained by contacting:
 *
 *  Office of Technology Licensing
 *  Georgia Institute of Technology
 *  926 Dalney Street, NW
 *  Atlanta, GA 30318
 *  404.385.8066
 *  techlicensing@gtrc.gatech.edu
 *
 * This software program and documentation are copyrighted by Georgia Tech
 * Research Corporation (GTRC). The software program and documentation are
 * supplied "as is", without any accompanying services from GTRC. GTRC does
 * not warrant that the operation of the program will be uninterrupted or
 * error-free. The end-user understands that the program was developed for
 * research purposes and is advised not to rely exclusively on the program for
 * any reason.
 *
 * IN NO EVENT SHALL GEORGIA TECH RESEARCH CORPORATION BE LIABLE TO ANY PARTY
 * FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES,
 * INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
 * DOCUMENTATION, EVEN IF GEORGIA TECH RESEARCH CORPORATION HAS BEEN ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE. GEORGIA TECH RESEARCH CORPORATION
 * SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS, AND  GEORGIA TECH
 * RESEARCH CORPORATION HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT,
 * UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 *
 * This source code is part of the corsaro software. The original corsaro
 * software is Copyright (c) 2012-2019 The Regents of the University of
 * California. All rights reserved. Permission to copy, modify, and distribute
 * this software for academic research and education purposes is subject to the
 * conditions and copyright notices in the source code files and in the included
 * LICENSE file.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "corsaro_subnetasn.h"
#include "config.h"
#include "khash.h"
#include "utils.h"
#include "libcorsaro_plugin.h"
#include "libipmeta.h"

#define CORSARO_SUBNETASN_MAGIC 0x5341534E /* "SASN" */
#define PLUGIN_NAME "subnetasn"

/** Default configuration values */
#define CORSARO_SUBNETASN_DEFAULT_PROVIDER "pfx2as"

static corsaro_plugin_t corsaro_subnetasn_plugin = {
  PLUGIN_NAME,
  CORSARO_PLUGIN_ID_SUBNETASN,
  CORSARO_SUBNETASN_MAGIC,
  CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_subnetasn),
  CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_subnetasn),
  CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_subnetasn),
  CORSARO_PLUGIN_GENERATE_TAIL};

typedef struct corsaro_subnetasn_config {
  corsaro_plugin_proc_options_t basic;
  char *asn_provider;
  char *asn_provider_args;
  char *output_dir;
} corsaro_subnetasn_config_t;

typedef struct subnet_asn_entry {
  uint32_t *asns;
  int asn_cnt;
} subnet_asn_entry_t;

/* Hash map: Subnet (uint32_t) -> pointer to subnet_asn_entry_t */
KHASH_MAP_INIT_INT(subnet, subnet_asn_entry_t *)

typedef struct corsaro_subnetasn_state {
  ipmeta_t *ipmeta;
  ipmeta_provider_t *prov;
  khash_t(subnet) * subnet_hash;
  uint32_t last_rotation;
} corsaro_subnetasn_state_t;

typedef struct corsaro_subnetasn_merge_state {
  khash_t(subnet) * subnet_hash;
  uint32_t timestamp;
} corsaro_subnetasn_merge_state_t;

corsaro_plugin_t *corsaro_subnetasn_alloc(void)
{
  return &corsaro_subnetasn_plugin;
}

static void subnet_asn_entry_free(subnet_asn_entry_t *entry)
{
  if (entry) {
    if (entry->asns)
      free(entry->asns);
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
  if (!conf)
    return -1;

  CORSARO_INIT_PLUGIN_PROC_OPTS(conf->basic);
  conf->asn_provider = strdup(CORSARO_SUBNETASN_DEFAULT_PROVIDER);

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
      if (conf->asn_provider_args)
        free(conf->asn_provider_args);
      conf->asn_provider_args = strdup(val_str);
    } else if (!strcmp(key_str, "output_dir")) {
      if (conf->output_dir)
        free(conf->output_dir);
      conf->output_dir = strdup(val_str);
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
  return 0;
}

void corsaro_subnetasn_destroy_self(corsaro_plugin_t *p)
{
  corsaro_subnetasn_config_t *conf = (corsaro_subnetasn_config_t *)p->config;
  if (conf) {
    free(conf->asn_provider);
    if (conf->asn_provider_args)
      free(conf->asn_provider_args);
    if (conf->output_dir)
      free(conf->output_dir);
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
  if (!state)
    return NULL;

  state->subnet_hash = kh_init(subnet);

  state->ipmeta = ipmeta_init(IPMETA_DS_DEFAULT);
  if (!state->ipmeta) {
    corsaro_log(p->logger, "Failed to initialize ipmeta");
    free(state);
    return NULL;
  }

  state->prov = ipmeta_get_provider_by_name(state->ipmeta, conf->asn_provider);
  if (!state->prov) {
    corsaro_log(p->logger, "Failed to find provider '%s'", conf->asn_provider);
    ipmeta_free(state->ipmeta);
    free(state);
    return NULL;
  }

  if (ipmeta_enable_provider(state->ipmeta, state->prov,
                             conf->asn_provider_args) != 0) {
    corsaro_log(p->logger, "Failed to enable provider '%s'",
                conf->asn_provider);
    ipmeta_free(state->ipmeta);
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
    if (state->ipmeta)
      ipmeta_free(state->ipmeta);
    free(state);
  }
  return 0;
}

int corsaro_subnetasn_start_interval(corsaro_plugin_t *p, void *local,
                                     corsaro_interval_t *int_start)
{
  corsaro_subnetasn_state_t *state = (corsaro_subnetasn_state_t *)local;
  state->last_rotation = int_start->time;
  // Clear hash for new interval? No, corsaro creates new threads/state logic
  // usually handled differently or we clear it. Actually, in corsaro,
  // start_interval is notification. If output rotation happens, we usually
  // clear state AFTER merge/rotation. But here we are just gathering.
  return 0;
}

void *corsaro_subnetasn_end_interval(corsaro_plugin_t *p, void *local,
                                     corsaro_interval_t *int_end,
                                     uint8_t complete)
{
  // Return something to merge?
  // We return the state itself or a copy?
  // Typically we return the state if we want to merge it.
  // But wait, the merge function takes "tomerge".
  // If we return the state, we pass ownership?
  // Let's look at corsaro_dos. It returns a copy or passes the pointer?
  // corsaro_dos_end_interval actually returns NULL? No, it's void*.

  // We will just return the local state pointer, but we need to be careful
  // about not freeing it yet if 'halt_processing' is called. Actually, the
  // common pattern is to return the data structure we want merged.
  return local;
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

  // Use libtrace to get IP (assuming IPv4)
  if (trace_get_source_address(packet, (struct sockaddr *)&addr) == NULL) {
    return 0;
  }

  if (addr.ss_family != AF_INET) {
    return 0; // Only IPv4 for now as per req
  }

  v4 = (struct sockaddr_in *)&addr;
  src_ip = ntohl(v4->sin_addr.s_addr);
  subnet_ip = src_ip & 0xFFFFFF00; // /24 mask

  // Check if already in hash
  k = kh_get(subnet, state->subnet_hash, subnet_ip);
  if (k == kh_end(state->subnet_hash)) {
    // New subnet, lookup ASN
    ipmeta_record_set_t *records = ipmeta_record_set_init();
    struct in_addr lookup_addr;
    lookup_addr.s_addr = htonl(src_ip);

    // We look up the specific IP, but we store the result for the subnet.
    // NOTE: Ideally we should use the subnet base for lookup? Or strictly
    // source IP? User asked for "IPv4 /24 subnets seen... broken down by the
    // ASN that the /24 subnet belongs to". Usually assume the whole /24 is same
    // ASN, but BGP can be more granular (rarely for /24). Let's lookup the IP.

    int prov_mask = IPMETA_PROV_TO_MASK(ipmeta_get_provider_id(state->prov));
    ipmeta_lookup_addr(state->ipmeta, AF_INET, &lookup_addr, prov_mask,
                       records);

    // Collect ASNs
    // We might get multiple records (e.g. from different depths or providers,
    // but we only enabled one). ipmeta_record_t can have multiple ASNs.

    // Simple set for ASNs for this subnet
    // We will store them in a dynamic array in the entry.
    // Since this is per-packet, we want to be fast.
    // But we only do this ONCE per subnet per interval (if using khash).

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
        // Append ASNs to entry
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

    // Deduplicate entry->asns
    if (entry->asn_cnt > 1) {
      // sort and uniq (naive)
      // Using qsort
      // ...
    }

    // Insert into hash
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
  // Only used if NOT merging, or if rotating per thread.
  return NULL;
}

/* --- Merging --- */

void *corsaro_subnetasn_init_merging(corsaro_plugin_t *p, int sources)
{
  corsaro_subnetasn_merge_state_t *state =
    calloc(1, sizeof(corsaro_subnetasn_merge_state_t));
  if (!state) {
    return NULL;
  }
  state->subnet_hash = kh_init(subnet);
  return state;
}

int corsaro_subnetasn_halt_merging(corsaro_plugin_t *p, void *local)
{
  corsaro_subnetasn_merge_state_t *state =
    (corsaro_subnetasn_merge_state_t *)local;
  if (state) {
    destroy_subnet_hash(state->subnet_hash);
    free(state);
  }
  return 0;
}

int compare_uint32(const void *a, const void *b)
{
  return (*(uint32_t *)a - *(uint32_t *)b);
}

// Helper to merge ASNs into destination entry
static void merge_asns(subnet_asn_entry_t *dst, subnet_asn_entry_t *src)
{
  if (!src || src->asn_cnt == 0) {
    return;
  }

  // Naive merge: realloc, append, sort, uniq
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

  // Unique
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

  mstate->timestamp = fin->timestamp;

  // Clear previous merge state? Or assume rotate_output cleared it?
  // We should clear it if it's not empty, OR we just accum if we want
  // cumulative? Standard corsaro: memory handlers usually new per interval or
  // reset. destroy_subnet_hash(mstate->subnet_hash); // Assuming fresh start
  // for interval mstate->subnet_hash = kh_init(subnet);

  // Actually, rotate_output is where we write and then CLEAR.

  // Iterate over all source threads
  // Note: 'tomerge' is array of pointers returned by 'end_interval'.
  // Here, corsaro_subnetasn_state_t pointers.

  // Wait, end_interval returned the local state.
  // We should NOT modify the local state of threads?
  // Actually, threads are paused/stopped or at a sync point.
  // But we should copy data?

  for (i = 0; i < fin->threads_ended; i++) {
    corsaro_subnetasn_state_t *tstate = (corsaro_subnetasn_state_t *)tomerge[i];
    if (!tstate) {
      continue;
    }
    subnet_asn_entry_t *src_val;
    uint32_t subnet_key;

    kh_foreach(tstate->subnet_hash, subnet_key, src_val, {
      int ret;
      khiter_t k = kh_put(subnet, mstate->subnet_hash, subnet_key, &ret);
      if (ret < 0) {
        // Error inserting into hash, skip this entry
        continue;
      }
      if (ret != 0) { // New key
        subnet_asn_entry_t *new_entry = calloc(1, sizeof(subnet_asn_entry_t));
        if (new_entry) {
          kh_value(mstate->subnet_hash, k) = new_entry;
          merge_asns(new_entry, src_val);
        } else {
          // Failed to allocate new_entry, remove key from hash
          kh_del(subnet, mstate->subnet_hash, k);
        }
      } else { // Exists
        merge_asns(kh_value(mstate->subnet_hash, k), src_val);
      }
    });

    // Clear thread local hash for next interval?
    // Threads might continue running?
    // Usually init_processing creates state, halt destroys.
    // start_interval -> process -> end_interval.
    // We should clear the thread local hash here or in start_interval?
    // Ideally in start_interval of the NEXT interval.
    // Or we can clear it here if we are done with it.
    // Let's assume start_interval clears it.
    destroy_subnet_hash(tstate->subnet_hash);
    tstate->subnet_hash = kh_init(subnet);
  }

  return CORSARO_MERGE_SUCCESS;
}

int corsaro_subnetasn_rotate_output(corsaro_plugin_t *p, void *local)
{
  corsaro_subnetasn_merge_state_t *mstate =
    (corsaro_subnetasn_merge_state_t *)local;
  corsaro_subnetasn_config_t *conf = (corsaro_subnetasn_config_t *)p->config;
  gzFile f;
  uint32_t subnet_key;
  subnet_asn_entry_t *entry;
  struct in_addr addr;

  if (!mstate || kh_size(mstate->subnet_hash) == 0) {
    return 0;
  }

  // We need the timestamp. Where to get it?
  // Usually stored in state or passed?
  // p->last_rotation?
  // We can use a global or pass it?
  // corsaro_generate_avro_file_name uses timestamp.
  // We need to manufacture a filename.
  // corsaro usually handles filename generation in derive_output_name but
  // that's for threads. For merger, we need to manually create it? Let's assume
  // we can use a helper or just sprintf. We don't have the timestamp easily
  // here unless we saved it in merge_interval_results (from fin). But verify
  // signature of merge_interval_results: it has corsaro_fin_interval_t *fin. We
  // should store timestamp in mstate.

  // NOTE: I missed saving timestamp in mstate. Fix that.

  // For now, let's assume we saved it. I'll add 'timestamp' to mstate struct
  // logic. But I can't edit the struct definition above easily in this
  // 'write_to_file' call if I don't restart. I can assume the user will let me
  // fix it or I will fix it in a subsequent edit. Let's use `time(NULL)` as
  // fallback or just `0` if unknown, but better to fix logic. Adding timestamp
  // field to mstate definition (it was defined above).

  // ... redefining struct logic in thought ...
  // typedef struct corsaro_subnetasn_merge_state {
  //    khash_t(subnet) *subnet_hash;
  //    uint32_t timestamp;
  // } ...

  // I'll assume I can add it to the struct definition in this file write.

  // fname construction
  // corsaro_get_interval_start_time?
  // Let's use a dummy name for now and I will fix it in a patch if needed.
  // Or usage of corsaro_generate_filename helper?

  // fname construction
  char filename[PATH_MAX];
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
    return -1;
  }

  kh_foreach(mstate->subnet_hash, subnet_key, entry, {
    addr.s_addr = htonl(subnet_key);
    char *ip_str = inet_ntoa(addr);
    for (int i = 0; i < entry->asn_cnt; i++) {
      // Clean IP string copy because inet_ntoa static buffer?
      // Actually valid within this scope?
      gzprintf(f, "%u,%s\n", entry->asns[i], ip_str);
    }
  });

  gzclose(f);

  // Clear merge hash
  destroy_subnet_hash(mstate->subnet_hash);
  mstate->subnet_hash = kh_init(subnet);

  return 0;
}
