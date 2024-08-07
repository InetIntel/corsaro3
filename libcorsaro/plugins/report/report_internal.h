/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * Shane Alcock, WAND, University of Waikato
 *
 * corsaro-info@caida.org
 *
 * Copyright (C) 2012-2019 The Regents of the University of California.
 * All Rights Reserved.
 *
 * This file is part of corsaro.
 *
 * Permission to copy, modify, and distribute this software and its
 * documentation for academic research and education purposes, without fee, and
 * without a written agreement is hereby granted, provided that
 * the above copyright notice, this paragraph and the following paragraphs
 * appear in all copies.
 *
 * Permission to make use of this software for other than academic research and
 * education purposes may be obtained by contacting:
 *
 * Office of Innovation and Commercialization
 * 9500 Gilman Drive, Mail Code 0910
 * University of California
 * La Jolla, CA 92093-0910
 * (858) 534-5815
 * invent@ucsd.edu
 *
 * This software program and documentation are copyrighted by The Regents of the
 * University of California. The software program and documentation are supplied
 * “as is”, without any accompanying services from The Regents. The Regents does
 * not warrant that the operation of the program will be uninterrupted or
 * error-free. The end-user understands that the program was developed for
 * research purposes and is advised not to rely exclusively on the program for
 * any reason.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
 * EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN “AS IS” BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 */

#ifndef CORSARO_REPORT_INTERNAL_H_
#define CORSARO_REPORT_INTERNAL_H_

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libipmeta.h>
#include <zmq.h>

#include <Judy.h>
#include "libcorsaro_plugin.h"

/* XXX could make this configurable? */
/** The number of IP tag updates to include in a single enqueued message
 *  to an IP tracker thread. */
#define REPORT_BATCH_SIZE (10000)

/** Macro function for converting a metric class and value into a 64 bit
 *  number that we can use as a numeric hash key.
  */
#define GEN_METRICID(class, val) \
      ((((uint64_t) class) << 32) + ((uint64_t)val) & 0xFFFFFFFF)


#define IS_METRIC_ALLOWED(allowedmetrics, metric) \
      (allowedmetrics == 0 || (allowedmetrics & (1UL << metric)))

/** An upper bound on the number of possible ports */
#define METRIC_PORT_MAX (65536)
/** An upper bound on the number of ICMP message types and codes */
#define METRIC_ICMP_MAX (256)
/** An upper bound on the number of post-IP protocols */
#define METRIC_IPPROTOS_MAX (256)

/** Maximum number of IP tracker threads allowed */
#define CORSARO_REPORT_MAX_IPTRACKERS (32)

/** Maximum depth of sub-classification for hierarchical metrics, e.g. geolocation metrics
 *  have a hierarchy of continent, country, region, county, ... etc
 */
#define MAX_ASSOCIATED_METRICS (8)

typedef struct corsaro_report_config corsaro_report_config_t;
/* Note: these pre-defined alpha-2 codes are used to bootstrap the
 * results data so that we can reliably report 0 values for countries
 * that do not appear in a given interval, even if we've never seen that
 * country code before.
 * The list does not have to be exhaustive -- country codes that appear
 * but are not in the list below will begin to be reported as soon as they
 * are observed and all subsequent intervals should include results for
 * the 'new' code even if the packet count was zero. It is only intervals
 * prior to the country code being observed by the running instance of the
 * report plugin that will have missing values (in that case).
 */

/** Metrics that are supported by the report plugin */
typedef enum {
    CORSARO_METRIC_CLASS_COMBINED,
    CORSARO_METRIC_CLASS_MAXMIND_CONTINENT,
    CORSARO_METRIC_CLASS_MAXMIND_COUNTRY,
    CORSARO_METRIC_CLASS_NETACQ_CONTINENT,
    CORSARO_METRIC_CLASS_NETACQ_COUNTRY,
    CORSARO_METRIC_CLASS_PREFIX_ASN,
    CORSARO_METRIC_CLASS_TCP_SOURCE_PORT,
    CORSARO_METRIC_CLASS_TCP_DEST_PORT,
    CORSARO_METRIC_CLASS_UDP_SOURCE_PORT,
    CORSARO_METRIC_CLASS_UDP_DEST_PORT,
    CORSARO_METRIC_CLASS_IP_PROTOCOL,
    CORSARO_METRIC_CLASS_ICMP_TYPECODE,
    CORSARO_METRIC_CLASS_NETACQ_REGION,
    CORSARO_METRIC_CLASS_NETACQ_POLYGON,
    CORSARO_METRIC_CLASS_IPINFO_CONTINENT,
    CORSARO_METRIC_CLASS_IPINFO_COUNTRY,
    CORSARO_METRIC_CLASS_IPINFO_REGION,
    CORSARO_METRIC_CLASS_IPINFO_COUNTRY_PREFIX_ASN,
    CORSARO_METRIC_CLASS_IPINFO_REGION_PREFIX_ASN,
    CORSARO_METRIC_CLASS_FILTER_CRITERIA,
    CORSARO_METRIC_CLASS_LAST,      // always have at end of enum
} corsaro_report_metric_class_t;

/** Types of messages that can be sent to the IP tracker threads */
enum {
    CORSARO_IP_MESSAGE_HALT,        /**< Halt tracker thread */
    CORSARO_IP_MESSAGE_UPDATE,      /**< Message contains new stats */
    CORSARO_IP_MESSAGE_INTERVAL,    /**< Interval has ended, begin tally */
    CORSARO_IP_MESSAGE_RESET        /**< Force tallies to be reset */
};


/** Structure describing an IP address that has been observed by an IP
 *  tracker thread.
 *
 *  Unlike all other hashed structures, this one is more efficient to
 *  manage using uthash rather than khash.
 */
typedef struct corsaro_ip_hash {

    /** The IP address as a 32 bit integer */
    uint32_t ipaddr;

    /** Number of metrics associated with this IP. */
    uint32_t metriccount;

    /** Judy array used to store associated metrics */
    Pvoid_t metricsseen;
} PACKED corsaro_ip_hash_t;


/** Structure used to store the tallied statistics for a single metric */
typedef struct corsaro_metric_ip_hash_t {

    /** The metric ID -- for the general map, the upper 32 bits are the metric
     * type, lower 32 bits are the metric value. */
    uint64_t metricid;

    corsaro_report_metric_class_t metricclass;

    uint64_t associated_metricids[MAX_ASSOCIATED_METRICS];
    uint64_t associated_metricclasses[MAX_ASSOCIATED_METRICS];

    /** Unique source IPs associated with this metric */
    Pvoid_t srcips;

    /** Unique destination IPs associated with this metric */
    Pvoid_t destips;

    /** Unique source ASNs associated with this metric */
    Pvoid_t srcasns;

    /** Number of packets that were tagged with this metric */
    uint32_t packets;

    /** Number of IP-layer bytes in packets that were tagged with this metric */
    uint64_t bytes;

} PACKED corsaro_metric_ip_hash_t;

/** Structure for keeping track of missing messages between a processing
 *  thread and an IP tracker thread.
 */
typedef struct corsaro_report_iptracker_source {
    uint32_t expected;      /**< Expected sequence number of the next message */
    uint32_t lost;          /**< Total messages lost since last interval */
} corsaro_report_iptracker_source_t;

/** Structure used to keep track of which processing threads have ended
 *  an interval and which ones we are still waiting on.
 */
typedef struct corsaro_report_outstanding_interval {
    /** The timestamp for the interval in question */
    uint32_t interval_ts;

    /** Array of binary flags that indicate whether the thread at index i
     *  has sent us an interval end message or not. */
    uint8_t reports_recvd[256];

    /** Total number of interval end messages received for this interval */
    uint8_t reports_total;
} corsaro_report_out_interval_t;

typedef struct corsaro_report_iptracker_maps {
    corsaro_metric_ip_hash_t combined;

    corsaro_metric_ip_hash_t *ipprotocols;
    corsaro_metric_ip_hash_t *filters;

    Pvoid_t geoasns;
    Pvoid_t general;
} corsaro_report_iptracker_maps_t;

typedef struct corsaro_report_savedtags {
    uint64_t associated_metricids[MAX_ASSOCIATED_METRICS];
    uint64_t associated_metricclasses[MAX_ASSOCIATED_METRICS];
    uint64_t next_saved;

    uint32_t srcip;
    uint32_t destip;
    uint32_t srcasn;
    uint32_t bytes;
    uint32_t packets;
} corsaro_report_savedtags_t;

/** Structure to store state for an IP tracker thread */
typedef struct corsaro_report_iptracker {

    corsaro_report_config_t *conf;

    /** The queue for reading incoming messages from the processing threads */
    void *incoming;

    uint8_t *inbuf;
    uint32_t inbuflen;

    uint32_t srcip_sample_index;
    uint32_t dstip_sample_index;

    /** The timestamp of the interval that our most recent complete tally
     *  belongs to.
     */
    uint32_t lastresultts;

    /** The number of processing threads that are able to send messages to this
     *  IP tracker thread.
     */
    uint8_t sourcethreads;

    /** Tracks whether an IP tracker thread is ready to halt */
    uint8_t haltphase;

    uint8_t haltsseen;

    /** Thread ID for this IP tracker thread */
    pthread_t tid;

    /** Mutex used to protect the most recent complete tally */
    pthread_mutex_t mutex;

    corsaro_report_iptracker_maps_t *prev_maps;
    corsaro_report_iptracker_maps_t *curr_maps;
    corsaro_report_iptracker_maps_t *next_maps;

    corsaro_report_savedtags_t netacq_saved;
    corsaro_report_savedtags_t ipinfo_saved;

    /** Hash map containing the ongoing tallies for tags that should be
     *  counted towards the next interval. */
    Pvoid_t nextresult;

    /** Reference to a corsaro logger for logging error messages etc. */
    corsaro_logger_t *logger;

    /** List of intervals for which not all processing threads have sent
     *  us an interval end message.
     */
    libtrace_list_t *outstanding;

    /** Expected sequence numbers and loss counts for each source feeding
     *  into this tracker thread.
     */
    corsaro_report_iptracker_source_t *sourcetrack;

    /** Bitmask representing which metric classes are going to be tracked by
     *  this corsarotrace instance.
     *
     *  This is copied straight from the global config.
     */
    uint64_t allowedmetricclasses;

    uint64_t *geoasn_couplets;
    uint64_t geoasn_couplet_count;

} corsaro_report_iptracker_t;

typedef struct allowed_ports {
    uint8_t tcp_sources[8192];
    uint8_t tcp_dests[8192];
    uint8_t udp_sources[8192];
    uint8_t udp_dests[8192];
} allowed_ports_t;

/** Level of detail for reporting geo-tagged series
 *  LITE = just continents and countries
 *  FULL = continents, countries, regions and counties
 */
typedef enum {
    REPORT_GEOMODE_FULL,
    REPORT_GEOMODE_LITE
} corsaro_report_geomode_t;

typedef enum {
    REPORT_IPCOUNT_METHOD_ALL,
    REPORT_IPCOUNT_METHOD_SAMPLE,
    REPORT_IPCOUNT_METHOD_PREFIXAGG
} corsaro_report_ipcount_method_t;

typedef struct corsaro_report_ipcount_conf {
    corsaro_report_ipcount_method_t method;
    uint8_t pfxbits;
} corsaro_report_ipcount_conf_t;

typedef struct corsaro_report_config corsaro_report_config_t;

/** Structure describing configuration specific to the report plugin */
struct corsaro_report_config {

    /** Standard options, e.g. template */
    corsaro_plugin_proc_options_t basic;

    /** Additional labelling to attach to every avro record -- useful for
     *  distinguishing between different inputs, for instance */
    char *outlabel;

    /** Number of IP tracker threads to create */
    int tracker_count;

    /** Output format */
    corsaro_output_format_t outformat;

    /** Level of detail for reporting geo-tagged series */
    corsaro_report_geomode_t geomode;

    /** Array of operational IP tracker threads -- included in here because
     *  the merge thread needs to be able to access the thread structures and
     *  this was a relatively easy place to put them.
     */
    corsaro_report_iptracker_t *iptrackers;

    /** ZeroMQ queues that are used to communicate between processing threads
     *  and IP tracker threads.
     */
    void **tracker_queues;

    /** High water mark for internal messaging queues */
    uint16_t internalhwm;

    /** Flag that can be used to disable making queries to the tagger for
     *  fully qualified metric labels, especially for geo-tagging metrics.
     *  Intended as a transitional feature until all existing taggers are
     *  updated to support these queries -- having this enabled when
     *  receiving packets from a tagger that does not support it can lead to
     *  a failure to produce merged output if the tagger is under load.
     *
     *  TODO remove this option once it is no longer needed
     */
    uint8_t query_tagger_labels;

    /** Bitmask representing which metric classes are going to be tracked by
     *  this corsarotrace instance.
     *
     *  XXX should we get close to 64 total metrics, we're going to need to
     *  re-think this approach.
     */
    uint64_t allowedmetricclasses;

    /** TCP and UDP ports for which we are going to track per-port statistics.
     */
    allowed_ports_t allowedports;

    /** Configuration for how unique "IP"s are counted by this plugin
     *
     *  XXX consider whether we want to allow different config for each
     *  metric (if yes, we may want to redo our whole config process...)
     */
    corsaro_report_ipcount_conf_t src_ipcount_conf;
    corsaro_report_ipcount_conf_t dst_ipcount_conf;

    const char *geoasn_whitelist_file;
};



/** The statistics for a single IP + tag within an IP tracker update message */
typedef struct corsaro_report_msg_tag {
    /* The metric that this tag correspnds to */
    corsaro_report_metric_class_t tagclass;

    /** Unique ID for the tag */
    uint64_t tagid;

    /** Number of bytes sent by this IP address matching this tag */
    uint64_t bytes;

    /** Number of packets sent by this IP address matching this tag */
    uint32_t packets;

} PACKED corsaro_report_msg_tag_t;




/** Structure describing all of the metrics that apply to an IP that was
 *  observed within a libtrace packet.
 */
typedef struct corsaro_report_single_ip {

    /** The IP address itself */
    uint32_t ipaddr;

    /** The ASN for this IP (if it is a source IP) */
    uint32_t sourceasn;

    /** Flag indicating whether the IP was observed as a source IP */
    uint8_t issrc;

    /** The number of metric tags that are following this header */
    uint16_t numtags;

} PACKED corsaro_report_single_ip_header_t;

/** A message sent from a packet processing thread to an IP tracker thread */
typedef struct corsaro_report_ip_message {

    /** The type of message being sent, e.g. update, interval end or halt */
    uint8_t msgtype;

    /** The thread ID of the processing thread that is sending the message */
    uint8_t sender;

    /** The timestamp of the interval that is ending (interval end msg only) */
    uint32_t timestamp;

    /** The number of IP + tag updates included in this message */
    uint32_t bodycount;

    /** The sequence number for this message, used to detect loss within
     *  ZeroMQ */
    uint32_t seqno;

    uint32_t tagcount;
} PACKED corsaro_report_ipmsg_header_t;



/** Structure containing data that is to be transferred from a packet
 *  processing thread to the merge thread when an interval ends.
 */
typedef struct corsaro_report_interim {

    /** Global configuration for the processing threads */
    corsaro_report_config_t *baseconf;
} corsaro_report_interim_t;




/** Structure containing the final combined tally for a single metric within
 *  an interval.
 */
typedef struct corsaro_report_result {
    /** The metric ID -- for most metrics, the upper 32 bits are the metric
     *  type, lower 32 bits are the metric value. */
    uint64_t metricid;

    corsaro_report_metric_class_t metricclass;

    /** Total number of packets tagged with this metric */
    uint64_t pkt_cnt;

    /** Total number of IP-layer bytes in packets tagged with this metric */
    uint64_t bytes;

    /** Total number of unique source IPs that sent packets tagged with this
     *  metric */
    uint32_t uniq_src_ips;

    /** Total number of unique destination IPs that received packets tagged
     *  with this metric */
    uint32_t uniq_dst_ips;

    /** Set of unique ASNs that sent packets tagged with this metric. */
    Pvoid_t uniq_src_asns;

    Pvoid_t uniq_src_ipset;
    Pvoid_t uniq_dst_ipset;

    uint32_t uniq_src_asn_count;

    /** The timestamp of the interval that this tally applies to */
    uint32_t attimestamp;

    /** An user-defined identifying label to include with this result */
    char *label;

    /** A string representation of the metric class */
    char metrictype[256];

    /** A string representation of the metric value */
    char metricval[128];

} PACKED corsaro_report_result_t;

void *start_iptracker(void *tdata);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
