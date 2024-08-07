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

#include "libcorsaro.h"
#include "libcorsaro_plugin.h"
#include "libcorsaro_common.h"
#include "libcorsaro_avro.h"
#include "corsaro_report.h"
#include "utils.h"
#include "report_internal.h"

/** Broad overview of this whole plugin, since it is a *bit* complicated.
 *
 *  Our goal is to count the number of packets, bytes, source IPs and
 *  dest IPs observed per minute for each supported metric.
 *
 *  The IP counting is the challenging part, as we need to keep track of
 *  which IPs we've seen already so as not to count them twice, but we also
 *  need to account for the possibility that an IP can appear on multiple
 *  processing threads.
 *  Also, on the telescope we can end up seeing a LOT of unique IPs even in
 *  the space of a minute so we have to be careful about both memory usage and
 *  CPU time efficiency.
 *
 *  Here's how it all works out:
 *  We start with N packet processing threads, as with any other plugin.
 *  We use parallel libtrace to funnel packets to each thread using our
 *  standard hashing approach.
 *
 *  We also create a set of IP tracker threads (4 by default). Each of
 *  the IP tracker threads has a queue associated with it and the queues
 *  are available to the packet processing threads.
 *
 *  For each packet received by a packet processing thread, we...
 *    - grab the source IP address
 *    - map that IP address to one of the IP tracker threads using a
 *      consistent deterministic function.
 *    - update an internal map (keyed by the IP address) that keeps track
 *      of each tag observed for that address and increment the number of
 *      packets and bytes seen for each IP + tag combination that applies
 *      to this packet. There is one map per tracker thread.
 *    - repeat for the destination address, but do NOT increment packets
 *      or bytes for each metric (otherwise we count the packet twice).
 *    - when we have either a decent number of IP addresses in a map, or
 *      a single IP address accumulates a large number of tags, create a
 *      message to send to the corresponding IP tracker containing all of
 *      the IPs, their tags and the packet/byte counts for each tag. Send
 *      the message and reset the map for that tracker thread.
 *
 *  At the end of the interval, our packet processing thread pushes on an
 *  "interval" message to each IP tracker thread to signal that it has sent
 *  all of the packets for that interval.
 *
 *  At the same time, an IP tracker thread continuously reads messages from
 *  its queue. Update messages are used to update the thread's internal
 *  record of all observed IPs, the metrics that apply to each IP and the
 *  byte, IP and packet tallies for each metric. When an interval message
 *  has been received from all processing threads, the final tally for the
 *  tracker thread is confirmed and the "last" interval timestamp is updated
 *  to signify that the tally is complete.
 *
 *  Finally, the merge thread waits for an interval end trigger from the
 *  processing loop. Once received, it will poll until all of the tracker
 *  threads have signalled that their tally for that interval is complete.
 *  As tallies become available, the merge thread simply adds them together
 *  since there should be no tallies containing overlapping IPs (because of
 *  the hash of IP address to IP tracker thread). Once all tallies have been
 *  received, the combined tally is turned into Avro records and written to
 *  the results file.
 */



/** The magic number for this plugin - "REPT" */
#define CORSARO_REPORT_MAGIC 0x52455054

/** The name for this plugin */
#define PLUGIN_NAME "report"

/** Common plugin information and function callbacks */
static corsaro_plugin_t corsaro_report_plugin = {
    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_REPORT,
    CORSARO_REPORT_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_TAIL
};

/** Allows external access to the report plugin definition and callbacks */
corsaro_plugin_t *corsaro_report_alloc(void) {
    return &(corsaro_report_plugin);
}

#define INVALID_PORT 0xFFFFFFFF

static inline unsigned long int strtoport(char *ptr, bool capmax,
        corsaro_logger_t *logger) {

    unsigned long int first;
    errno = 0;
    first = strtoul(ptr, NULL, 0);
    if (errno != 0) {
        corsaro_log(logger, "Error converting '%s' to port number: %s",
                ptr, strerror(errno));
        return INVALID_PORT;
    }

    if (first > 65535 && capmax == false) {
        corsaro_log(logger, "Invalid port number in portrange option '%s'",
                ptr);
        return INVALID_PORT;
    } else if (first > 65535) {
        first = 65535;
    }

    return first;
}

static void parse_ip_counting(corsaro_report_ipcount_conf_t *ipconf,
        yaml_document_t *doc, yaml_node_t *yamlconf, corsaro_logger_t *logger) {

    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    for (pair = yamlconf->data.mapping.pairs.start;
            pair < yamlconf->data.mapping.pairs.top; pair ++) {

        char *val;
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);
        val = (char *)value->data.scalar.value;

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "method") == 0) {

            if (strcasecmp(val, "sample") == 0) {
                ipconf->method = REPORT_IPCOUNT_METHOD_SAMPLE;
            } else if (strcasecmp(val, "prefixagg") == 0) {
                ipconf->method = REPORT_IPCOUNT_METHOD_PREFIXAGG;
            } else if (strcasecmp(val, "none") == 0) {
                ipconf->method = REPORT_IPCOUNT_METHOD_ALL;
            } else {
                corsaro_log(logger,
                        "Invalid method for counting unique IPs: '%s'",
                        val);
                corsaro_log(logger, "Ignoring...");
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "subnetmask") == 0) {
            uint32_t optval = strtoul((char *)val, NULL, 0);
            if (optval > 32) {
                ipconf->pfxbits = 32;
            } else if (optval == 0) {
                ipconf->pfxbits = 32;
            } else {
                ipconf->pfxbits = optval;
            }
        }
    }

}

static void parse_port_ranges(uint8_t *port_array, yaml_document_t *doc,
        yaml_node_t *rangelist, bool *seen_flag, corsaro_logger_t *logger) {

    yaml_node_item_t *item;
    for (item = rangelist->data.sequence.items.start;
            item != rangelist->data.sequence.items.top; item++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        char *range, *dash = NULL;
        unsigned long int first, last;
        int index = 0, firstindex = 0;

        if (node->type != YAML_SCALAR_NODE) {
            corsaro_log(logger, "Invalid YAML configuration for a portrange option -- ignoring");
            return;
        }
        range = (char *)node->data.scalar.value;

        dash = strchr(range, '-');
        if (dash == NULL) {
            first = strtoport(range, false, logger);
            if (first == INVALID_PORT) {
                continue;
            }
            last = first;
        } else {
            *dash = '\0';
            first = strtoport(range, false, logger);
            *dash = '-';
            if (first == INVALID_PORT) {
                continue;
            }
            last = strtoport(dash + 1, true, logger);
            if (last == INVALID_PORT) {
                continue;
            }
        }
        if (last < first) {
            corsaro_log(logger, "Invalid port range configuration '%s' -- first port must be <= the last port", range);
            continue;
        }

        if (*seen_flag == false) {
            memset(port_array, 0, 8192 * sizeof(uint8_t));
            *seen_flag = true;
        }

        corsaro_log(logger, "Setting port range to %u : %u", first, last);

        firstindex = (first / 8);
        for (index = firstindex; index < 8192; index ++) {
            int msb = index * 8;
            int lsb = msb + 7;
            uint8_t toadd = 0xff;

            if (msb > last) {
                break;
            }

            if (first > msb) {
                if (first - msb >= 8) {
                    toadd = 0;
                } else {
                    toadd &= ((0xff) >> (first - msb));
                }
            }

            if (last < lsb) {
                if (lsb - last >= 8) {
                    toadd = 0;
                } else {
                    toadd &= ((0xff) << (lsb - last));
                }
            }
            port_array[index] |= toadd;
        }
    }
}

static void parse_metric_limits(corsaro_report_config_t *conf,
        yaml_document_t *doc, yaml_node_t *metlist, corsaro_logger_t *logger) {

    yaml_node_item_t *item;
    for (item = metlist->data.sequence.items.start;
            item != metlist->data.sequence.items.top; item++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        char *name;

        if (node->type != YAML_SCALAR_NODE) {
            corsaro_log(logger, "Invalid YAML configuration for 'limitmetrics' option -- ignoring");
            conf->allowedmetricclasses = 0;
            return;
        }

        name = (char *)node->data.scalar.value;
        if (strcasecmp(name, "basic") == 0) {
            conf->allowedmetricclasses |=
                    ((1UL << CORSARO_METRIC_CLASS_COMBINED) |
                     (1UL << CORSARO_METRIC_CLASS_IP_PROTOCOL));
        }
        if (strcasecmp(name, "tcpports") == 0) {
            conf->allowedmetricclasses |=
                    ((1UL << CORSARO_METRIC_CLASS_TCP_SOURCE_PORT) |
                     (1UL << CORSARO_METRIC_CLASS_TCP_DEST_PORT));
        }
        if (strcasecmp(name, "udpports") == 0) {
            conf->allowedmetricclasses |=
                    ((1UL << CORSARO_METRIC_CLASS_UDP_SOURCE_PORT) |
                     (1UL << CORSARO_METRIC_CLASS_UDP_DEST_PORT));
        }
        if (strcasecmp(name, "icmp") == 0) {
            conf->allowedmetricclasses |=
                    ((1UL << CORSARO_METRIC_CLASS_ICMP_TYPECODE));
        }
        if (strcasecmp(name, "netacq") == 0) {
            conf->allowedmetricclasses |=
                    ((1UL << CORSARO_METRIC_CLASS_NETACQ_CONTINENT) |
                     (1UL << CORSARO_METRIC_CLASS_NETACQ_COUNTRY) |
                     (1UL << CORSARO_METRIC_CLASS_NETACQ_REGION) |
                     (1UL << CORSARO_METRIC_CLASS_NETACQ_POLYGON));
        }
        if (strcasecmp(name, "maxmind") == 0) {
            conf->allowedmetricclasses |=
                    ((1UL << CORSARO_METRIC_CLASS_MAXMIND_CONTINENT) |
                     (1UL << CORSARO_METRIC_CLASS_MAXMIND_COUNTRY));
        }
        if (strcasecmp(name, "ipinfo") == 0) {
            conf->allowedmetricclasses |=
                    ((1UL << CORSARO_METRIC_CLASS_IPINFO_CONTINENT) |
                     (1UL << CORSARO_METRIC_CLASS_IPINFO_REGION) |
                     (1UL << CORSARO_METRIC_CLASS_IPINFO_COUNTRY));
        }
        if (strcasecmp(name, "pfx2asn") == 0) {
            conf->allowedmetricclasses |=
                     ((1UL << CORSARO_METRIC_CLASS_PREFIX_ASN) |
                      (1UL << CORSARO_METRIC_CLASS_IPINFO_COUNTRY_PREFIX_ASN) |
                      (1UL << CORSARO_METRIC_CLASS_IPINFO_REGION_PREFIX_ASN));
        }

        if (strcasecmp(name, "filter") == 0) {
            conf->allowedmetricclasses |=
                    (1UL << CORSARO_METRIC_CLASS_FILTER_CRITERIA);
        }
    }
}

/** Parses the YAML configuration specific to the report plugin
 *
 *  @param p        A pointer to an instance of the report plugin.
 *  @param doc      A reference to the YAML document being parsed.
 *  @param options  A reference to the report plugin config section from the
 *                  YAML document.
 *  @return 0 if the report plugin config was parsed without problems, -1 if
 *            an error occurred.
 */
int corsaro_report_parse_config(corsaro_plugin_t *p, yaml_document_t *doc,
        yaml_node_t *options) {

    corsaro_report_config_t *conf;
    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;
    bool set_tcp_src_ports = false;
    bool set_udp_src_ports = false;
    bool set_tcp_dest_ports = false;
    bool set_udp_dest_ports = false;

    conf = (corsaro_report_config_t *)malloc(sizeof(corsaro_report_config_t));
    if (conf == NULL) {
        corsaro_log(p->logger,
                "unable to allocate memory to store report plugin config.");
        return -1;
    }

    CORSARO_INIT_PLUGIN_PROC_OPTS(conf->basic);
    conf->outlabel = NULL;
    conf->outformat = CORSARO_OUTPUT_AVRO;
    conf->tracker_count = 4;
    conf->query_tagger_labels = 1;
    conf->internalhwm = 30;
    /* zero is a special value to represent 'all' metrics */
    conf->allowedmetricclasses = 0;
    conf->geomode = REPORT_GEOMODE_FULL;
    conf->src_ipcount_conf.method = REPORT_IPCOUNT_METHOD_ALL;
    conf->src_ipcount_conf.pfxbits = 32;
    conf->dst_ipcount_conf.method = REPORT_IPCOUNT_METHOD_ALL;
    conf->dst_ipcount_conf.pfxbits = 32;
    conf->geoasn_whitelist_file = NULL;


    if (options->type != YAML_MAPPING_NODE) {
        corsaro_log(p->logger,
                "report plugin config should be a map.");
        free(conf);
        return -1;
    }

    for (pair = options->data.mapping.pairs.start;
            pair < options->data.mapping.pairs.top; pair ++) {

        char *val;
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);
        val = (char *)value->data.scalar.value;

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "output_row_label") == 0) {
            if (conf->outlabel) {
                corsaro_log(p->logger,
                        "duplicate definition of 'output_row_label' in report config -- using latter.");
                free(conf->outlabel);
            }
            conf->outlabel = strdup(val);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SEQUENCE_NODE
                    && strcmp((char *)key->data.scalar.value,
                            "tcp_source_port_range") == 0) {
            parse_port_ranges(conf->allowedports.tcp_sources, doc, value,
                    &set_tcp_src_ports, p->logger);

        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SEQUENCE_NODE
                    && strcmp((char *)key->data.scalar.value,
                            "tcp_dest_port_range") == 0) {
            parse_port_ranges(conf->allowedports.tcp_dests, doc, value,
                    &set_tcp_dest_ports, p->logger);

        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SEQUENCE_NODE
                    && strcmp((char *)key->data.scalar.value,
                            "udp_source_port_range") == 0) {
            parse_port_ranges(conf->allowedports.udp_sources, doc, value,
                    &set_udp_src_ports, p->logger);

        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SEQUENCE_NODE
                    && strcmp((char *)key->data.scalar.value,
                            "udp_dest_port_range") == 0) {
            parse_port_ranges(conf->allowedports.udp_dests, doc, value,
                    &set_udp_dest_ports, p->logger);

        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_MAPPING_NODE
                    && strcmp((char *)key->data.scalar.value,
                            "source_ip_counting") == 0) {

            parse_ip_counting(&(conf->src_ipcount_conf), doc, value, p->logger);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_MAPPING_NODE
                    && strcmp((char *)key->data.scalar.value,
                            "dest_ip_counting") == 0) {

            parse_ip_counting(&(conf->dst_ipcount_conf), doc, value, p->logger);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SEQUENCE_NODE
                    && strcmp((char *)key->data.scalar.value, "limitmetrics")
                            == 0) {
            parse_metric_limits(conf, doc, value, p->logger);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                    && strcmp((char *)key->data.scalar.value,
                    "iptracker_threads") == 0) {

            conf->tracker_count = strtol((char *)value->data.scalar.value,
                    NULL, 0);
            if (conf->tracker_count < 1) {
                conf->tracker_count = 1;
            }
            if (conf->tracker_count > CORSARO_REPORT_MAX_IPTRACKERS) {
                corsaro_log(p->logger, "report plugin: iptracker thread count is currently capped at %d", CORSARO_REPORT_MAX_IPTRACKERS);
                conf->tracker_count = CORSARO_REPORT_MAX_IPTRACKERS;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                    && strcmp((char *)key->data.scalar.value,
                    "internalhwm") == 0) {
            uint64_t optval;

            optval = strtoul((char *)value->data.scalar.value, NULL, 0);
            if (optval > 65535) {
                conf->internalhwm = 0;
            } else {
                conf->internalhwm = optval;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                    && strcmp((char *)key->data.scalar.value,
                    "querytaggerlabels") == 0) {

            if (parse_onoff_option(p->logger, (char *)value->data.scalar.value,
                    &(conf->query_tagger_labels), "query_tagger_labels") < 0) {
                corsaro_log(p->logger, "setting query_tagger_labels to disabled");
                conf->query_tagger_labels = 0;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "geo_mode") == 0) {

            if (strcasecmp((char *)value->data.scalar.value, "lite") == 0) {
                conf->geomode = REPORT_GEOMODE_LITE;
            } else if (strcasecmp((char *)value->data.scalar.value,
                    "full") == 0) {
                conf->geomode = REPORT_GEOMODE_FULL;
            } else {
                corsaro_log(p->logger, "unexpected geo_mode value: '%s', valid values are 'lite' or 'full'",
                        (char *)value->data.scalar.value);
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "geoasn_whitelist_file") == 0) {
            if (conf->geoasn_whitelist_file) {
                free(conf->geoasn_whitelist_file);
            }
            conf->geoasn_whitelist_file =
                    strdup((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "output_format") == 0) {
           if (strcmp((char *)value->data.scalar.value, "avro") == 0) {
                conf->outformat = CORSARO_OUTPUT_AVRO;
           } else if (strcmp((char *)value->data.scalar.value,
                    "libtimeseries") == 0) {
                conf->outformat = CORSARO_OUTPUT_LIBTIMESERIES;
           } else {
                corsaro_log(p->logger, "output format '%s' is not supported by the report plugin.",
                        (char *)value->data.scalar.value);
                corsaro_log(p->logger, "falling back to avro output.");
                conf->outformat = CORSARO_OUTPUT_AVRO;
           }
        }
    }

    /* If no specific port ranges are given, then default to reporting
     * time series for ALL ports
     */
    if (set_tcp_src_ports == false) {
        memset(conf->allowedports.tcp_sources, 0xff, sizeof(uint8_t) * 8192);
    }
    if (set_tcp_dest_ports == false) {
        memset(conf->allowedports.tcp_dests, 0xff, sizeof(uint8_t) * 8192);
    }
    if (set_udp_src_ports == false) {
        memset(conf->allowedports.udp_sources, 0xff, sizeof(uint8_t) * 8192);
    }
    if (set_udp_dest_ports == false) {
        memset(conf->allowedports.udp_dests, 0xff, sizeof(uint8_t) * 8192);
    }

    p->config = conf;

    return 0;
}

/** Complete configuration for the report plugin and assign default values
 *  to any unconfigured options.
 *
 *  This function also initialises and starts the IP tracker threads, so that
 *  they are up and running as soon as we start processing packets.
 *
 *  @param p        A reference to the running instance of the report plugin
 *  @param stdopts  The set of global-level options that are common to every
 *                  plugin
 *  @param zmq_ctxt A ZeroMQ contect for the entire process that can be
 *                  used to create new messaging sockets
 *  @return 0 if successful, -1 if an error occurred.
 */
int corsaro_report_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt) {

    corsaro_report_config_t *conf;
    int i, j, ret = 0, rto=10, hwm=50, inchwm;
    char sockname[40];

    conf = (corsaro_report_config_t *)(p->config);
    conf->basic.template = stdopts->template;
    conf->basic.monitorid = stdopts->monitorid;
    conf->basic.procthreads = stdopts->procthreads;
    conf->basic.libtsascii = stdopts->libtsascii;
    conf->basic.libtskafka = stdopts->libtskafka;
    conf->basic.libtsdbats = stdopts->libtsdbats;

    if (conf->outlabel == NULL) {
        conf->outlabel = strdup("unlabeled");
    }

    corsaro_log(p->logger,
            "report plugin: labeling all output rows with '%s'",
            conf->outlabel);

    if (conf->geoasn_whitelist_file) {
        corsaro_log(p->logger,
                "report plugin: reading valid geoasn couplets from '%s'",
                conf->geoasn_whitelist_file);
    } else {
        corsaro_log(p->logger,
                "report plugin: no geoasn couplet whitelist specified");
    }

    if (conf->outformat == CORSARO_OUTPUT_AVRO) {
        corsaro_log(p->logger,
                "report plugin: writing output to avro files");
    } else if (conf->outformat == CORSARO_OUTPUT_LIBTIMESERIES) {
        corsaro_log(p->logger,
                "report plugin: writing output using libtimeseries");
        display_libts_ascii_options(p->logger, conf->basic.libtsascii,
                "report plugin");
        display_libts_kafka_options(p->logger, conf->basic.libtskafka,
                "report plugin");
        display_libts_dbats_options(p->logger, conf->basic.libtsdbats,
                "report plugin");
    } else {
        corsaro_log(p->logger,
                "report plugin: invalid value for output format (?)");
    }

    if (conf->allowedmetricclasses == 0) {
        corsaro_log(p->logger, "report plugin: tracking ALL metrics");
    } else {
        if (conf->allowedmetricclasses & (1 << CORSARO_METRIC_CLASS_COMBINED)) {
            corsaro_log(p->logger, "report plugin: tracking basic metrics");
        }
        if (conf->allowedmetricclasses &
                (1 << CORSARO_METRIC_CLASS_ICMP_TYPECODE)) {
            corsaro_log(p->logger, "report plugin: tracking ICMP metrics");
        }
        if (conf->allowedmetricclasses &
                (1 << CORSARO_METRIC_CLASS_TCP_SOURCE_PORT))
        {
            corsaro_log(p->logger, "report plugin: tracking TCP metrics");
        }
        if (conf->allowedmetricclasses &
                (1 << CORSARO_METRIC_CLASS_UDP_SOURCE_PORT))
        {
            corsaro_log(p->logger, "report plugin: tracking UDP metrics");
        }
        if (conf->allowedmetricclasses &
                (1 << CORSARO_METRIC_CLASS_NETACQ_CONTINENT))
        {
            corsaro_log(p->logger,
                "report plugin: tracking Netacq-Edge metrics");
        }
        if (conf->allowedmetricclasses &
                (1 << CORSARO_METRIC_CLASS_IPINFO_CONTINENT))
        {
            corsaro_log(p->logger,
                "report plugin: tracking IPInfo metrics");
        }
        if (conf->allowedmetricclasses &
                (1 << CORSARO_METRIC_CLASS_MAXMIND_CONTINENT))
        {
            corsaro_log(p->logger, "report plugin: tracking Maxmind metrics");
        }
        if (conf->allowedmetricclasses & (1 << CORSARO_METRIC_CLASS_PREFIX_ASN))
        {
            corsaro_log(p->logger, "report plugin: tracking pfx2asn metrics");
        }
        if (conf->allowedmetricclasses &
                (1 << CORSARO_METRIC_CLASS_FILTER_CRITERIA))
        {
            corsaro_log(p->logger, "report plugin: tracking filtering metrics");
        }
    }

    if (    (conf->allowedmetricclasses &
                        (1 << CORSARO_METRIC_CLASS_NETACQ_CONTINENT)) ||
            (conf->allowedmetricclasses &
                        (1 << CORSARO_METRIC_CLASS_IPINFO_CONTINENT)) ||
            (conf->allowedmetricclasses &
                        (1 << CORSARO_METRIC_CLASS_MAXMIND_CONTINENT))) {

        uint64_t todisable = 0;
        if (conf->geomode == REPORT_GEOMODE_LITE) {
            corsaro_log(p->logger,
                    "report plugin: geo-tagging limited to continents and countries");
            todisable |= (1 << CORSARO_METRIC_CLASS_NETACQ_REGION);
            todisable |= (1 << CORSARO_METRIC_CLASS_NETACQ_POLYGON);
            todisable |= (1 << CORSARO_METRIC_CLASS_IPINFO_REGION);

            conf->allowedmetricclasses &= (~(todisable));
        } else {
            corsaro_log(p->logger,
                    "report plugin: full geo-tagging enabled");
        }

    }

    if (conf->src_ipcount_conf.method == REPORT_IPCOUNT_METHOD_ALL) {
        corsaro_log(p->logger,
                "report plugin: counting all unique source IPs");
    } else if (conf->src_ipcount_conf.method == REPORT_IPCOUNT_METHOD_PREFIXAGG) {
        corsaro_log(p->logger,
                "report plugin: aggregating source IPs into /%us",
                conf->src_ipcount_conf.pfxbits);
    } else if (conf->src_ipcount_conf.method == REPORT_IPCOUNT_METHOD_SAMPLE) {
        corsaro_log(p->logger,
                "report plugin: counting sampled source IPs (1 per /%u)",
                conf->src_ipcount_conf.pfxbits);
    }

    if (conf->dst_ipcount_conf.method == REPORT_IPCOUNT_METHOD_ALL) {
        corsaro_log(p->logger,
                "report plugin: counting all unique dest IPs");
    } else if (conf->dst_ipcount_conf.method == REPORT_IPCOUNT_METHOD_PREFIXAGG) {
        corsaro_log(p->logger,
                "report plugin: aggregating dest IPs into /%us",
                conf->dst_ipcount_conf.pfxbits);
    } else if (conf->dst_ipcount_conf.method == REPORT_IPCOUNT_METHOD_SAMPLE) {
        corsaro_log(p->logger,
                "report plugin: counting sampled dest IPs (1 per /%u)",
                conf->dst_ipcount_conf.pfxbits);
    }

    corsaro_log(p->logger,
            "report plugin: starting %d IP tracker threads",
            conf->tracker_count);
    if (conf->query_tagger_labels == 0) {
        corsaro_log(p->logger,
                "report plugin: NOT querying the tagger for FQ geo-location labels");
    }

    hwm = conf->internalhwm;
    inchwm = hwm * conf->basic.procthreads;

    corsaro_log(p->logger, "report plugin: using internal queue HWM of %u",
            conf->internalhwm);

    /* Create and start the IP tracker threads.
     *
     * We include the tracker thread references in the config, because
     * that is easily available in both the packet processing and
     * merging threads.
     */
    conf->iptrackers = (corsaro_report_iptracker_t *)calloc(
            conf->tracker_count, sizeof(corsaro_report_iptracker_t));
    conf->tracker_queues = calloc(conf->tracker_count * conf->basic.procthreads,
		sizeof(void *));

    for (i = 0; i < conf->tracker_count; i++) {

        pthread_mutex_init(&(conf->iptrackers[i].mutex), NULL);
        conf->iptrackers[i].lastresultts = 0;
        conf->iptrackers[i].conf = conf;
        conf->iptrackers[i].srcip_sample_index = 0;
        conf->iptrackers[i].dstip_sample_index = 0;
        conf->iptrackers[i].inbuf = NULL;
        conf->iptrackers[i].inbuflen = 0;
        conf->iptrackers[i].prev_maps = NULL;
        conf->iptrackers[i].curr_maps = NULL;
        conf->iptrackers[i].next_maps = NULL;
        conf->iptrackers[i].logger = p->logger;
        conf->iptrackers[i].sourcethreads = stdopts->procthreads;
        conf->iptrackers[i].haltphase = 0;
        conf->iptrackers[i].haltsseen = 0;
        conf->iptrackers[i].allowedmetricclasses = conf->allowedmetricclasses;
        conf->iptrackers[i].outstanding = libtrace_list_init(
               sizeof(corsaro_report_out_interval_t));

        conf->iptrackers[i].sourcetrack = calloc(stdopts->procthreads,
                sizeof(corsaro_report_iptracker_source_t));

        snprintf(sockname, 40, "inproc://reporttracker%d", i);

        conf->iptrackers[i].incoming = zmq_socket(zmq_ctxt, ZMQ_PULL);
        if (zmq_setsockopt(conf->iptrackers[i].incoming, ZMQ_RCVTIMEO, &rto,
                    sizeof(rto)) < 0) {
            corsaro_log(p->logger,
                    "error while configuring ip tracker %d pull socket: %s", i,
                    strerror(errno));
            ret = -1;
        }

        if (zmq_setsockopt(conf->iptrackers[i].incoming, ZMQ_RCVHWM, &inchwm,
                    sizeof(inchwm)) < 0) {
            corsaro_log(p->logger,
                    "error while configuring ip tracker %d pull socket: %s", i,
                    strerror(errno));
            ret = -1;
        }

        if (zmq_bind(conf->iptrackers[i].incoming, sockname) < 0) {
            corsaro_log(p->logger,
                    "error while binding ip tracker %d pull socket: %s", i,
                    strerror(errno));
            ret = -1;
        }

        /* Each processing thread needs a queue for it to send messages to
         * each of the IP tracking threads, so we need m * n queues (where
         * m = num proc threads and n = num tracker threads).
         *
         * Lay them out in such a way that the proc threads can easily
         * identify "their" queues.
         */
        for (j = 0; j < conf->basic.procthreads; j++) {
            int tq_id = i * conf->basic.procthreads + j;
            conf->tracker_queues[tq_id] = zmq_socket(zmq_ctxt, ZMQ_PUSH);
            if (zmq_setsockopt(conf->tracker_queues[tq_id], ZMQ_SNDHWM, &hwm,
                        sizeof(hwm)) < 0) {
                corsaro_log(p->logger,
                        "error while configuring ip tracker %d push socket: %s", tq_id,
                        strerror(errno));
                ret = -1;
            }

            if (zmq_connect(conf->tracker_queues[tq_id], sockname) < 0) {
                corsaro_log(p->logger,
                        "error while connecting ip tracker %d-%d push socket: %s",
                        i, j, strerror(errno));
                ret = -1;
            }
        }


        pthread_create(&(conf->iptrackers[i].tid), NULL,
                start_iptracker, &(conf->iptrackers[i]));
    }

    return ret;
}

/** Tidies up all memory allocated by this instance of the report plugin.
 *
 *  @param p    A reference to the running instance of the report plugin
 */
void corsaro_report_destroy_self(corsaro_plugin_t *p) {
    int i, j;
    if (p->config) {
        corsaro_report_config_t *conf;
        conf = (corsaro_report_config_t *)(p->config);
        if (conf->outlabel) {
            free(conf->outlabel);
        }
        if (conf->geoasn_whitelist_file) {
            free(conf->geoasn_whitelist_file);
        }

        /* Hopefully the tracker threads have joined by this point... */
        if (conf->iptrackers) {
            for (i = 0; i < conf->tracker_count; i++) {
                pthread_mutex_destroy(&(conf->iptrackers[i].mutex));

                zmq_close(conf->iptrackers[i].incoming);
                for (j = 0; j < conf->basic.procthreads; j++) {
                    zmq_close(conf->tracker_queues[
                            i * conf->basic.procthreads + j]);
                }
                if (conf->iptrackers[i].inbuf) {
                    free(conf->iptrackers[i].inbuf);
                }
                free(conf->iptrackers[i].sourcetrack);
                libtrace_list_deinit(conf->iptrackers[i].outstanding);
            }
            free(conf->iptrackers);
            free(conf->tracker_queues);
        }

        free(p->config);
    }
    p->config = NULL;

}
/** Given a timestamp and processing thread ID, generate an appropriate
 *  Avro output filename using the pre-configured output file template.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The packet processing thread state for this plugin.
 *  @param timestamp    The timestamp of the first interval covered by this
 *                      output file.
 *  @param threadid     The processing thread that is creating this file. Set
 *                      to -1 if the merge thread is calling this function.
 *  @return A malloc'd string containing the filename that should be used
 *          when creating an output file. Returns NULL if an error occurs.
 *
 *  @note It is the caller's responsibility to free the returned string when
 *        they are finished with opening the file.
 */
char *corsaro_report_derive_output_name(corsaro_plugin_t *p,
        void *local, uint32_t timestamp, int threadid) {

    corsaro_report_config_t *conf;
    char *outname = NULL;

    conf = (corsaro_report_config_t *)(p->config);

    outname = corsaro_generate_avro_file_name(conf->basic.template, p->name,
            conf->basic.monitorid, timestamp, threadid);
    if (outname == NULL) {
        corsaro_log(p->logger,
                "failed to generate suitable filename for report output");
        return NULL;
    }

    return outname;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
