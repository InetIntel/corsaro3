/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * Shane Alcock, WAND, University of Waikato
 *
 * corsaro-info@caida.org
 *
 * Copyright (C) 2012 The Regents of the University of California.
 *
 * This file is part of corsaro.
 *
 * corsaro is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * corsaro is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with corsaro.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdlib.h>
#include <string.h>

#include <libipmeta.h>
#include "libcorsaro3_tagging.h"
#include "libcorsaro3_log.h"

corsaro_packet_tagger_t *corsaro_create_packet_tagger(corsaro_logger_t *logger,
        ipmeta_t *ipmeta) {

    corsaro_packet_tagger_t *tagger = NULL;

    tagger = (corsaro_packet_tagger_t *)calloc(1,
            sizeof(corsaro_packet_tagger_t));
    if (!tagger) {
        return NULL;
    }

    /* TODO
     * In theory, we could allocate and init ipmeta ourselves rather than
     * making the caller do it for us -- corsaro_init_ipmeta_provider()
     * would need to take a tagger instead of an ipmeta as a parameter,
     * but that's probably not a big deal.
     */
    tagger->logger = logger;
    tagger->ipmeta = ipmeta;
    tagger->providers = libtrace_list_init(sizeof(ipmeta_provider_t *));
    tagger->tagfreelist = libtrace_list_init(sizeof(corsaro_packet_tags_t *));
    tagger->providermask = 0;

    return tagger;
}

#define MAXSPACE (4096)
#define FRAGSPACE (512)

#define COPY_STRING(space, maxspace, used, toadd, errname) \
    if (used + strlen(toadd) >= maxspace) { \
        corsaro_log(logger, "%s option string is too long?", errname); \
        return NULL; \
    } \
    memcpy(nxt, toadd, strlen(toadd)); \
    nxt += strlen(toadd); \
    used += strlen(toadd); \
    space[used] = '\0';


/* One day, someone might update libipmeta to not take horrible getopt
 * style configuration and then these nasty functions could go away. */
static inline char *create_maxmind_option_string(corsaro_logger_t *logger,
        maxmind_opts_t *maxopts) {

    char space[MAXSPACE];
    char fragment[FRAGSPACE];
    char *nxt = space;
    int used = 0;
    int towrite = 0;

    if (maxopts->directory) {
        snprintf(fragment, FRAGSPACE, "-d %s ", maxopts->directory);
        COPY_STRING(space, MAXSPACE, used, fragment, "maxmind");
    }

    if (maxopts->ds_name) {
        snprintf(fragment, FRAGSPACE, "-D %s ", maxopts->ds_name);
        COPY_STRING(space, MAXSPACE, used, fragment, "maxmind");
    }

    if (maxopts->blocks_file) {
        snprintf(fragment, FRAGSPACE, "-b %s ", maxopts->blocks_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "maxmind");
    }

    if (maxopts->locations_file) {
        snprintf(fragment, FRAGSPACE, "-l %s ", maxopts->locations_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "maxmind");
    }

    if (used > 0) {
        return strdup(space);
    }
    return NULL;
}

static inline char *create_prefix2asn_option_string(corsaro_logger_t *logger,
        pfx2asn_opts_t *pfxopts) {

    char space[MAXSPACE];
    char fragment[FRAGSPACE];
    char *nxt = space;
    int used = 0;
    int towrite = 0;

    if (pfxopts->pfx2as_file) {
        snprintf(fragment, FRAGSPACE, "-f %s ", pfxopts->pfx2as_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "prefix2asn");
    }

    if (pfxopts->ds_name) {
        snprintf(fragment, FRAGSPACE, "-D %s ", pfxopts->ds_name);
        COPY_STRING(space, MAXSPACE, used, fragment, "prefix2asn");
    }

    if (used > 0) {
        return strdup(space);
    }
    return NULL;
}

static inline char *create_netacq_option_string(corsaro_logger_t *logger,
        netacq_opts_t *acqopts) {

    char space[MAXSPACE];
    char fragment[FRAGSPACE];
    char *nxt = space;
    int used = 0;
    int towrite = 0;
    libtrace_list_node_t *n;

    if (acqopts->blocks_file) {
        snprintf(fragment, FRAGSPACE, "-b %s ", acqopts->blocks_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->ds_name) {
        snprintf(fragment, FRAGSPACE, "-D %s ", acqopts->ds_name);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->country_file) {
        snprintf(fragment, FRAGSPACE, "-c %s ", acqopts->country_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->locations_file) {
        snprintf(fragment, FRAGSPACE, "-l %s ", acqopts->locations_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->region_file) {
        snprintf(fragment, FRAGSPACE, "-r %s ", acqopts->region_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->polygon_map_file) {
        snprintf(fragment, FRAGSPACE, "-p %s ", acqopts->polygon_map_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->polygon_table_files) {
        n = acqopts->polygon_table_files->head;
        while (n) {
            char *fname = *((char **)(n->data));
            snprintf(fragment, FRAGSPACE, "-t %s ", fname);
            COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
            n = n->next;
        }
    }

    if (used > 0) {
        return strdup(space);
    }
    return NULL;
}

static char *create_ipmeta_options(corsaro_logger_t *logger,
        ipmeta_provider_id_t provid, void *options) {

    char *opts = NULL;

    switch(provid) {
        case IPMETA_PROVIDER_MAXMIND:
            opts = create_maxmind_option_string(logger,
                    (maxmind_opts_t *)options);
            break;
        case IPMETA_PROVIDER_NETACQ_EDGE:
            opts = create_netacq_option_string(logger,
                    (netacq_opts_t *)options);
            break;
        case IPMETA_PROVIDER_PFX2AS:
            opts = create_prefix2asn_option_string(logger,
                    (pfx2asn_opts_t *)options);
            break;
    }

    return opts;

}

ipmeta_provider_t *corsaro_init_ipmeta_provider(ipmeta_t *ipmeta,
        ipmeta_provider_id_t provid, void *options, corsaro_logger_t *logger) {

    char *optstring = NULL;
    ipmeta_provider_t *prov;

    if (ipmeta == NULL) {
        corsaro_log(logger,
                "Cannot create IPMeta provider: IPMeta instance is NULL.");
        return NULL;
    }

    prov = ipmeta_get_provider_by_id(ipmeta, provid);
    if (prov == NULL) {
        corsaro_log(logger,
                "Cannot create IPMeta provider: %u is an invalid provider ID.",
                provid);
        return NULL;
    }

    optstring = create_ipmeta_options(logger, provid, options);
    if (!optstring) {
        corsaro_log(logger,
                "Cannot create IPMeta provider %u: error parsing options.",
                provid);
        return NULL;
    }

    if (ipmeta_enable_provider(ipmeta, prov, (const char *)optstring,
            IPMETA_PROVIDER_DEFAULT_NO) != 0) {
        corsaro_log(logger,
                "Cannot create IPMeta provider %u: libipmeta internal error.",
                provid);
        free(optstring);
        return NULL;
    }

    if (optstring) {
        free(optstring);
    }
    return prov;
}

int corsaro_enable_ipmeta_provider(corsaro_packet_tagger_t *tagger,
        ipmeta_provider_t *prov) {


    if (tagger == NULL) {
        return -1;
    }

    if (tagger->ipmeta == NULL) {
        corsaro_log(tagger->logger,
                "Cannot enable IPMeta provider: IPMeta instance is NULL.");
        return -1;
    }

    /* Provider is not initialised, so just skip it */
    if (prov == NULL) {
        return 0;
    }

    libtrace_list_push_back(tagger->providers, &prov);
    tagger->providermask |= (1 << (ipmeta_get_provider_id(prov) - 1));

    return 0;
}

int corsaro_replace_ipmeta_provider(corsaro_packet_tagger_t *tagger,
        ipmeta_provider_t *prov) {

    libtrace_list_node_t *n;
    ipmeta_provider_t **current = NULL;

    if (tagger == NULL) {
        return -1;
    }

    if (tagger->ipmeta == NULL) {
        corsaro_log(tagger->logger,
                "Cannot replace IPMeta provider: IPMeta instance is NULL.");
        return -1;
    }

    /* Provider is not initialised, so just skip it */
    if (prov == NULL) {
        return 0;
    }

    /* Try to find an existing instance of this provider in our provider
     * list. */
    n = tagger->providers->head;
    while (n) {
        current = (ipmeta_provider_t **)(n->data);

        n = n->next;
        if (ipmeta_get_provider_id(*current) == ipmeta_get_provider_id(prov)) {
            break;
        }
        current = NULL;
    }

    if (current == NULL) {
        /* This provider type didn't exist before? In that case, just
         * add it to the list. */
        libtrace_list_push_back(tagger->providers, &prov);
        tagger->providermask |= (1 << (ipmeta_get_provider_id(prov) - 1));
    } else {
        /* Replace the existing one with our new provider.
         *
         * XXX We DO NOT free the old provider instance here, hopefully the
         * caller still has a reference to it...
         */
        n->data = &prov;
    }
    return 0;
}

void corsaro_destroy_packet_tagger(corsaro_packet_tagger_t *tagger) {

    if (tagger) {
        if (tagger->providers) {
            libtrace_list_deinit(tagger->providers);
        }
        free(tagger);
    }
}

static int update_maxmind_tags(corsaro_logger_t *logger,
        ipmeta_record_t *rec, corsaro_packet_tags_t *tags) {

    if (rec == NULL) {
        return 0;
    }

    tags->maxmind_continent = *((uint16_t *)(rec->continent_code));
    tags->maxmind_country = *((uint16_t *)(rec->country_code));

    tags->providers_used |= (1 << IPMETA_PROVIDER_MAXMIND);

    return 0;
}

static int update_netacq_tags(corsaro_logger_t *logger,
        ipmeta_record_t *rec, corsaro_packet_tags_t *tags) {

    if (rec == NULL) {
        return 0;
    }

    tags->netacq_continent = *((uint16_t *)(rec->continent_code));
    tags->netacq_country = *((uint16_t *)(rec->country_code));

    /* TODO regions, polygons etc */

    tags->providers_used |= (1 << IPMETA_PROVIDER_NETACQ_EDGE);

    return 0;
}

static int update_pfx2as_tags(corsaro_logger_t *logger,
        ipmeta_record_t *rec, corsaro_packet_tags_t *tags) {

    if (rec == NULL) {
        return 0;
    }

    /* Original corsaro tagging ignored all "group" ASNs so I'm going
     * to do the same for now.
     */
    if (rec->asn_cnt != 1) {
        return 0;
    }

    tags->prefixasn = rec->asn[0];
    tags->providers_used |= (1 << IPMETA_PROVIDER_PFX2AS);
    return 0;
}

static void update_basic_tags(corsaro_logger_t *logger,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {

    void *transport;
    uint8_t proto;
    libtrace_icmp_t *icmp;
    uint32_t rem;

    /* Basic tags refer to those that do not require any libipmeta providers
     * to derive, e.g. port numbers, transport protocols etc.
     */

    tags->protocol = 0;
    tags->src_port = 0;
    tags->dest_port = 0;

    transport = trace_get_transport(packet, &proto, &rem);

    if (transport == NULL) {
        /* transport header is missing or this is an non-initial IP fragment */
        return;
    }

    tags->protocol = proto;
    if (proto == TRACE_IPPROTO_ICMP && rem >= 2) {
        /* ICMP doesn't have ports, but we are interested in the type and
         * code, so why not reuse the space in the tag structure :) */
        icmp = (libtrace_icmp_t *)transport;
        tags->src_port = icmp->type;
        tags->dest_port = icmp->code;
    } else if ((proto == TRACE_IPPROTO_TCP || proto == TRACE_IPPROTO_UDP) &&
            rem >= 4) {
        tags->src_port = ntohs(*((uint16_t *)transport));
        tags->dest_port = ntohs(*(((uint16_t *)transport) + 1));
    }
    tags->providers_used |= 1;
}

int corsaro_tag_packet(corsaro_packet_tagger_t *tagger,
        corsaro_packet_tags_t *tags, libtrace_packet_t *packet) {

    struct sockaddr_storage saddr;
    struct sockaddr_in *sin;
    libtrace_list_node_t *n;
    ipmeta_record_set_t *records;
    ipmeta_record_t *rec;
    tags->providers_used = 0;
    uint32_t numips = 0;

    if (packet == NULL) {
        return 0;
    }

    update_basic_tags(tagger->logger, packet, tags);
    if (tagger->providers == NULL) {
        return 0;
    }

    /* We only care about the source address on the telescope.
     *
     * If we want to tag bidirectional traffic in the future then we will
     * have to expand our tag structure and run the providers against the
     * dest address too.
     */
    if (trace_get_source_address(packet, (struct sockaddr *)(&saddr)) == NULL)
    {
        return 0;
    }

    /* Skip IPv6 traffic for now, libipmeta probably won't like it anyway */
    if (saddr.ss_family != AF_INET) {
        return 0;
    }

    sin = (struct sockaddr_in *)(&saddr);

    records = ipmeta_record_set_init();
    if (ipmeta_lookup_single(tagger->ipmeta, sin->sin_addr.s_addr,
            tagger->providermask, records) < 0) {
        corsaro_log(tagger->logger, "error while performing ipmeta lookup");
        return -1;
    }

    while ((rec = ipmeta_record_set_next(records, &numips)) != NULL) {
        switch(rec->source) {
            case IPMETA_PROVIDER_MAXMIND:
                if (update_maxmind_tags(tagger->logger, rec, tags) != 0) {
                    return -1;
                }
                break;
            case IPMETA_PROVIDER_NETACQ_EDGE:
                if (update_netacq_tags(tagger->logger, rec, tags) != 0) {
                    return -1;
                }
                break;
            case IPMETA_PROVIDER_PFX2AS:
                if (update_pfx2as_tags(tagger->logger, rec, tags) != 0) {
                    return -1;
                }
                break;
            /* TODO other provider methods */
            default:
                printf("???: %u\n", rec->source);
        }
    }

    return 0;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
