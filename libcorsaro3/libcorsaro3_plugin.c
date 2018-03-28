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

#include "config.h"

#include <assert.h>
#include "libcorsaro3_plugin.h"
#include "libcorsaro3_mergeapi.h"

#ifdef WITH_PLUGIN_SIXT
#include "corsaro_flowtuple.h"
#endif

#define PLUGIN_INIT_ADD(plugin)                                                \
{                                                                              \
    tail = add_plugin(logger, tail, plugin##_alloc(), 1);                      \
    if (all == NULL) {                                                         \
        all = tail;                                                            \
    }                                                                          \
    plugin_cnt++;                                                              \
}


static int corsaro_plugin_verify(corsaro_logger_t *logger,
        corsaro_plugin_t *plugin)
{
    /* some sanity checking to make sure this plugin has been implemented
       with the features we need. #if 0 this for production */
    if (plugin == NULL) {
        corsaro_log(logger, "attempted to load a NULL plugin");
        return 0;
    }

    if (plugin->name == NULL) {
        corsaro_log(logger, "plugin has no name!");
        return 0;
    }

    if (plugin->id < 0 || plugin->id > CORSARO_PLUGIN_ID_MAX) {
        corsaro_log(logger, "plugin %s has invalid ID %d.", plugin->name,
                plugin->id);
        return 0;
    }

    if (plugin->magic <= 0x010101) {
        corsaro_log(logger, "plugin %s has an invalid magic number.",
                plugin->name);
        return 0;
    }

    /* Check all required methods are present */
    /* TODO add more methods here */

    if (plugin->parse_config == NULL) {
        corsaro_log(logger, "plugin %s has no parse_config() method.",
                plugin->name);
        return 0;
    }

    /* ->next is only set for references to plugins that are part of
     * a plugin list -- it should be NULL for the original plugin
     * definitions.
     */
    if (plugin->next != NULL) {
        corsaro_log(logger, "plugin %s is a copy, not an original.",
                plugin->name);
        return 0;
    }

    return 1;

}


static corsaro_plugin_t *add_plugin(corsaro_logger_t *logger,
        corsaro_plugin_t *plisttail,
        corsaro_plugin_t *p, uint8_t firstload) {

    corsaro_plugin_t *copy = NULL;

    if ((copy = malloc(sizeof(corsaro_plugin_t))) == NULL) {
        corsaro_log(logger, "unable to malloc memory for plugin");
        return NULL;
    }

    memcpy(copy, p, sizeof(corsaro_plugin_t));

    /* This used to be optional, but probably no harm in checking each time. */
    if (firstload) {
        if (corsaro_plugin_verify(logger, copy) == 0) {
            free(copy);
            return NULL;
        }
    }

    if (plisttail != NULL) {
        if (plisttail->next != NULL) {
            corsaro_log(logger, "tail of plugin list is not NULL??");
        }
        plisttail->next = copy;
    }

    return copy;
}

static inline void populate_interval(corsaro_interval_t *interval,
        uint32_t number, uint32_t time)
{
    interval->corsaro_magic = CORSARO_MAGIC;
    interval->magic = CORSARO_MAGIC_INTERVAL;
    interval->number = number;
    interval->time = time;
}

static inline void reset_packet_state(corsaro_packet_state_t *pstate) {
    pstate->flags = 0;
}


corsaro_plugin_t *corsaro_load_all_plugins(corsaro_logger_t *logger) {
    corsaro_plugin_t *all = NULL;
    corsaro_plugin_t *tail = NULL;
    int plugin_cnt = 0;

#ifdef ED_PLUGIN_INIT_ALL_ENABLED
    ED_PLUGIN_INIT_ALL_ENABLED
#endif

    /* For now, I'm just going to maintain the plugins as a list until I
     * encounter a genuine use case where we need to do lots of lookups.
     */

    return all;
}

void corsaro_cleanse_plugin_list(corsaro_plugin_t *plist) {

    corsaro_plugin_t *p = plist;

    while (plist != NULL) {
        p = plist;
        plist = p->next;
        p->destroy_self(p);
        free(p);
    }
}

corsaro_plugin_t *corsaro_find_plugin(corsaro_plugin_t *plist, char *name) {
    corsaro_plugin_t *p = plist;

    while (p != NULL) {
        if (strlen(name) == strlen(p->name) && strncasecmp(name, p->name,
                strlen(p->name)) == 0) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

corsaro_plugin_t *corsaro_enable_plugin(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, corsaro_plugin_t *parent) {

    corsaro_plugin_t *copy = NULL;

    copy = add_plugin(logger, plist, parent, 0);
    copy->enabled = 1;
    /* Save a reference to the global logger so we can log errors etc to it
     * if no specific logger is requested for this plugin.
     */
    copy->logger = logger;
    copy->local_logger = 0;
    corsaro_log(logger, "enabling %s plugin", copy->name);
    return copy;
}

void corsaro_disable_plugin(corsaro_plugin_t *p) {
    p->enabled = 0;
}

int corsaro_configure_plugin(corsaro_plugin_t *p, yaml_document_t *doc,
        yaml_node_t *options) {

    if (p->config) {
        free(p->config);
    }
    return p->parse_config(p, doc, options);
}

int corsaro_finish_plugin_config(corsaro_plugin_t *plist,
        corsaro_plugin_proc_options_t *stdopts) {

    corsaro_plugin_t *p = plist;

    while (p != NULL) {
        if (p->config != NULL) {
            p->finalise_config(p, stdopts);
        }
        p = p->next;
    }
    return 0;
}

/* XXX number of arguments is starting to get out of hand */
corsaro_plugin_set_t *corsaro_start_plugins(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, int count, int threadid) {
    int index = 0;

    corsaro_plugin_set_t *pset = (corsaro_plugin_set_t *)malloc(
            sizeof(corsaro_plugin_set_t));

    pset->active_plugins = plist;
    pset->plugincount = 0;
    pset->plugin_state = (void **) malloc(sizeof(void *) * count);
    pset->api = CORSARO_TRACE_API;
    pset->globlogger = logger;

    memset(pset->plugin_state, 0, sizeof(void *) * count);

    while (plist != NULL) {
        assert(index < count);

        pset->plugin_state[index] = plist->init_processing(plist,
                threadid);
        index += 1;
        plist = plist->next;
        pset->plugincount ++;
    }

    return pset;
}

corsaro_plugin_set_t *corsaro_start_reader_plugins(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, int count, int maxsources) {

    int index = 0;

    corsaro_plugin_set_t *pset = (corsaro_plugin_set_t *)malloc(
            sizeof(corsaro_plugin_set_t));

    pset->active_plugins = plist;
    pset->plugincount = 0;
    pset->plugin_state = (void **) malloc(sizeof(void *) * count);
    pset->api = CORSARO_READER_API;
    pset->globlogger = logger;

    memset(pset->plugin_state, 0, sizeof(void *) * count);

    while (plist != NULL) {
        assert(index < count);

        pset->plugin_state[index] = plist->init_reading(plist, maxsources);

        index += 1;
        plist = plist->next;
        pset->plugincount ++;
    }

    return pset;

}

int corsaro_stop_plugins(corsaro_plugin_set_t *pset) {

    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;

    while (p != NULL) {
        if (pset->api == CORSARO_TRACE_API) {
            p->halt_processing(p, pset->plugin_state[index]);
        }
        if (pset->api == CORSARO_READER_API) {
            p->halt_reading(p, pset->plugin_state[index]);
        }

        pset->plugin_state[index] = NULL;
        p = p->next;
        index ++;
    }
    free(pset->plugin_state);
    free(pset);
    return 0;
}

int corsaro_push_packet_plugins(corsaro_plugin_set_t *pset,
        libtrace_packet_t *packet) {
    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;
    corsaro_packet_state_t pstate;

    if (pset->api != CORSARO_TRACE_API) {
        return -1;
    }

    reset_packet_state(&pstate);

    while (p != NULL) {
        p->process_packet(p, pset->plugin_state[index], packet, &pstate);
        p = p->next;
        index ++;
    }
    return 0;
}

int corsaro_push_end_plugins(corsaro_plugin_set_t *pset, uint32_t intervalid,
        uint32_t ts) {
    corsaro_interval_t end;
    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;

    populate_interval(&end, intervalid, ts);
    end.isstart = 0;

    if (pset->api != CORSARO_TRACE_API) {
        return -1;
    }

    while (p != NULL) {
        p->end_interval(p, pset->plugin_state[index], &end);
        p = p->next;
        index ++;
    }
    return 0;
}

int corsaro_push_start_plugins(corsaro_plugin_set_t *pset, uint32_t intervalid,
        uint32_t ts) {
    corsaro_interval_t start;
    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;

    populate_interval(&start, intervalid, ts);
    start.isstart = 1;

    if (pset->api != CORSARO_TRACE_API) {
        return -1;
    }

    while (p != NULL) {
        p->start_interval(p, pset->plugin_state[index], &start);
        p = p->next;
        index ++;
    }
    return 0;
}

int corsaro_push_rotate_file_plugins(corsaro_plugin_set_t *pset,
        uint32_t intervalid, uint32_t ts) {

    corsaro_interval_t rotstart;
    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;

    populate_interval(&rotstart, intervalid, ts);
    rotstart.isstart = 0;

    if (pset->api != CORSARO_TRACE_API) {
        return -1;
    }

    while (p != NULL) {
        p->rotate_output(p, pset->plugin_state[index], &rotstart);
        p = p->next;
        index ++;
    }
    return 0;
}

/** "Distinct" merge is intended to be used when each result in the interim
 *  files can be considered complete, i.e. there is no possibility of there
 *  being results in the other interim files that should be merged or
 *  combined with the result being looked at right now.
 *
 *  An example would be flowtuple results -- since we should be hashing
 *  our packets based on flowtuple anyway, each flowtuple result should be
 *  confined to a single thread (and therefore a single interim file).
 *
 *  This means we can write each flowtuple result to the merged output as
 *  soon as we see it, as the result is already complete.
 */
static int perform_distinct_merge(corsaro_plugin_t *p, void *plocal,
        corsaro_merge_reader_t **readers, corsaro_plugin_result_t *results,
        int tcount, corsaro_merge_writer_t *writer) {

    int i, ret;
    corsaro_plugin_result_t *cand = NULL;
    int candind = -1;

    do {
        candind = -1;
        cand = NULL;

        for (i = 0; i < tcount; i++) {
            if (readers[i] == NULL) {
                /* no more results from this source */
                continue;
            }

            if (results[i].type == CORSARO_RESULT_TYPE_BLANK) {
                /* need a fresh result */
                ret = corsaro_read_next_merge_result(readers[i], p,
                        plocal, &(results[i]));
                if (ret == -1) {
                    /* some error occurred? */
                    /* close the reader I guess... */
                    corsaro_close_merge_reader(readers[i], p, plocal);
                    p->release_result(p, plocal, &(results[i]));
                    readers[i] = NULL;
                    results[i].type = CORSARO_RESULT_TYPE_EOF;
                    continue;
                }
            }

            if (results[i].type == CORSARO_RESULT_TYPE_EOF) {
                /* Reached EOF for this source. */
                corsaro_close_merge_reader(readers[i], p, plocal);
                p->release_result(p, plocal, &(results[i]));
                readers[i] = NULL;
                results[i].type = CORSARO_RESULT_TYPE_EOF;
                continue;
            }

            if (cand == NULL) {
                cand = &(results[i]);
                candind = i;
                continue;
            }

            if (p->compare_results(p, plocal, cand, &(results[i])) > 0) {
                cand = &(results[i]);
                candind = i;
            }
        }

        if (candind == -1) {
            /* no more results, close file and move onto next plugin */
            break;
        }

        if (corsaro_write_next_merge_result(writer, p, plocal,
                &(results[candind])) < 0) {
            /* Something went wrong with the writing */
            corsaro_log(p->logger,
                    "error while writing %s result to merged result file.",
                    p->name);
            /* This output file is probably screwed so just bail on this
             * one and hope someone is checking the logs.
             */
            return -1;
        }

        /* Release the result we just wrote */
        p->release_result(p, plocal, &(results[candind]));
        results[candind].type = CORSARO_RESULT_TYPE_BLANK;
    } while (candind != -1);

    return 0;
}

/** Overlapping merge is intended to be used when there is some possibility
 *  that the results may have been spread across multiple interim files.
 *  In this case, the corresponding result fragments will need to be collated
 *  and combined before they can be written to the merged output file.
 *
 *  An example would be the per-country statistics for the geolocation report
 *  plugin -- packets are hashed by flow tuple so all packets for any given
 *  country cannot be guaranteed to have appeared on the same thread. To
 *  produce a correct count of packets seen for NZ, we will need to read
 *  all results and sum the packet counts for NZ reported in each interim
 *  file.
 */
static int perform_overlap_merge(corsaro_plugin_t *p, void *plocal,
        corsaro_merge_reader_t **readers, corsaro_plugin_result_t *results,
        int tcount, corsaro_merge_writer_t *writer) {

    return 0;
}

int corsaro_merge_plugin_outputs(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, corsaro_fin_interval_t *fin, int count)
{

    corsaro_plugin_set_t *pset;
    corsaro_plugin_t *p = NULL;
    int index = 0;
    corsaro_merge_reader_t **readers = NULL;
    corsaro_merge_writer_t *output = NULL;
    corsaro_plugin_result_t *results = NULL;
    int i;
    int errors = 0;
    char **sourcefilenames = NULL;
    char *outname = NULL;

    corsaro_log(logger, "commencing merge for all plugins %u:%u.",
            fin->interval_id, fin->timestamp);

    pset = corsaro_start_reader_plugins(logger, plist, count,
            fin->threads_ended);
    if (pset == NULL) {
        corsaro_log(logger,
                "error while starting plugins for merging output.");
        return 1;
    }

    readers = (corsaro_merge_reader_t **)calloc(1, fin->threads_ended *
            sizeof(corsaro_merge_reader_t *));
    results = (corsaro_plugin_result_t *)calloc(1, fin->threads_ended *
            sizeof(corsaro_plugin_result_t));
    sourcefilenames = (char **)calloc(1, sizeof(char *) * fin->threads_ended);

    p = pset->active_plugins;
    while (p != NULL) {
        int nextresind;

        corsaro_log(logger, "commencing merge for plugin %s", p->name);
        memset(results, 0, fin->threads_ended * sizeof(corsaro_plugin_result_t));
        outname = p->derive_output_name(p, pset->plugin_state[index],
                fin->timestamp, -1);
        if (outname == NULL) {
            corsaro_log(logger,
                    "unable to derive suitable merged %s output file name.",
                    p->name);
            errors ++;
            p = p->next;
            continue;
        }

        output = corsaro_create_merge_writer(p, pset->plugin_state[index],
                outname, p->finalfmt);
        if (output == NULL) {
            errors ++;
            p = p->next;
            index ++;
        }

        for (i = 0; i < fin->threads_ended; i++) {
            sourcefilenames[i] = p->derive_output_name(p,
                    pset->plugin_state[index], fin->timestamp, i);
            readers[i] = corsaro_create_merge_reader(p,
                    pset->plugin_state[index], sourcefilenames[i],
                    p->interimfmt);

            if (readers[i] == NULL) {
                corsaro_log(logger,
                        "error while opening %s file as input for merging.",
                        p->name);
                errors ++;
            }
        }

        if (p->mergestyle == CORSARO_MERGE_TYPE_OVERLAPPING) {
            if (perform_overlap_merge(p, pset->plugin_state[index], readers,
                    results, fin->threads_ended, output) == -1) {
                errors ++;
            }
        } else if (p->mergestyle == CORSARO_MERGE_TYPE_DISTINCT) {
            if (perform_distinct_merge(p, pset->plugin_state[index], readers,
                    results, fin->threads_ended, output) == -1) {
                errors ++;
            }
        }

        for (i = 0; i < fin->threads_ended; i++) {
            if (readers[i] != NULL) {
                corsaro_close_merge_reader(readers[i], p,
                        pset->plugin_state[index]);
                readers[i] = NULL;
            }
            remove(sourcefilenames[i]);
            free(sourcefilenames[i]);
        }
        corsaro_close_merge_writer(output, p, pset->plugin_state[index]);

        p = p->next;
        index ++;
    }

    free(readers);
    free(results);
    free(sourcefilenames);
    corsaro_stop_plugins(pset);
    corsaro_log(logger, "completed merge for all plugins %u:%u.", fin->interval_id, fin->timestamp);
    return errors;

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :