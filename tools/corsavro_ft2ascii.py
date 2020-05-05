#!/usr/bin/env python3

"""
Simple tool to dump the contents of a corsaro flowtuple Avro file (i.e.
one generated using corsaro3) to standard output.

The format of the text output matches that of the old cors2ascii tool
when run against a corsaro2 flowtuple file.

The main purpose of this tool is to provide some backwards compatibility
for people who were using cors2ascii with flowtuple data, and wish to
continue to do so with the new avro files without having to re-develop any
code / scripts.

Usage: python3 corsavro_ft2ascii.py <flowtuple avro file>

<flowtuple avro file> can be a swift URI.
"""

from fastavro import reader
import sys, ipaddress

last_time = 0
interval_count = 0
flow_count = 0
flows_saved = {}

def dump_ft_record(record):
    global last_time, interval_count, flow_count, flows_saved

    if "time" not in record:
        return -1

    if record["time"] > last_time:

        if last_time != 0:
            # Try to replicate the old category headers as best we can,
            # but we're not going to bother trying to put flows in the
            # "right" category -- just stick them all in 'other' for now.
            print("START flowtuple_backscatter 0")
            print("END flowtuple_backscatter")
            print("START flowtuple_icmpreq 0")
            print("END flowtuple_icmpreq")
            print("START flowtuple_other %u" % (flow_count))
            for f in flows_saved:
                print(f)
            print("END flowtuple_other")
            print("# CORSARO_INTERVAL_END %u %u" % \
                    (interval_count - 1, last_time))

            # Dump some progress to stderr so users have some idea of where
            # we're up to (especially as we can be pretty slow)
            print("completed %u intervals" % (interval_count), file=sys.stderr)

        print("# CORSARO_INTERVAL_START %u %u" % \
                (interval_count, record["time"]))
        interval_count += 1
        last_time = record["time"]
        flow_count = 0;
        flows_saved = []

    # Unfortunately, we can't just dump each flow as soon as we read it,
    # because we need to have a correct flow count to put in our category
    # header line. Instead, we have to save each flow in memory and dump them
    # all once we are sure we've seen all of the flows for the current
    # interval -- XXX this may cause memory issues if we have a *lot* of
    # flows in a single interval?
    flows_saved.append("%s|%s|%u|%u|%u|%u|0x%02x|%u,%u" \
            % (ipaddress.ip_address(record["src_ip"]), \
               ipaddress.ip_address(record["dst_ip"]), \
               record["src_port"], record["dst_port"], \
               record["protocol"], record["ttl"], \
               record["tcp_flags"], record["ip_len"],
               record["packet_cnt"]))
    flow_count += 1

if len(sys.argv) < 2:
    print("Usage: python3 corsavro_ft2ascii.py <flowtuple_avro_file>", \
            file=sys.stderr)
    exit(1)

with open(sys.argv[1], 'rb') as fo:
    avro_reader = reader(fo)
    for record in avro_reader:
        dump_ft_record(record)


# vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
