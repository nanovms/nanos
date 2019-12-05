#!/usr/bin/env python

import os
import sys
import re
import csv
import pandas as pd

# dictionary of thread stacks
thread_stacks = {}

# function latencies
function_times = []

def update_parent(child_time, tid):
    if len(thread_stacks[tid]) == 0:
        return

    thread_stacks[tid][-1]["child_duration"] += child_time

def parse_entry(match, tid):
    function = match.group(1)
    thread_stacks[tid].append({
        "function" : function,
        "child_duration" : 0
    })
    return tid

def parse_return(match, tid):
    time = float(match.group(1))

    # pop the stack
    try:
        dat = thread_stacks[tid][-1]
    except IndexError as e:
        print >> sys.stderr, "No entry for return? Is this a complete trace file?"
        return tid

    function = dat["function"]
    child_time = dat["child_duration"]
    del thread_stacks[tid][-1]

    update_parent(time, tid)

    function_times.append({
        "tid" : tid,
        "latency_us" : time,
        "latency_us_self" : time - child_time,
        "function" : function
    })

    return tid

def parse_leaf(match, tid):
    time = float(match.group(1))
    function = match.group(2)

    update_parent(time, tid)

    function_times.append({
        "tid" : tid,
        "latency_us" : time,
        "latency_us_self" : time,
        "function" : function
    })

    return tid

def parse_switch(match, tid):
    tid_out = int(match.group(1))
    tid_in = int(match.group(2))
    assert tid_out == tid

    if tid_in not in thread_stacks:
        thread_stacks[tid_in] = []
    return tid_in

def parse_null(match, tid):
    return tid

class Parser(object):
    def __init__(self, regex, parse):
        self.regex = regex
        self.parse = parse

    def match(self, line):
        return re.match(self.regex, line)

    def parse(self, match, tid):
        return self.parse(match, tid)

def parse_trace(trace):
    preamble = r'^ 0\) [@*#!+ ] '
    time = r'([0-9]+.?[0-9]*) us'
    no_time = r'[ ]*'
    bar = r'[ ]+\|[ ]+'

    function = r'([a-zA-Z_0-9.]+)\(\)'
    entry = function + r' \{'
    leaf = function + r';'
    ret = r'\}'
    to_end = r'.*$'

    pat_entry = re.compile(preamble + no_time + bar + entry + to_end)
    pat_leaf = re.compile(preamble + time + bar + leaf + to_end)
    pat_return = re.compile(preamble + time + bar + ret + to_end)
    pat_switch = re.compile(r'------------------------------------------')
    pat_thread_switch = re.compile(r' 0\) [a-zA-Z0-9_]*-([0-9]+)  => [a-zA-Z0-9_]*-([0-9]+)[ ]*$')

    parsers = [
        Parser(pat_entry, parse_entry),
        Parser(pat_leaf, parse_leaf),
        Parser(pat_return, parse_return),
        Parser(pat_switch, parse_null),
        Parser(pat_thread_switch, parse_switch)
    ]

    current = 0
    thread_stacks[current] = []

    with open(trace, 'r') as f:
        for line in f.readlines():
            for p in parsers:
                m = p.match(line)
                if m:
                    current = p.parse(m, current)
                    break
            else:
                print "Unmatched line: %s" % line

    global function_times
    csv_columns = ['function', 'tid', 'latency_us', 'latency_us_self']
    with open('trace.csv', 'w') as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()
        for d in function_times:
            writer.writerow(d)

def main(argv):
    argc = len(argv)

    if argc != 2:
        print >> sys.stderr, "Usage: %s <function_graph trace file>" % argv[0]
        return -1

    return parse_trace(argv[1])

if __name__ == '__main__':
    sys.exit(main(sys.argv))

