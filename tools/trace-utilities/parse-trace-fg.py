#!/usr/bin/env python

import os
import sys
import re
import csv

# dictionary of thread stacks
thread_stacks = {}

# stack time track
stack_times = {}

def parse_entry(match, tid):
    function = match.group(1)
    thread_stacks[tid].append({
        "function" : function,
    })
    return tid

def record_stack_time(stk, tm):
    if stk in stack_times:
        stack_times[stk] += tm
    else:
        stack_times[stk] = tm

def parse_return(match, tid):
    time = float(match.group(1))

    # pop the stack
    try:
        dat = thread_stacks[tid][-1]
    except IndexError as e:
        print >> sys.stderr, "No entry for return? Is this a complete trace file?"
        return tid

    function = dat["function"]
    stk = ""
    for f in thread_stacks[tid]:
        stk += f["function"]
        if f["function"] != function:
            stk += ";"
    del thread_stacks[tid][-1]
    record_stack_time(stk, time)

    return tid

def parse_leaf(match, tid):
    time = float(match.group(1))
    function = match.group(2)

    stk = ""
    for f in thread_stacks[tid]:
        stk += f["function"] + ";"
    stk += function
    record_stack_time(stk, time)

    return tid

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
    preamble = r'^ [0-9]\) [@*#!+ ] '
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

    parsers = [
        Parser(pat_entry, parse_entry),
        Parser(pat_leaf, parse_leaf),
        Parser(pat_return, parse_return),
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

    with open('tracefg.out', 'w') as f:
        for s in sorted(stack_times.iterkeys()):
            f.write('{0} {1:0f}\n'.format(s, stack_times[s]))

def main(argv):
    argc = len(argv)

    if argc != 2:
        print >> sys.stderr, "Usage: %s <function_graph trace file>" % argv[0]
        return -1

    return parse_trace(argv[1])

if __name__ == '__main__':
    sys.exit(main(sys.argv))

