#!/usr/bin/env python

import os
import sys
import getopt
import pandas as pd
import plotly.graph_objs as go

def main(argv):
    argc = len(argv)
    if argc != 2:
        print >> sys.stderr, "Usage: %s <trace csv>" % argv[0]
        return -1

    df = pd.read_csv(argv[1])
    tids = sorted(set(df['tid']))
    functions = sorted(set(df['function']), reverse=True)

    fig = go.Figure(
        data=[
            go.Bar(
                name=fn,
                x=tids, 
                y = [
                    sum(df[(df['function'] == fn) & (df['tid'] == tid)]['latency_us_self'])
                    for tid in tids
                ]
            )
            for fn in functions
        ]
    )
    fig.update_layout(
        title = "Sum of Per-Function Self Latencies",
        xaxis_title = "Thread Idx",
        yaxis_title = "Latency (us)",
        barmode='stack', 
        yaxis={'categoryorder' : 'total ascending'}
    )
    fig.show()

if __name__ == "__main__":
    argv = sys.argv
    sys.exit(main(argv))
