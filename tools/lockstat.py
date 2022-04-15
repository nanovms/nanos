from __future__ import print_function
import copy
import sys

sortkeys = {'acq', 'cont', 'spins', 'spins_avg', 'spins_min', 'spins_max', 'hold_time', 'hold_avg', 'hold_min', 'hold_max', 'sleeps'}
num_stat_fields = 12

def fields_to_dict(f):
    d = dict()
    d['type'] = f[1]
    d['acq'] = int(f[2])
    d['cont'] = int(f[3])
    d['tries'] = int(f[4])
    d['spins'] = int(f[5])
    d['spins_avg'] = d['spins'] / d['cont'] if d['cont'] != 0 else 0
    d['spins_min'] = int(f[6])
    d['spins_max'] = int(f[7])
    d['hold_time'] = int(f[8])
    d['hold_avg'] = d['hold_time'] / d['acq']
    d['hold_min'] = int(f[9])
    d['hold_max'] = int(f[10])
    d['sleeps'] = int(f[11])
    return d

def process_file(inf):
    locks = dict()
    ln = inf.readline()
    while ln:
        f = ln.split()
        if len(f) < num_stat_fields:
            break
        d = fields_to_dict(f)
        if f[0] in locks:
            locks[f[0]]['acq'] += d['acq']
            locks[f[0]]['cont'] += d['cont']
            locks[f[0]]['tries'] += d['tries']
            locks[f[0]]['spins'] += d['spins']
            if d['spins_min'] > 0 and d['spins_min'] < locks[f[0]]['spins_min']:
                locks[f[0]]['spins_min'] = d['spins_min']
            if d['spins_max'] > locks[f[0]]['spins_max']:
                locks[f[0]]['spins_max'] = d['spins_max']
            locks[f[0]]['hold_time'] += d['hold_time']
            if d['hold_min'] < locks[f[0]]['hold_min']:
                locks[f[0]]['hold_min'] = d['hold_min']
            if d['hold_max'] > locks[f[0]]['hold_max']:
                locks[f[0]]['hold_max'] = d['hold_max']
            locks[f[0]]['sleeps'] += d['sleeps']
            locks[f[0]]['call_traces'].append((d, f[num_stat_fields:]))
        else:
            locks[f[0]] = d.copy()
            locks[f[0]]['call_traces'] = [(d, f[num_stat_fields:])]

        ln = inf.readline()

    for v in locks.items():
        v[1]['spins_avg'] = v[1]['spins']/v[1]['cont'] if v[1]['cont'] != 0 else 0
        v[1]['hold_avg'] = v[1]['hold_time']/v[1]['acq']

    return locks

def print_locks(locks, sortcol):
    print('%-18s %5s %7s %7s %12s %7s %7s %10s %12s %7s %7s %10s %10s' %
            ('Lock Address', 'Type', 'Acquire', 'Contend',
                'Tot Spins', 'Min', 'Avg', 'Max', 'Hld Cycles', 'Min',
                'Avg', 'Max', 'Sleeps'))
    for k in sorted(locks.items(), key=lambda v: v[1][sortcol], reverse=True):
        print('%s %5s %7d %7d %12d %7d %7d %10d %12d %7d %7d %10d %10d' %
               (k[0], k[1]['type'], k[1]['acq'], k[1]['cont'],
                   k[1]['spins'], k[1]['spins_min'],
                   k[1]['spins_avg'], k[1]['spins_max'], k[1]['hold_time'],
                   k[1]['hold_min'], k[1]['hold_avg'], k[1]['hold_max'],
                   k[1]['sleeps']))
        traces = k[1]['call_traces']
        for t in sorted(traces, key=lambda tv: tv[0][sortcol], reverse=True):
            print('  %2d%% ' % (t[0][sortcol]*100 / k[1][sortcol]), end='')
            #print('(%d/%d)' % (t[0][sortcol], k[1][sortcol]), end='')
            for i in range(0, len(t[1]), 2):
                print('%s' % (t[1][i+1]), end='')
            print('')
        print('')

def main():
    args = sys.argv[1:]
    inf = sys.stdin
    if len(args) != 0:
        inf = open(args[0])
    locks = process_file(inf)
    sortcol = 'cont'
    if len(args) > 1:
        if args[1] in sortkeys:
            sortcol = args[1]
        else:
            print('bad sort key!')

    print_locks(locks, sortcol)
    inf.close()

if __name__ == '__main__':
    main()

