#!/usr/bin/env python3
import os
import sys
import subprocess
import socket
from threading import Thread
import ast
import re
import struct
import tempfile
import time

ip4_addr = "127.0.0.1"
repo_directory = "."

TEST_TIMEOUT = 120.0

###############################################################################
NETCONS_LISTEN_PORT = 8888


def udp_reader(ctx):
    while True:
        try:
            s, _ = ctx['sock'].recvfrom(512)
            if 'data' in ctx:
                ctx['data'] = ctx['data'] + s
            else:
                ctx['data'] = s
        except:
            return


def netcons_pre(ctx):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip4_addr, NETCONS_LISTEN_PORT))
    ctx['sock'] = sock
    ctx['thread'] = Thread(target=udp_reader, args=(ctx, ))
    ctx['thread'].start()


def netcons_post(ctx):
    try:
        ctx['sock'].shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        ctx['sock'].close()
    except Exception:
        pass
    if 'data' not in ctx or len(ctx['data']) == 0:
        return (-1, 'no udp console messages received')


def coredump_post(ctx):
    with tempfile.TemporaryDirectory() as tmp:
        try:
            subprocess.run([
                repo_directory + '/output/tools/bin/dump', '-d', tmp,
                repo_directory + '/output/image/disk.raw'
            ],
                           capture_output=True,
                           check=True)
        except:
            return (-1, 'dump failed')
        coredump_path = tmp + '/coredumps/core'
        if not os.path.isfile(coredump_path):
            return (-1, 'coredump not generated')
        elif os.path.getsize(coredump_path) == 0:
            return (-1, 'empty coredump')


def notrace_post(ctx):
    if re.search('\[2\] arch_prctl', ctx['output'], re.M) != None:
        return (-1, 'syscall was not excluded')


def tracelist_post(ctx):
    if re.search('\[2\] arch_prctl', ctx['output'], re.M) == None:
        return (-1, 'syscall was not found')
    if re.search('\[2\] [^arch_prctl]', ctx['output'], re.M) != None:
        return (-1, 'other syscalls were not excluded')


def debugsyscalls_post(ctx):
    if ctx['output'].find('exit_group') == -1:
        return (-1, 'debugsyscalls does not appear to be activated')


def ltrace_post(ctx):
    if ctx['output'].find('[LTRACE]') == -1:
        return (-1, 'ltrace does not appear to be activated')


###############################################################################


def run_test(program, option):
    child = subprocess.Popen([
        'make', '-C' + repo_directory, 'TARGET=' + program,
        'EXTRA_MKFS_OPTS=-t \(%s\)' % (option), 'run-noaccel'
    ],
                             stdout=subprocess.PIPE,
                             encoding='utf-8')
    try:
        returncode = child.wait(timeout=TEST_TIMEOUT)
    except:
        raise TimeoutError
    out = child.stdout.read()
    return (returncode, out)


def test_basic_options():
    basic_programs = [{
        'name':
        'mmap',
        'option':
        'consoles:[+net]\ netconsole_ip:%s\ netconsole_port:%d' %
        (ip4_addr, NETCONS_LISTEN_PORT),
        'pre':
        netcons_pre,
        'post':
        netcons_post
    }, {
        'name': 'mmap',
        'option': 'missing_files:t'
    }, {
        'name': 'hws',
        'option': 'syscall_summary:t'
    }, {
        'name': 'sigoverflow',
        'option': 'coredumplimit:32M',
        'post': coredump_post
    }, {
        'name': 'hws',
        'option': 'debugsyscalls:t\ notrace:[arch_prctl]',
        'post': notrace_post
    }, {
        'name': 'hws',
        'option': 'debugsyscalls:t\ tracelist:[arch_prctl]',
        'post': tracelist_post
    }, {
        'name': 'hws',
        'option': 'trace:t\ debugsyscalls:t',
        'post': debugsyscalls_post
    }, {
        'name': 'hw',
        'option': 'ltrace:t',
        'post': ltrace_post
    }]

    for p in basic_programs:
        ctx = dict()
        if 'pre' in p:
            p['pre'](ctx)
        try:
            rc, out = run_test(p['name'], p['option'])
        except TimeoutError:
            print('FAILED: %s timed out' % (p['name']))
            raise RuntimeError
        if rc != 0:
            print('%s\nFAILED: "%s" failed with option "%s"' %
                  (out, p['name'], p['option']))
            raise RuntimeError
        ctx['output'] = out
        if 'post' in p:
            try:
                t = p['post'](ctx)
            except Exception as err:
                print(
                    'FAILED: "%s" with option "%s" post check exception: %s' %
                    (p['name'], p['option'], err))
                raise RuntimeError
            if t != None:
                rc, out = t
                if rc != 0:
                    print('FAILED: "%s" with option "%s" post check: %s' %
                          (p['name'], p['option'], out))
                    raise RuntimeError
        print('PASSED: "%s" with option "%s"' % (p['name'], p['option']))


def test_aslr():

    def run(option):
        exp = re.compile('^\{ \'.*$', re.M)
        try:
            rc, out = run_test('aslr', option)
        except TimeoutError:
            print('FAILED: aslr program timed out')
            raise TimeoutError
        if rc != 0:
            print('%s\nFAILED: aslr program failed to run' % (out))
            raise RuntimeError
        g = exp.search(out)
        try:
            d = ast.literal_eval(g.group(0))
        except:
            print("FAILED: error parsing rd aslr output")
            raise RuntimeError
        return d

    rd = run('')
    nd = run('')
    if rd['main'] == nd['main'] or rd['library'] == nd['library'] or rd[
            'heap'] == nd['heap'] or rd['stack'] == nd['stack']:
        print('FAILED: aslr locations did not change between runs: %s vs %s' %
              (rd, nd))
        raise RuntimeError
    rd = run('noaslr:t')
    nd = run('noaslr:t')
    if rd['main'] != nd['main'] or rd['library'] != nd['library'] or rd[
            'heap'] != nd['heap']:
        print('FAILED: noaslr locations changed between runs: %s vs %s' %
              (rd, nd))
        raise RuntimeError
    print('PASSED: aslr and noaslr')


###############################################################################
ACCEPT_PROBE_PORT = 9090
ACCEPT_PROBE_DEAD = 10


def accept_reset_peer(ctx):
    """Open connections to the guest and reset them while it is not accepting them yet, then open
    one more and leave it alone. close() with SO_LINGER at zero sends a RST, which the guest
    cannot produce for itself: that is why this half has to run out here."""
    deadline = time.time() + 60
    opened = 0
    while opened < ACCEPT_PROBE_DEAD and time.time() < deadline:
        try:
            s = socket.create_connection(('127.0.0.1', ACCEPT_PROBE_PORT), timeout=5)
        except OSError:
            time.sleep(0.2)     # the guest is still booting
            continue
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        s.close()
        opened += 1
    ctx['dead'] = opened
    if opened == ACCEPT_PROBE_DEAD:
        try:
            ctx['live'] = socket.create_connection(('127.0.0.1', ACCEPT_PROBE_PORT), timeout=5)
        except OSError:
            pass


def accept_reset_pre(ctx):
    ctx['thread'] = Thread(target=accept_reset_peer, args=(ctx, ))
    ctx['thread'].start()


def accept_reset_post(ctx):
    ctx['thread'].join(timeout=TEST_TIMEOUT)
    if 'live' in ctx:
        ctx['live'].close()
    if ctx.get('dead') != ACCEPT_PROBE_DEAD:
        return (-1, 'could not open %d connections to the guest' % (ACCEPT_PROBE_DEAD))
    m = re.search('PROBE ACCEPTED (\d+)', ctx['output'])
    if m == None:
        return (-1, 'the program did not report what it accepted')
    n = int(m.group(1))
    if n != 1:
        return (-1, 'accept() returned %d connections, expected the 1 that is still alive: '
                '%d that had been reset were handed out as well' % (n, n - 1))


def test_accept_reset():
    ctx = dict()
    accept_reset_pre(ctx)
    try:
        rc, out = run_test('accept_probe', '')
    except TimeoutError:
        print('FAILED: accept_probe timed out')
        raise RuntimeError
    if rc != 0:
        print('%s\nFAILED: accept_probe failed to run' % (out))
        raise RuntimeError
    ctx['output'] = out
    t = accept_reset_post(ctx)
    if t != None:
        print('FAILED: accept_probe: %s' % (t[1]))
        raise RuntimeError
    print('PASSED: connections reset before accept are not handed out')


def get_ip4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def main():
    global ip4_addr, repo_directory
    ip4_addr = get_ip4()
    repo_directory = os.path.dirname(os.path.realpath(sys.argv[0])) + "/.."
    try:
        test_basic_options()
        test_aslr()
        test_accept_reset()
    except:
        return -1
    return 0


if __name__ == '__main__':
    sys.exit(main())
