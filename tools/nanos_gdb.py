import gdb

# these definitions and tagof must be in sync with C source
class Tag:
    unknown = 0
    string = 1
    symbol = 2
    table_tuple = 3
    function_tuple = 4

def tagof(p):
    return ((p.cast(typ('u64')) >> 38) & 7)

def typ(s):
    return gdb.lookup_type(s)

def get_buffer_string(val):
    str = val['contents'].cast(typ('char').pointer()) + val['start']
    return repr(str.string(length=(val['end']-val['start'])))[1:-1]

def print_table(t):
    i = 0
    while i < t['buckets']:
        j = t['entries'][i]
        while j != 0:
            k = j['c']
            v = j['v']
            kstr = get_buffer_string(k.cast(typ('symbol'))['s'])
            if tagof(v) == Tag.table_tuple:
                vstr = "(table)0x%16x (count %d)" %(v, v.cast(typ('table'))['count'])
            elif tagof(v) == Tag.function_tuple:
                vstr = "(tuple)0x%16x" %(v)
            elif tagof(v) == Tag.symbol:
                vstr = "(symbol) ", get_buffer_string(v.cast(typ('symbol'))['s'])
            else:
                vstr = get_buffer_string(v.cast(typ('buffer')))
            print(kstr + ": " + vstr)
            j = j['next']
        i = i + 1

class BufferPrinter(gdb.Command):
    "Print a nanos buffer"

    def __init__(self):
        super(BufferPrinter, self).__init__ ("print_buffer", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        buf_val = gdb.parse_and_eval(arg)
        if (buf_val.type.name != 'buffer' and buf_val.type.name != 'string'):
            print('argument must be of type buffer (was %s)' % (buf_val.type))
            return
        print(get_buffer_string(buf_val))

class TablePrinter(gdb.Command):
    "Print a nanos table"

    def __init__(self):
        super(TablePrinter, self).__init__ ("print_table", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        buf_val = gdb.parse_and_eval(arg)
        if (buf_val.type.name != 'table'):
            print('argument must be of type table (was %s)' % (buf_val.type))
            return
        print_table(buf_val)

BufferPrinter()
TablePrinter()

