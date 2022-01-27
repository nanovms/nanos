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

def rbtree_traverse_inorder(n, f):
    if n == 0:
        return True
    if not rbtree_traverse_inorder(n['c'][0], f):
        return False
    f(n)
    return rbtree_traverse_inorder(n['c'][1], f)

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

class TreePrinter(gdb.Command):
    "Print a nanos rbtree"

    def __init__(self):
        super(TreePrinter, self).__init__ ("print_tree", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        offset = 0
        contype = None
        if len(argv) < 1:
            return
        tree = gdb.parse_and_eval(argv[0])
        if (tree.type.name != 'rbtree'):
            print('argument must be of type rbtree (was %s)' % (tree.type))
            return
        if len(argv) >= 2:
            contype = typ(argv[1]).strip_typedefs()
            if contype.code == gdb.TYPE_CODE_PTR:
                contype = contype.target()
            if contype.code != gdb.TYPE_CODE_STRUCT:
                print('container type is not a struct')
                return
            fieldname = None
            for f in contype.fields():
                if f.type.name == typ('rbnode').name:
                    fieldname = f.name
                    break
            if fieldname == None:
                print('container type does not contain rbnode')
                return
            offset = gdb.parse_and_eval('offsetof(struct %s, %s)' % (contype.name, fieldname))
        def print_node(n):
            if contype == None:
                print('(rbnode)0x%x' % (n))
            else:
                print('(struct %s *)0x%x' % (contype.name, int(n) - offset))

        rbtree_traverse_inorder(tree['root'], print_node)

BufferPrinter()
TablePrinter()
TreePrinter()

