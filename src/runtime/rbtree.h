typedef struct rbnode *rbnode;
struct rbnode {
    word parent_color;           /* parent used for verification */
    rbnode c[2];
};

typedef closure_type(rbnode_handler, boolean, rbnode n);
typedef closure_type(rb_key_compare, int, rbnode a, rbnode b);

typedef struct rbtree {
    rbnode root;
    u64 count;
    rb_key_compare key_compare;
    rbnode_handler print_key;
    heap h;
} *rbtree;

boolean rbtree_insert_node(rbtree t, rbnode n);

boolean rbtree_remove_by_key(rbtree t, rbnode k);

/* Delete by node is really delete by key, because we need to perform
   transformations while descending the tree in order to do a safe
   removal - but we'll keep the call as part of the interface in case
   a more optimal solution arises later. */
static inline void rbtree_remove_node(rbtree t, rbnode n)
{
    assert(rbtree_remove_by_key(t, n));
}

rbnode rbtree_lookup(rbtree t, rbnode k);

void init_rbtree(rbtree t, rb_key_compare key_compare, rbnode_handler print_key);

rbtree allocate_rbtree(heap h, rb_key_compare key_compare, rbnode_handler print_key);

void destruct_rbtree(rbtree t, rbnode_handler destructor);

void deallocate_rbtree(rbtree rb, rbnode_handler destructor);

#define RB_INORDER 0
#define RB_PREORDER 1
#define RB_POSTORDER 2

void rbtree_dump(rbtree t, int order);

boolean rbtree_traverse(rbtree t, int order, rbnode_handler rh);

status rbtree_validate(rbtree t);

static inline u64 rbtree_get_count(rbtree t)
{
    return t->count;
}

static inline void init_rbnode(rbnode n)
{
    n->parent_color = 0;
    n->c[0] = n->c[1] = 0;
}

/* not for key nodes! */
rbnode rbnode_get_prev(rbnode h);
rbnode rbnode_get_next(rbnode h);

rbnode rbtree_lookup_max_lte(rbtree t, rbnode k);
rbnode rbtree_find_first(rbtree t);
