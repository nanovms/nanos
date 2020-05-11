/* implementation of Sedgewick's left-leaning red-black tree

   https://www.cs.princeton.edu/~rs/talks/rb/LLRB.pdf
   https://www.cs.princeton.edu/~rs/talks/LLRB/RedBlack.pdf

   TODO: consider adding augmentation for cheaper meta updates and
         less work on collection
*/

#include <runtime.h>

//#define RBTREE_PARANOIA
//#define RBTREE_DEBUG
#ifdef RBTREE_DEBUG
#define rbtree_debug(x, ...) do {rprintf("RBTREE %s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define rbtree_debug(x, ...)
#endif

#define left 0
#define right 1
#define black 0
#define red 1
#define COLOR_MASK 1

#define parent(n) ((rbnode)((n)->parent_color & ~COLOR_MASK))
#define set_parent(n, p) ((n)->parent_color = (((n)->parent_color) & COLOR_MASK) | \
                          u64_from_pointer(p))
#define child(n, i) ((n)->c[i])
#define get_color(n) ((n)->parent_color & COLOR_MASK)
#define set_color(n, c) do { (n)->parent_color = ((n)->parent_color & ~COLOR_MASK) | (c); } while(0)
#define set_parent_and_color(n, p, c) do { (n)->parent_color = u64_from_pointer(p) | (c); } while(0)
#define invert_color(n) do { (n)->parent_color ^= COLOR_MASK; } while(0)
#define is_black(n) (get_color(n) == black)
#define is_red(n) ((n) && !is_black(n))
#define is_black_or_null(n) (!is_red(n)) /* a little more descriptive than !is_red... */
#define is_leaf(n) (!child(n, left) && !child(n, right))

static inline int compare_nodes(rbtree t, rbnode a, rbnode b)
{
    assert(t->key_compare);
    return apply(t->key_compare, a, b);
}

static inline int other(int side)
{
    return right - side;
}

static inline rbnode rotate(int hand, rbnode h)
{
    int oh = other(hand);
    rbnode x = child(h, oh);
    assert(x);
    rbnode xh = child(x, hand);
    child(h, oh) = xh;
    if (xh)
        set_parent(xh, h);
    child(x, hand) = h;
    set_parent_and_color(x, parent(h), get_color(h));
    set_parent_and_color(h, x, red);
    return x;
}

static inline void color_flip(rbnode n)
{
    assert(n);
    invert_color(n);
    assert(child(n, left));
    invert_color(child(n, left));
    assert(child(n, right));
    invert_color(child(n, right));
}

static inline rbnode find_limit(rbnode h, boolean max)
{
    assert(h);
    do {
        rbnode c = child(h, max ? right : left);
        if (!c)
            return h;
        h = c;
    } while (1);
}

/* find first parent that has this path on hand */
static inline rbnode find_ancestor_of_hand(rbnode h, boolean hand)
{
    assert(h);
    rbnode p;
    do {
        p = parent(h);
        if (!p)
            return INVALID_ADDRESS; /* not found */
        if (child(p, other(hand)) == h)
            return p;
        h = p;
    } while (1);
}

static inline rbnode get_adjacent_inorder(rbnode h, int hand)
{
    rbnode hh = child(h, hand);
    return hh ? find_limit(hh, hand == left ? true : false) :
        find_ancestor_of_hand(h, hand);
}

rbnode rbtree_find_first(rbtree t)
{
    if (!t->root)
        return INVALID_ADDRESS;
    return find_limit(t->root, false);
}

rbnode rbnode_get_prev(rbnode h)
{
    return get_adjacent_inorder(h, left);
}

rbnode rbnode_get_next(rbnode h)
{
    return get_adjacent_inorder(h, right);
}

rbnode rbtree_lookup(rbtree t, rbnode k)
{
    rbnode h = t->root;
    while (h) {
        int d = compare_nodes(t, k, h);
        if (d == 0)
            return h;
        h = child(h, d < 0 ? left : right);
    }
    return INVALID_ADDRESS;
}

static rbnode max_lte_internal(rbtree t, rbnode h, rbnode k)
{
    int d = compare_nodes(t, k, h);
    if (d == 0)
        return h;
    if (d > 0) {                /* k > h */
        if (!child(h, right))
            return h;
        rbnode next = max_lte_internal(t, child(h, right), k);
        if (next == INVALID_ADDRESS || compare_nodes(t, next, k) > 0) {
            return h;
        } else {
            return next;
        }
    }
    /* k < h */
    if (!child(h, left))
        return INVALID_ADDRESS;
    return max_lte_internal(t, child(h, left), k);
}

rbnode rbtree_lookup_max_lte(rbtree t, rbnode k)
{
    if (!t->root)
        return INVALID_ADDRESS;
    return max_lte_internal(t, t->root, k);
}

static inline rbnode check_move_red(rbnode h, int hand)
{
    int oh = other(hand);
    rbnode hh = child(h, hand);
    rbtree_debug("h %p, hand %d, hh %p\n", h, hand, hh);
    if (!hh || (is_black(hh) && is_black_or_null(child(hh, left)))) {
        rbtree_debug("   color_flip\n");
        color_flip(h);
        rbnode ho = child(h, oh);
        if (!ho || is_black_or_null(child(ho, left)))
            return h;
        rbtree_debug("   other left is red\n");
        if (hand == left) {
            rbtree_debug("   left hand, rotate right\n");
            child(h, right) = rotate(right, child(h, right));
        }
        h = rotate(hand, h);
        color_flip(h);
    }
    return h;
}

/* correct violations of invariant properties on way back up the tree */
static rbnode fix_up(rbnode h)
{
    /* rotate right-leaning red links into left-leaning */
    if (is_black_or_null(child(h, left)) && is_red(child(h, right))) {
        rbtree_debug("rl -> ll: %p\n", h);
        h = rotate(left, h);
        rbtree_debug("  head now %p\n", h);
    }

    /* break up consecutive red links */
    if (is_red(child(h, left))) {
        rbnode lgc = child(child(h, left), left);
        if (is_red(lgc)) {
            rbtree_debug("breakup consecutive reds (%p, %p)\n", child(h, left),
                         child(child(h, left), left));
            h = rotate(right, h);
            rbtree_debug("  head now %p\n", h);
        }
    }

    /* break up 4-nodes - leaving a 2-3 tree */
    if (is_red(child(h, left)) && is_red(child(h, right))) {
        rbtree_debug("break up 4-node\n");
        color_flip(h);
    }
    return h;
}

static rbnode remove_min(rbnode h, rbnode *removed)
{
    if (!child(h, left)) {
        *removed = h;
        return 0;
    }

    /* push red links down left spine to accommodate min remove */
    h = check_move_red(h, left);
    child(h, left) = remove_min(child(h, left), removed);
    return fix_up(h);
}

#ifdef RBTREE_DEBUG
static inline char char_from_delta(int d)
{
    return d == 0 ? '=' : (d < 0 ? '<' : '>');
}
#endif

static rbnode remove_internal(rbtree t, rbnode h, rbnode k, boolean *result)
{
    if (!h)
        return h;
    int d = compare_nodes(t, k, h);
    rbtree_debug("compare1 h %p: %c, result %d\n", h, char_from_delta(d), *result);
    if (d < 0) {
        if (!child(h, left))
            return h;           /* search failed */

        /* push red links down left spine */
        h = check_move_red(h, left);
        child(h, left) = remove_internal(t, child(h, left), k, result);
        return fix_up(h);
    }

    if (d > 0 && !child(h, right))
        return h;           /* search failed */

    /* rotate red to move down right spine */
    if (is_red(child(h, left))) {
        rbtree_debug("  left is red, rotate right\n");
        h = rotate(right, h);
    }
    assert(h);
    d = compare_nodes(t, k, h);
    rbtree_debug("  compare2 h %p: %c, rt %p\n", h, char_from_delta(d), child(h, right));
    if (d == 0 && is_leaf(h)) {
        /* match at leaf */
        *result = true;
        return 0;
    }

    /* keep pushing red links down */
    h = check_move_red(h, right);
    assert(h);
    d = compare_nodes(t, k, h);
    rbtree_debug("    compare3 h %p: %c, rt %p\n", h, char_from_delta(d), child(h, right));
    if (d != 0) {
        if (!child(h, right))
            return h;           /* search failed */
        child(h, right) = remove_internal(t, child(h, right), k, result);
        return fix_up(h);
    }

    /* replace match with min of right subtree */
    assert(child(h, right)); /* invariant: not 2-node */
    rbnode rmin = 0;
    rbnode rnew = remove_min(child(h, right), &rmin);
    assert(rmin);
    if (rnew)
        set_parent(rnew, rmin);
    set_parent_and_color(rmin, parent(h), get_color(h));
    assert(!child(rmin, left));
    if (child(h, left))
        set_parent(child(h, left), rmin);
    child(rmin, left) = child(h, left);
    child(rmin, right) = rnew;
    if (parent(h)) /* not root */
        child(parent(h), child(parent(h), left) == h ? left : right) = rmin;
    h = rmin;
    *result = true;
    return fix_up(h);
}

boolean rbtree_remove_by_key(rbtree t, rbnode k)
{
    boolean result = 0;
    rbtree_debug("t %p, k %p\n", t, k);
    t->root = remove_internal(t, t->root, k, &result);
    if (t->root)
        set_color(t->root, black);
    if (result) {
        assert(t->count > 0);
        t->count--;
    }
#ifdef RBTREE_PARANOIA
    {
        status s = rbtree_validate(t);
        if (!is_ok(s)) {
            halt("%s: validate check failed: %v\n", __func__, s);
        }
    }
#endif
    return result;
}

/* recursive version */
static rbnode insert_node_internal(rbtree t, rbnode h, rbnode n, boolean *result)
{
    rbtree_debug("   pre  h %p, n %p, result %d\n", h, n, *result);

    /* insert */
    int d = compare_nodes(t, n, h);
    if (d != 0) {
        int hand = d < 0 ? left : right;
        rbnode hh = child(h, hand);
        if (!hh) {
            child(h, hand) = n;
            set_parent(n, h);
            *result = true;
        } else {
            child(h, hand) = insert_node_internal(t, hh, n, result);
        }
    }
    h = fix_up(h);
    rbtree_debug("   head now %p\n", h);
    return h;
}

boolean rbtree_insert_node(rbtree t, rbnode n)
{
    rbtree_debug("t %p, n %p\n", t, n);
    boolean result = false;
    if (!t->root) {
        t->root = n;
        result = true;
    } else {
        set_color(n, red);
        t->root = insert_node_internal(t, t->root, n, &result);
    }
    set_color(t->root, black);
    if (result)
        t->count++;
#ifdef RBTREE_PARANOIA
    {
        status s = rbtree_validate(t);
        if (!is_ok(s)) {
            halt("%s: validate check failed: %v\n", __func__, s);
        }
    }
#endif
    return result;
}

static void print_key(rbtree t, rbnode n)
{
    if (n) {
        if (t->print_key)
            apply(t->print_key, n);
        else
            rprintf("%p", n);
    }
}

static void dump_node(rbtree t, rbnode n)
{
    rprintf("node %p\n", n);
    print_key(t, n);
    if (n) {
        if (is_red(n))
            rprintf(" <===");
        else
            rprintf(" <---");
        print_key(t, parent(n));
        rprintf("\n   L ");
        print_key(t, child(n, left));
        rprintf("\n   R ");
        print_key(t, child(n, right));
        rprintf("\n\n");
    }
}

closure_function(1, 1, boolean, dump_internal,
                 rbtree, t,
                 rbnode, n)
{
    dump_node(bound(t), n);
    return true;
}

static inline boolean traverse_inorder(rbnode n, rbnode_handler rh)
{
    if (!n)
        return true;
    if (!traverse_inorder(child(n, left), rh))
        return false;
    if (!apply(rh, n))
        return false;
    return traverse_inorder(child(n, right), rh);
}

static inline boolean traverse_preorder(rbnode n, rbnode_handler rh)
{
    if (!n)
        return true;
    if (!apply(rh, n))
        return false;
    if (!traverse_preorder(child(n, left), rh))
        return false;
    return traverse_preorder(child(n, right), rh);
}

static inline boolean traverse_postorder(rbnode n, rbnode_handler rh)
{
    if (!n)
        return true;
    if (!traverse_postorder(child(n, left), rh))
        return false;
    if (!traverse_postorder(child(n, right), rh))
        return false;
    return apply(rh, n);
}

boolean rbtree_traverse(rbtree t, int order, rbnode_handler rh)
{
    if (order == RB_INORDER)
        return traverse_inorder(t->root, rh);
    if (order == RB_PREORDER)
        return traverse_preorder(t->root, rh);
    assert(order == RB_POSTORDER);
    return traverse_postorder(t->root, rh);
}

void rbtree_dump(rbtree t, int order)
{
    rbtree_traverse(t, order, stack_closure(dump_internal, t));
}

static status parent_child_check(rbtree t, rbnode p, int hand)
{
    rbnode c = child(p, hand);
    char *hstr = hand == left ? "left" : "right";
    if (!c)
        return STATUS_OK;
    if (parent(c) != p) {
        dump_node(t, p);
        return timm("result", "parent mismatch: %p, %s child %p, parent(child) %p",
                    p, hstr, c, parent(c));
    }
    if (is_red(p) && is_red(c)) {
        dump_node(t, p);
        return timm("result", "both node %p and %s child %p are red",
                    p, hstr, c);
    }
    return STATUS_OK;
}

/* traverse while testing for invariants:

   - node child's parent link must point to node
   - no consecutive red links
   - no right-leaning 3-nodes
   - number of black links from root is same for all leaves
*/
static status validate_tree_invariants(rbtree t, rbnode n, u64 black_links, u64 *black_count)
{
    if (!n)
        return STATUS_OK;

    rbnode nl = child(n, left);
    rbnode nr = child(n, right);

    if (!nl && !nr) {
        /* leaf checks */
        if (*black_count != -1ull) {
            if (*black_count != black_links) {
                return timm("result", "rbtree validate: black line count mismatch at leaf");
            }
        } else {
            *black_count = black_links;
        }
        return STATUS_OK;
    }

    if (is_black_or_null(nl) && (nr && is_red(nr))) {
        dump_node(t, n);
        return timm("result", "rbtree validate: right-leaning 3-node");
    }

    status s = parent_child_check(t, n, left);
    if (!is_ok(s))
        return s;
    s = parent_child_check(t, n, right);
    if (!is_ok(s))
        return s;

    if (nl)
        s = validate_tree_invariants(t, nl, black_links + (is_black(nl) ? 1 : 0), black_count);
    if (is_ok(s) && nr)
        s = validate_tree_invariants(t, nr, black_links + (is_black(nr) ? 1 : 0), black_count);
    return s;
}

/* we'd like to add a test for max lte here, but we don't have a way
   to generate key nodes without creating another callback to user
   ... so stress max lte in unit test */

closure_function(2, 1, boolean, test_inorder_node,
                 rbnode *, last, status *, result,
                 rbnode, n)
{
    if (*bound(last) != 0) {
        rbnode last = *bound(last);
        rbnode prev = rbnode_get_prev(n);
        if (prev != last) {
            *bound(result) = timm("result", "prev of n %p doesn't match last %p\n", prev, last);
            return false;
        }
        rbnode next = rbnode_get_next(last);
        if (next != n) {
            *bound(result) = timm("result", "next of last %p doesn't match node %p\n", next, n);
            return false;
        }
    } else {
        rbnode prev = rbnode_get_prev(n);
        if (prev != INVALID_ADDRESS) {
            *bound(result) = timm("result", "first element %p, prev %p, should be invalid\n", n, prev);
            return false;
        }
    }
    *bound(last) = n;
    return true;
}

static status test_inorder(rbtree t)
{
    rbnode last = 0;
    status result = STATUS_OK;
    rbtree_traverse(t, RB_INORDER, stack_closure(test_inorder_node, &last, &result));
    if (is_ok(result)) {
        if (last && rbnode_get_next(last) != INVALID_ADDRESS)
            return timm("result", "next of last element should be invalid");
    }
    return result;
}

status rbtree_validate(rbtree t)
{
    u64 black_count = -1ull;
    status s = validate_tree_invariants(t, t->root, 0, &black_count);
    if (!is_ok(s))
        return s;

    return test_inorder(t);
}

void init_rbtree(rbtree t, rb_key_compare key_compare, rbnode_handler print_key)
{
    assert(t);
    t->root = 0;
    t->count = 0;
    t->key_compare = key_compare;
    t->print_key = print_key;
    t->h = 0;
}

rbtree allocate_rbtree(heap h, rb_key_compare key_compare,
                       rbnode_handler print_key)
{
    rbtree t = allocate(h, sizeof(struct rbtree));
    if (t == INVALID_ADDRESS)
        return t;
    init_rbtree(t, key_compare, print_key);
    t->h = h;
    return t;
}

void destruct_rbtree(rbtree t, rbnode_handler destructor)
{
    rbtree_traverse(t, RB_POSTORDER, destructor);
    t->root = 0;
}

void deallocate_rbtree(rbtree t, rbnode_handler destructor)
{
    destruct_rbtree(t, destructor);
    if (t->h)
        deallocate(t->h, t, sizeof(struct rbtree));
}
