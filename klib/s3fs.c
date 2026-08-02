#include <errno.h>
#include <kernel.h>
#include <pagecache.h>
#include <fs.h>
#include <storage.h>
#include <net_utils.h>
#include <xml.h>
#include <aws.h>

#define S3FS_VOL_PREFIX ss("s3:")

#if S3FS_DEBUG
#define s3fs_debug(x, ...) do {tprintf(sym(s3fs), 0, ss(x"\n"), ##__VA_ARGS__);} while(0)
#else
#define s3fs_debug(x, ...)
#endif

static struct {
    heap h;
    sstring region;
    sstring access_key;
    sstring secret;
    struct buffer sha_empty;
    struct buffer sha_payload;
} s3fs;

typedef struct s3fs_volume {
    struct filesystem fs;
    sstring bucket;
    struct buffer hostname;
    closure_struct(fs_init_handler, fs_init);
    struct list objs;
} *s3fs_volume;

typedef struct s3fs_object {
    struct list l;
    tuple md;
    /* The key stored here is prepended with a leading slash, to make it easier to build an S3 query
     * string. */
    sstring key;
    boolean stale;
    struct s3fs_file *f;
} *s3fs_object;

typedef struct s3fs_file {
    struct fsfile f;
    s3fs_object obj;
    closure_struct(pagecache_node_reserve, reserve);
    closure_struct(thunk, free);
} *s3fs_file;

typedef struct s3fs_read_ctx {
    sg_list sg;
    status_handler completion;
    closure_struct(value_handler, handler);
} *s3fs_read_ctx;

typedef struct s3fs_write_ctx {
    fsfile f;
    u64 write_end;
    sg_buf sgb;
    status_handler completion;
    closure_struct(value_handler, handler);
} *s3fs_write_ctx;

/* Helper to dispatch an HTTP request to the S3 REST API */
static void s3fs_request(s3fs_volume vol, buffer query, http_method method, tuple req, buffer body,
                         value_handler resp_handler)
{
    sstring m = http_request_methods[method];
    s3fs_debug("S3 request: %s %b", m, query);
    set(req, sym(url), query);
    buffer datetime = allocate_buffer(s3fs.h, 16);
    if (datetime == INVALID_ADDRESS) {
        msg_err("s3fs request: cannot allocate memory");
        goto err;
    }
    aws_req_set_date(req, datetime);
    /* The host header must be inserted now (even though the net_utils code inserts it internally)
     * because it needs to be included in the signature. */
    set(req, sym(host), &vol->hostname);
    buffer content_hash = (body && buffer_length(body)) ? &s3fs.sha_payload : &s3fs.sha_empty;
    set(req, sym(x-amz-content-sha256), content_hash);
    buffer auth = aws_req_sign(s3fs.h, s3fs.region, ss("s3"), m, req, body,
                               s3fs.access_key, s3fs.secret);
    if (!auth) {
        msg_err("s3fs request: cannot allocate memory");
        goto err;
    }
    set(req, sym(Authorization), auth);
    struct net_http_req_params params;
    params.host = isstring(vol->hostname.contents, vol->hostname.length);
    params.req = req;
    params.body = body;
    params.resp_handler = resp_handler;
    params.method = method;
    params.port = 443;
    params.tls = true;
    status s = net_http_req(&params);
    if (is_ok(s))
        return;
    msg_err("S3 request error: %v", s);
    timm_dealloc(s);
  err:
    apply(resp_handler, 0);
}

static void s3fs_req_cleanup(tuple req)
{
    buffer auth = get_string(req, sym(Authorization));
    if (auth)
        deallocate_buffer(auth);
    buffer datetime = aws_req_get_date(req);
    if (datetime)
        deallocate_buffer(datetime);
    deallocate_value(req);
}

static s3fs_object s3fs_obj_new_from_md(s3fs_volume vol, bytes key_len, tuple md)
{
    heap h = vol->fs.h;
    s3fs_object obj = allocate(h, sizeof(*obj));
    if (obj == INVALID_ADDRESS)
        return 0;
    if (!sstring_allocate(h, key_len, &obj->key))
        goto err_dealloc_obj;
    obj->md = md;
    obj->f = 0;
    list_push(&vol->objs, &obj->l);
    return obj;
  err_dealloc_obj:
    deallocate(h, obj, sizeof(*obj));
    return 0;
}

static s3fs_object s3fs_obj_new(s3fs_volume vol, bytes key_len, tuple parent, boolean directory)
{
    tuple md = allocate_tuple();
    if (md == INVALID_ADDRESS)
        return 0;
    if (directory) {
        tuple c = allocate_tuple();
        if (c == INVALID_ADDRESS)
            goto err_dealloc_md;
        set(md, sym(children), c);
    }
    s3fs_object obj = s3fs_obj_new_from_md(vol, key_len, md);
    if (!obj)
        goto err_dealloc_md;
    set(md, sym(..), parent);
    return obj;
  err_dealloc_md:
    destruct_value(md, true);
    return 0;
}

static void s3fs_obj_delete(s3fs_volume fs, s3fs_object obj)
{
    s3fs_debug("deleting object %p, md %p", obj, obj->md);
    if (list_inserted(&obj->l))
        list_delete(&obj->l);
    heap h = fs->fs.h;
    sstring_deallocate(h, obj->key);
    if (obj->md)
        fs_cleanup_dir_entry(obj->md);
    if (obj->f)
        fsfile_release(&obj->f->f);
    deallocate(h, obj, sizeof(*obj));
}

static void s3fs_obj_cache_hit(s3fs_volume fs, s3fs_object obj)
{
    if (&obj->l != list_begin(&fs->objs)) {
        list_delete(&obj->l);
        list_push(&fs->objs, &obj->l);
    }
}

static s3fs_object s3fs_obj_get(s3fs_volume fs, tuple md)
{
    list_foreach(&fs->objs, e) {
        s3fs_object obj = struct_from_list(e, s3fs_object, l);
         if (obj->md == md) {
             s3fs_obj_cache_hit(fs, obj);
             return obj;
         }
    }
    return 0;
}

static s64 s3fs_get_blocks(fsfile f)
{
    u64 len = fsfile_get_length(f);
    return pad(len, SECTOR_SIZE) >> SECTOR_OFFSET;
}

closure_func_basic(pagecache_node_reserve, status, s3fs_f_reserve,
                   range q)
{
    s3fs_debug("reserve range %R", q);
    s3fs_file fsf = struct_from_closure(s3fs_file, reserve);
    fsfile f = &fsf->f;
    if (f->length < q.end)
        f->length = q.end;
    return STATUS_OK;
}

static void s3fs_file_delete(s3fs_volume fs, s3fs_file fsf)
{
    s3fs_debug("deallocating file %p", fsf);
    pagecache_deallocate_node(fsf->f.cache_node);
    deallocate(fs->fs.h, fsf, sizeof(*fsf));
}

closure_func_basic(status_handler, void, s3fs_f_sync_complete,
                   status s)
{
    s3fs_debug("file sync complete: %v", s);
    if (!is_ok(s)) {
        msg_err("s3fs: failed to sync page cache node: %v", s);
        timm_dealloc(s);
    }
    fsfile f = struct_from_closure(fsfile, sync_complete);
    s3fs_file fsf = (s3fs_file)f;
    s3fs_volume s3fs = (s3fs_volume)(f->fs);
    s3fs_file_delete(s3fs, fsf);
}

closure_func_basic(thunk, void, s3fs_f_free)
{
    s3fs_debug("file free");
    s3fs_file fsf = struct_from_closure(s3fs_file, free);
    fsfile f = &fsf->f;
    pagecache_purge_node(f->cache_node, init_closure_func(&f->sync_complete, status_handler,
                                                          s3fs_f_sync_complete));
}

static s3fs_file s3fs_file_new(s3fs_volume fs, s3fs_object obj)
{
    heap h = fs->fs.h;
    s3fs_file fsf = allocate(h, sizeof(*fsf));
    if (fsf == INVALID_ADDRESS)
        return 0;
    int ret = fsfile_init(&fs->fs, &fsf->f, obj->md,
                          init_closure_func(&fsf->reserve, pagecache_node_reserve, s3fs_f_reserve),
                          init_closure_func(&fsf->free, thunk, s3fs_f_free));
    if (ret < 0) {
        deallocate(h, fsf, sizeof(*fsf));
        return 0;
    }
    obj->f = fsf;
    fsf->obj = obj;
    fsf->f.get_blocks = s3fs_get_blocks;
    return fsf;
}

closure_function(3, 1, void, s3fs_io_handler,
                 tuple, req, buffer, query, value_handler, handler,
                 value resp)
{
    buffer query = bound(query);
    unwrap_buffer(query->h, query);
    s3fs_req_cleanup(bound(req));
    value_handler handler = bound(handler);
    apply(handler, resp);
    closure_finish();
}

static void s3fs_io_req(fsfile f, boolean write, range q, buffer body, value_handler handler)
{
    s3fs_file s3f = (s3fs_file)f;
    s3fs_volume vol = (s3fs_volume)f->fs;
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        goto err;
    heap h = s3fs.h;
    buffer query = wrap_buffer(h, s3f->obj->key.ptr, s3f->obj->key.len);
    if (query == INVALID_ADDRESS)
        goto err_dealloc_req;
    buffer r = 0;
    if (!range_empty(q)) {
        buffer r = allocate_buffer(h, 32);
        if (r == INVALID_ADDRESS)
            goto err_dealloc_query;
        bprintf(r, "bytes=%ld-%ld", q.start, q.end - 1);
        set(req, sym(range), r);
    }
    value_handler resp_handler = closure(h, s3fs_io_handler, req, query, handler);
    if (resp_handler == INVALID_ADDRESS)
        goto err_dealloc_range;
    s3fs_request(vol, query, write ? HTTP_REQUEST_METHOD_PUT : HTTP_REQUEST_METHOD_GET, req, body,
                 resp_handler);
    return;
  err_dealloc_range:
    if (r)
        deallocate_buffer(r);
  err_dealloc_query:
    unwrap_buffer(h, query);
  err_dealloc_req:
    deallocate_value(req);
  err:
    apply(handler, 0);
}

closure_func_basic(value_handler, void, s3fs_read_handler,
                   value resp)
{
    s3fs_read_ctx ctx = struct_from_closure(s3fs_read_ctx, handler);
    status s;
    sg_list sg = ctx->sg;
    if (http_resp_is_ok(resp)) {
        buffer body = get(resp, sym(content));
        if (body)
            sg_copy_from_buf(buffer_ref(body, 0), sg, buffer_length(body));
        s = STATUS_OK;
    } else {
        s = timm("result", "fserror");
        timm_append(s, "fsstatus", "%d", -EIO);
    }
    async_apply_1(ctx->completion, s);
    deallocate(s3fs.h, ctx, sizeof(*ctx));
}

static void s3fs_fsf_read(fsfile f, sg_list sg, range q, status_handler completion)
{
    s3fs_debug("read r %R, sh %F", q, completion);
    status s;
    int fsstatus;
    s3fs_read_ctx read_ctx = allocate(s3fs.h, sizeof(*read_ctx));
    if (read_ctx == INVALID_ADDRESS) {
        fsstatus = -ENOMEM;
        goto out;
    }
    read_ctx->sg = sg;
    read_ctx->completion = completion;
    s3fs_io_req(f, false, q, 0,
                init_closure_func(&read_ctx->handler, value_handler, s3fs_read_handler));
    return;
  out:
    s = timm("result", "fserror");
    apply(completion, timm_append(s, "fsstatus", "%d", fsstatus));
}

closure_func_basic(value_handler, void, s3fs_write_handler,
                   value resp)
{
    s3fs_write_ctx ctx = struct_from_closure(s3fs_write_ctx, handler);
    status s;
    sg_buf sgb = ctx->sgb;
    if (http_resp_is_ok(resp)) {
        fsfile_set_length(ctx->f, ctx->write_end);
        s = STATUS_OK;
    } else {
        s = timm("result", "fserror");
        timm_append(s, "fsstatus", "%d", -EIO);
    }
    if (sgb != INVALID_ADDRESS)
        sg_buf_release(sgb);
    async_apply_1(ctx->completion, s);
    deallocate(s3fs.h, ctx, sizeof(*ctx));
}

static void s3fs_fsf_write(fsfile f, sg_list sg, range q, status_handler completion)
{
    s3fs_debug("write r %R, sh %F", q, completion);
    status s;
    int fsstatus;
    if ((sg_list_length(sg) > 1) || (q.start != 0)) {
        fsstatus = -EOPNOTSUPP;
        goto out;
    }
    s3fs_write_ctx write_ctx = allocate(s3fs.h, sizeof(*write_ctx));
    if (write_ctx == INVALID_ADDRESS) {
        fsstatus = -ENOMEM;
        goto out;
    }
    sg_buf sgb = sg_list_head_remove(sg);
    buffer body;
    if (sgb != INVALID_ADDRESS) {
        body = wrap_buffer(s3fs.h, sgb->buf + sgb->offset, range_span(q));
        if (body == INVALID_ADDRESS) {
            sg_buf_release(sgb);
            fsstatus = -ENOMEM;
            goto err_dealloc_ctx;
        }
    } else {
        body = 0;
    }
    write_ctx->f = f;
    write_ctx->write_end = q.end;
    write_ctx->sgb = sgb;
    write_ctx->completion = completion;
    s3fs_io_req(f, true, irange(0, 0), body,
                init_closure_func(&write_ctx->handler, value_handler, s3fs_write_handler));
    return;
  err_dealloc_ctx:
    deallocate(s3fs.h, write_ctx, sizeof(*write_ctx));
  out:
    s = timm("result", "fserror");
    async_apply_1(completion, timm_append(s, "fsstatus", "%d", fsstatus));
}

static boolean is_leap_year(int year) {
    if ((year & 3) != 0) {
        return false;
    }
    if ((year % 100) != 0) {
        return true;
    }
    return (year % 400) == 0;
}

static boolean parse_last_modified(buffer b, timestamp *ts)
{
    /* timestamp example: Sat, 25 Jul 2026 09:15:30 GMT */
    if (buffer_length(b) < 29)
        return false;
    char *p = buffer_ref(b, 0);
    u64 day = (p[5] - '0') * 10 + (p[6] - '0');
    u64 month = -1ull;
    sstring mon = isstring(p + 8, 3);
    const char *months[] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    for (int i = 0; i < 12; i++) {
        if (!runtime_memcmp(mon.ptr, months[i], 3)) {
            month = i;
            break;
        }
    }
    if (month == -1ull)
        return false;
    u64 year = 0;
    for (int i = 0; i < 4; i++) {
        year = year * 10 + (p[12 + i] - '0');
    }
    u64 hour = (p[17] - '0') * 10 + (p[18] - '0');
    u64 min = (p[20] - '0') * 10 + (p[21] - '0');
    u64 sec = (p[23] - '0') * 10 + (p[24] - '0');
    s3fs_debug("last modified '%b', %d-%02d-%02d %02d:%02d:%02d", b,
               year, month + 1, day, hour, min, sec);
    u64 days = 0;
    for (u64 y = 1970; y < year; y++)
        days += is_leap_year(y) ? 366 : 365;
    int month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    for (u64 m = 0; m < month; m++) {
        if (m == 1 && is_leap_year(year))
            days += 29;
        else
            days += month_days[m];
    }
    days += day - 1;
    u64 total_secs = days * 86400 + hour * 3600 + min * 60 + sec;
    *ts = seconds(total_secs);
    return true;
}

closure_function(4, 1, void, s3fs_head_resp,
                 u64 *, plen, timestamp *, pmtime, boolean *, success, context, ctx,
                 value resp)
{
    if (http_resp_is_ok(resp)) {
        *bound(success) = true;
        buffer cl = get(resp, sym(Content-Length));
        if (!cl || !parse_int(cl, 10, bound(plen)))
            *bound(plen) = 0;
        buffer lm = get(resp, sym(Last-Modified));
        if (!lm || !parse_last_modified(lm, bound(pmtime)))
            *bound(pmtime) = 0;
    }
    context_schedule_return(bound(ctx));
}

static int s3fs_head_object(s3fs_volume s3fs, s3fs_object obj, u64 *plen, timestamp *pmtime)
{
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        return -ENOMEM;
    buffer query = alloca_wrap_sstring(obj->key);
    boolean success = false;
    context ctx = current_context();
    value_handler resp_handler = stack_closure(s3fs_head_resp, plen, pmtime, &success, ctx);
    context_pre_suspend(ctx);
    s3fs_request(s3fs, query, HTTP_REQUEST_METHOD_HEAD, req, 0, resp_handler);
    context_suspend();
    s3fs_req_cleanup(req);
    return success ? 0 : -EIO;
}

static int s3fs_get_fsfile(filesystem fs, tuple md, fsfile *f)
{
    s3fs_volume vol = (s3fs_volume)fs;
    s3fs_object obj = s3fs_obj_get(vol, md);
    s3fs_debug("get fsfile, md %p, obj %p", md, obj);
    if (!obj)
        return -ENOENT;
    s3fs_file fsf = obj->f;
    if (!fsf) {
        u64 len;
        timestamp mtime;
        int ret = s3fs_head_object(vol, obj, &len, &mtime);
        if (ret < 0)
            return ret;
        fsf = s3fs_file_new(vol, obj);
        if (!fsf)
            return -ENOMEM;
        fsfile_set_length(&fsf->f, len);
        filesystem_set_mtime(fs, md, mtime);
        obj->f = fsf;
    }
    fsfile_reserve(&fsf->f);
    *f = &fsf->f;
    return 0;
}

static tuple s3fs_get_meta(filesystem fs, inode n)
{
    s3fs_volume vol = (s3fs_volume)fs;
    s3fs_object obj = s3fs_obj_get(vol, pointer_from_u64(n));
    return obj ? obj->md : 0;
}

closure_function(1, 2, boolean, s3fs_dir_set_stale,
                 s3fs_volume, vol,
                 value k, value v)
{
    s3fs_volume vol = bound(vol);
    s3fs_object obj = s3fs_obj_get(vol, v);
    if (obj)
        obj->stale = true;
    return true;
}

closure_function(1, 2, boolean, s3fs_dir_del_stale,
                 s3fs_volume, vol,
                 value k, value v)
{
    s3fs_volume vol = bound(vol);
    s3fs_object obj = s3fs_obj_get(vol, v);
    if (obj && obj->stale) {
        s3fs_debug("deleting stale object %s", obj->key);
        fs_notify_release(obj->md, false);
        s3fs_obj_delete(vol, obj);
    }
    return true;
}

static boolean s3fs_readdir_entry(s3fs_volume vol, tuple parent, bytes dir_path_len, buffer body,
                                  xml_elem elem, boolean dir)
{
    if (elem->data_len <= dir_path_len)
        return true;
    s3fs_object obj = 0;
    sstring base_name = isstring(buffer_ref(body, elem->data_start + dir_path_len),
                                 elem->data_len - dir_path_len);
    if (dir)
        /* The trailing slash must not be included in the children tuple attribute. */
        base_name.len -= 1;
    symbol base_name_s = sym_sstring(base_name);
    tuple c = children(parent);
    tuple md = get(c, base_name_s);
    if (md)
        obj = s3fs_obj_get(vol, md);
    s3fs_debug("readdir '%s%s' (%s)", base_name, dir ? ss("/") : sstring_empty(),
               obj ? ss("cached") : ss("new"));
    if (obj) {
        obj->stale = false;
    } else {
        obj = s3fs_obj_new(vol, 1 + elem->data_len, parent, dir);   /* +1 for the leading slash */
        if (!obj) {
            msg_err("s3fs: readdir allocation failure");
            return false;
        }
        obj->key.ptr[0] = '/';
        runtime_memcpy(obj->key.ptr + 1, buffer_ref(body, elem->data_start), elem->data_len);
        obj->stale = false;
        set(c, base_name_s, obj->md);
    }
    return true;
}

closure_function(4, 1, void, s3fs_readdir_resp,
                 s3fs_volume, vol, s3fs_object, dir, boolean *, success, context, ctx,
                 value resp)
{
    s3fs_volume vol = bound(vol);
    if (!http_resp_is_ok(resp)) {
        *bound(success) = false;
        goto out;
    }
    buffer body = get(resp, sym(content));
    if (!body) {
        *bound(success) = false;
        goto out;
    }
    *bound(success) = true;
    s3fs_object dir = bound(dir);
    tuple dir_md = dir->md;
    bytes dir_path_len = dir->key.len - 1;
    struct xml_elem elem;
    while (xml_get_elem(body, ss("Key"), &elem)) {
        if (!s3fs_readdir_entry(vol, dir_md, dir_path_len, body, &elem, false)) {
            *bound(success) = false;
            goto out;
        }
        buffer_consume(body, elem.start + elem.len);
    }
    while (xml_get_elem(body, ss("Prefix"), &elem)) {
        if (!s3fs_readdir_entry(vol, dir_md, dir_path_len, body, &elem, true)) {
            *bound(success) = false;
            goto out;
        }
        buffer_consume(body, elem.start + elem.len);
    }
  out:
    context_schedule_return(bound(ctx));
}

static int s3fs_readdir(s3fs_volume fs, s3fs_object dir)
{
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        msg_err("s3fs: readdir allocation failure");
        return -ENOMEM;
    }

    /* Request list of objects with prefix */
    buffer query = little_stack_buffer(dir->key.len + 32);
    /* Remove the leading slash from the key string. */
    sstring prefix = isstring(dir->key.ptr + 1, dir->key.len - 1);
    bprintf(query, "/?delimiter=/&list-type=2&prefix=%s", prefix);
    tuple c = children(dir->md);
    iterate(c, stack_closure(s3fs_dir_set_stale, fs));
    boolean success;
    context ctx = current_context();
    value_handler resp_handler = stack_closure(s3fs_readdir_resp, fs, dir, &success, ctx);
    context_pre_suspend(ctx);
    s3fs_request(fs, query, HTTP_REQUEST_METHOD_GET, req, 0, resp_handler);
    context_suspend();
    s3fs_req_cleanup(req);
    if (success) {
        iterate(c, stack_closure(s3fs_dir_del_stale, fs));
        return 0;
    }
    return -EIO;
}

closure_function(2, 1, void, s3fs_mkobj_resp,
                 boolean *, success, context, ctx,
                 value resp)
{
    if (http_resp_is_ok(resp))
        *bound(success) = true;
    context_schedule_return(bound(ctx));
}

static int s3fs_mkobj(s3fs_volume s3fs, s3fs_object obj)
{
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        return -ENOMEM;
    buffer query = alloca_wrap_sstring(obj->key);
    boolean success = false;
    context ctx = current_context();
    value_handler resp_handler = stack_closure(s3fs_mkobj_resp, &success, ctx);
    context_pre_suspend(ctx);
    s3fs_request(s3fs, query, HTTP_REQUEST_METHOD_PUT, req, 0, resp_handler);
    context_suspend();
    s3fs_req_cleanup(req);
    return success ? 0 : -EIO;
}

closure_function(2, 1, void, s3fs_delete_resp,
                 boolean *, success, context, ctx,
                 value resp)
{
    if (http_resp_is_ok(resp))
        *bound(success) = true;
    context_schedule_return(bound(ctx));
}

static int s3fs_delete_key(s3fs_volume s3fs, sstring key)
{
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        return -ENOMEM;
    buffer query = alloca_wrap_sstring(key);
    boolean success = false;
    context ctx = current_context();
    value_handler resp_handler = stack_closure(s3fs_delete_resp, &success, ctx);
    context_pre_suspend(ctx);
    s3fs_request(s3fs, query, HTTP_REQUEST_METHOD_DELETE, req, 0, resp_handler);
    context_suspend();
    s3fs_req_cleanup(req);
    return success ? 0 : -EIO;
}

static tuple s3fs_lookup(filesystem fs, tuple parent, string name)
{
    s3fs_debug("lookup '%b'", name);
    s3fs_volume s3fs = (s3fs_volume)fs;
    tuple md;
    s3fs_object obj;
    if (!buffer_strcmp(name, "."))
        md = parent;
    else if (!buffer_strcmp(name, ".."))
        md = get(parent, sym(..));
    else
        md = get(children(parent), intern(name));
    if (!md || !(obj = s3fs_obj_get(s3fs, md)))
        return 0;
    if (is_dir(md) && (s3fs_readdir(s3fs, obj) < 0))
        return 0;
    return md;
}

static int s3fs_create(filesystem fs, tuple parent, string name, tuple md, fsfile *f)
{
    if (!name || is_symlink(md) || is_socket(md))
        return -EOPNOTSUPP;
    s3fs_debug("create '%b'", name);
    s3fs_volume s3fs = (s3fs_volume)fs;
    s3fs_object parent_obj = s3fs_obj_get(s3fs, parent);
    if (!parent_obj)
        return -ENOENT;
    boolean dir = is_dir(md);
    bytes key_len = parent_obj->key.len + buffer_length(name);
    if (dir)
        key_len += 1;   /* for the trailing slash */
    s3fs_object obj = s3fs_obj_new_from_md(s3fs, key_len, md);
    if (!obj)
        return -ENOMEM;
    runtime_memcpy(obj->key.ptr, parent_obj->key.ptr, parent_obj->key.len);
    runtime_memcpy(obj->key.ptr + parent_obj->key.len, buffer_ref(name, 0), buffer_length(name));
    s3fs_file fsf = 0;
    int ret;
    if (dir)
        obj->key.ptr[key_len - 1] = '/';
    else {
        fsf = s3fs_file_new(s3fs, obj);
        if (!fsf) {
            ret = -ENOMEM;
            goto out;
        }
        if (f) {
            fsfile_reserve(&fsf->f);
            *f = &fsf->f;
        }
    }
    ret = s3fs_mkobj(s3fs, obj);
  out:
    if (ret < 0) {
        obj->md = 0;
        s3fs_obj_delete(s3fs, obj);
    }
    return ret;
}

static int s3fs_unlink(filesystem fs, tuple parent, string name, tuple md, boolean *destruct_md)
{
    s3fs_volume s3fs = (s3fs_volume)fs;
    s3fs_debug("unlink '%b'", name);
    s3fs_object obj = s3fs_obj_get(s3fs, md);
    if (!obj)
        return -ENOENT;
    int ret = s3fs_delete_key(s3fs, obj->key);
    if (ret < 0)
        return ret;
    obj->md = 0;
    s3fs_obj_delete(s3fs, obj);
    if (destruct_md)
        *destruct_md = true;
    return 0;
}

closure_function(2, 1, void, s3fs_copy_resp,
                 boolean *, success, context, ctx,
                 value resp)
{
    if (http_resp_is_ok(resp))
        *bound(success) = true;
    context_schedule_return(bound(ctx));
}

static int s3fs_copy_object(s3fs_volume s3fs, sstring src_key, sstring dest_key)
{
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        return -ENOMEM;
    buffer copy_source = little_stack_buffer(1 + s3fs->bucket.len + src_key.len);
    bprintf(copy_source, "/%s%s", s3fs->bucket, src_key);
    set(req, sym(x-amz-copy-source), copy_source);
    buffer query = alloca_wrap_sstring(dest_key);
    boolean success = false;
    context ctx = current_context();
    value_handler resp_handler = stack_closure(s3fs_copy_resp, &success, ctx);
    context_pre_suspend(ctx);
    s3fs_request(s3fs, query, HTTP_REQUEST_METHOD_PUT, req, 0, resp_handler);
    context_suspend();
    s3fs_req_cleanup(req);
    return success ? 0 : -EIO;
}

static int s3fs_rename(filesystem fs, tuple old_parent, string old_name, tuple old_md,
                       tuple new_parent, string new_name, tuple new_md, boolean exchange,
                       boolean *destruct_md)
{
    s3fs_debug("rename old '%b' new '%b'%s", old_name, new_name,
               exchange ? ss(" (exchange)") : sstring_empty());
    if (exchange)
        return -EOPNOTSUPP;
    s3fs_volume s3fs = (s3fs_volume)fs;
    s3fs_object old_obj = s3fs_obj_get(s3fs, old_md);
    if (!old_obj)
        return -ENOENT;
    s3fs_object new_parent_obj = s3fs_obj_get(s3fs, new_parent);
    if (!new_parent_obj)
        return -ENOENT;
    boolean dir = is_dir(old_md);
    bytes key_len = new_parent_obj->key.len + buffer_length(new_name);
    if (dir)
        key_len += 1;
    sstring new_key;
    if (!sstring_allocate(s3fs->fs.h, key_len, &new_key))
        return -ENOMEM;
    runtime_memcpy(new_key.ptr, new_parent_obj->key.ptr, new_parent_obj->key.len);
    runtime_memcpy(new_key.ptr + new_parent_obj->key.len, buffer_ref(new_name, 0),
                   buffer_length(new_name));
    if (dir)
        new_key.ptr[key_len - 1] = '/';
    int ret = s3fs_copy_object(s3fs, old_obj->key, new_key);
    if (!ret) {
        s3fs_delete_key(s3fs, old_obj->key);
        sstring_deallocate(s3fs->fs.h, old_obj->key);
        old_obj->key = new_key;
    } else {
        sstring_deallocate(s3fs->fs.h, new_key);
    }
    if (!ret && new_md) {
        s3fs_object obj = s3fs_obj_get(s3fs, new_md);
        if (obj) {
            obj->md = 0;
            s3fs_obj_delete(s3fs, obj);
        }
        *destruct_md = true;
    }
    return ret;
}

static int s3fs_truncate(filesystem fs, fsfile f, u64 len)
{
    if (len > 0)
        return -EOPNOTSUPP;
    s3fs_volume s3fs = (s3fs_volume)fs;
    s3fs_file s3f = (s3fs_file)f;
    return s3fs_mkobj(s3fs, s3f->obj);
}

closure_function(4, 1, void, s3fs_cache_sync_complete,
                 filesystem, fs, fsfile, f, boolean, datasync, status_handler, completion,
                 status s)
{
    s3fs_debug("cache sync complete, status %v", s);
    async_apply_status_handler(bound(completion), s);
    closure_finish();
}

static status_handler s3fs_get_sync_handler(filesystem fs, fsfile fsf, boolean datasync,
                                            status_handler completion)
{
    return closure(fs->h, s3fs_cache_sync_complete, fs, fsf, datasync, completion);
}

closure_func_basic(fs_init_handler, void, s3fs_fs_init,
                   boolean readonly, filesystem_complete complete)
{
    s3fs_debug("FS init read-%s (%F)", readonly ? ss("only") : ss("write"), complete);
    s3fs_volume vol = struct_from_closure(s3fs_volume, fs_init);
    filesystem fs = &vol->fs;

    status s = filesystem_init(fs, s3fs.h, 1024ull * GB, 1, readonly);
    if (!is_ok(s)) {
        apply(complete, INVALID_ADDRESS, s);
        return;
    }
    tuple root_md = allocate_tuple();
    if (root_md == INVALID_ADDRESS)
        goto err_fs_deinit;
    tuple c = allocate_tuple();
    if (c == INVALID_ADDRESS)
        goto err_root_dealloc;
    s3fs_object root = s3fs_obj_new_from_md(vol, 1, root_md);
    if (!root)
        goto err_c_dealloc;
    set(root_md, sym_this("children"), c);
    set(root_md, sym_this(".."), root_md);
    root->key.ptr[0] = '/';
    fs->root = root_md;
    fs->lookup = s3fs_lookup;
    fs->create = s3fs_create;
    fs->unlink = s3fs_unlink;
    fs->rename = s3fs_rename;
    fs->truncate = s3fs_truncate;
    fs->get_fsfile = s3fs_get_fsfile;
    fs->get_inode = fs_get_inode;
    fs->file_read = s3fs_fsf_read;
    fs->file_write = s3fs_fsf_write;
    fs->get_meta = s3fs_get_meta;
    fs->get_sync_handler = s3fs_get_sync_handler;
    apply(complete, fs, STATUS_OK);
    return;
  err_c_dealloc:
    deallocate_value(c);
  err_root_dealloc:
    deallocate_value(root_md);
  err_fs_deinit:
    filesystem_deinit(fs);
    apply(complete, INVALID_ADDRESS, timm_oom);
}

static boolean s3fs_volume_create(heap h, value spec)
{
    string bucket = get_string(spec, sym_this("name"));
    if (!bucket) {
        msg_err("s3fs: missing or invalid bucket name");
        return false;
    }
    char label[VOLUME_LABEL_MAX_LEN];
    if (rsnprintf(label, sizeof(label), "%s%b", S3FS_VOL_PREFIX, bucket) >= sizeof(label)) {
        msg_err("s3fs: bucket name '%b' too long", bucket);
        return false;
    }
    string mount_path = get_string(spec, sym(mount));
    if (mount_path) {
        if (!storage_add_mountpoint(sym_sstring(sstring_from_cstring(label, sizeof(label))),
                                    mount_path)) {
            msg_err("s3fs: failed to add mount point for bucket %b at %b", bucket, mount_path);
            return false;
        }
    }
    s3fs_volume vol = allocate(h, sizeof(*vol));
    if (vol == INVALID_ADDRESS) {
        msg_err("s3fs: cannot allocate volume");
        return false;
    }
    vol->bucket = buffer_to_sstring(bucket);
    const sstring host_prefix = ss(".s3.");
    const sstring host_suffix = ss(".amazonaws.com");
    bytes bucket_len = buffer_length(bucket);
    bytes hostname_len = bucket_len + host_prefix.len + s3fs.region.len + host_suffix.len;
    char *hostname = mem_alloc(h, hostname_len, MEM_NOFAIL);
    init_buffer(&vol->hostname, hostname_len, false, h, hostname);
    runtime_memcpy(hostname, buffer_ref(bucket, 0), bucket_len);
    bytes offset = bucket_len;
    runtime_memcpy(hostname + offset, host_prefix.ptr, host_prefix.len);
    offset += host_prefix.len;
    runtime_memcpy(hostname + offset, s3fs.region.ptr, s3fs.region.len);
    offset += s3fs.region.len;
    runtime_memcpy(hostname + offset, host_suffix.ptr, host_suffix.len);
    buffer_produce(&vol->hostname, hostname_len);
    list_init(&vol->objs);
    u8 uuid[UUID_LEN];
    if (!volume_add(uuid, label, vol,
                    init_closure_func(&vol->fs_init, fs_init_handler, s3fs_fs_init), -1)) {
        msg_err("s3fs: cannot add volume for bucket %b", bucket);
        deallocate(h, vol, sizeof(*vol));
        return false;
    }
    return true;
}

int init(status_handler complete)
{
    tuple config = get(get_root_tuple(), sym_this("s3fs"));
    if (!config)
        return KLIB_INIT_OK;
    heap h = heap_locked(get_kernel_heaps());
    s3fs.h = h;
    string region = get_string(config, sym_this("region"));
    if (!region) {
        msg_err("s3fs: missing or invalid region");
        return KLIB_INIT_FAILED;
    }
    s3fs.region = buffer_to_sstring(region);
    string access_key = get_string(config, sym_this("access_key"));
    if (!access_key) {
        msg_err("s3fs: missing or invalid access key");
        return KLIB_INIT_FAILED;
    }
    s3fs.access_key = buffer_to_sstring(access_key);
    string secret = get_string(config, sym_this("secret"));
    if (!secret) {
        msg_err("s3fs: missing or invalid secret");
        return KLIB_INIT_FAILED;
    }
    s3fs.secret = buffer_to_sstring(secret);
    string buckets = get(config, sym_this("buckets"));
    if (!is_composite(buckets)) {
        msg_err("s3fs: invalid configuration");
        return KLIB_INIT_FAILED;
    }
    buffer_init_from_string(&s3fs.sha_empty,
                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    buffer_init_from_string(&s3fs.sha_payload, "UNSIGNED-PAYLOAD");
    value volume_spec;
    for (int i = 0; (volume_spec = get(buckets, integer_key(i))); i++) {
        if (!s3fs_volume_create(h, volume_spec))
            return KLIB_INIT_FAILED;
    }
    return KLIB_INIT_OK;
}
