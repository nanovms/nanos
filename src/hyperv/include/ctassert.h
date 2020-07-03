#ifndef _CTASSERT_H_
#define _CTASSERT_H_

/*
 * Macro to test if we're using a specific version of gcc or later.
 */
#if defined(__GNUC__)
#define __GNUC_PREREQ__(ma, mi) \
        (__GNUC__ > (ma) || __GNUC__ == (ma) && __GNUC_MINOR__ >= (mi))
#else
#define __GNUC_PREREQ__(ma, mi) 0
#endif

#ifndef __has_extension
#define __has_extension(x) 0
#endif

#if !__has_extension(c_static_assert)
#if (defined(__cplusplus) && __cplusplus >= 201103L) || \
    __has_extension(cxx_static_assert)
#define _Static_assert(x, y)    static_assert(x, y)
#elif __GNUC_PREREQ__(4,6) && !defined(__cplusplus)
/* Nothing, gcc 4.6 and higher has _Static_assert built-in */
#elif defined(__COUNTER__)
#define _Static_assert(x, y)    __Static_assert(x, __COUNTER__)
#define __Static_assert(x, y)   ___Static_assert(x, y)
#define ___Static_assert(x, y)  typedef char __assert_ ## y[(x) ? 1 : -1] \
                                __unused
#else
#define _Static_assert(x, y)    struct __hack
#endif
#endif

#ifndef CTASSERT
#define CTASSERT(x)     _Static_assert(x, "compile-time assertion failed")
#endif

#endif //_CTASSERT_H_
