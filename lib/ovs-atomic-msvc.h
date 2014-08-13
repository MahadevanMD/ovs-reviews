/*
 * Copyright (c) 2013, 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* This header implements atomic operation primitives using MSVC intrinsics. */
/* #ifndef IN_OVS_ATOMIC_H */
/* #error "This header should only be included indirectly via ovs-atomic.h." */
/* #endif */

/* #include <intrin.h> */
/* #include <windows.h> */

#define A 1, 2
#define FIRST(x, y) x
#define XFIRST(x) FIRST(x)
#define SECOND(x, y) y
#define XSECOND(x) SECOND(x)
XFIRST(A)
XSECOND(A)

#define OVS_ATOMIC_PTHREADS_IMPL 1

#define ATOMIC(TYPE) TYPE

#define ATOMIC_BOOL_LOCK_FREE 0
#define ATOMIC_CHAR_LOCK_FREE 0
#define ATOMIC_SHORT_LOCK_FREE 0
#define ATOMIC_INT_LOCK_FREE 0
#define ATOMIC_LONG_LOCK_FREE 0
#define ATOMIC_LLONG_LOCK_FREE 0
#define ATOMIC_POINTER_LOCK_FREE 0

typedef enum {
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
} memory_order;

#define ATOMIC_VAR_INIT(VALUE) (VALUE)
#define atomic_init(OBJECT, VALUE) (*(OBJECT) = (VALUE), (void) 0)

static inline void
atomic_thread_fence(memory_order order OVS_UNUSED)
{
    /* Nothing to do. */
}

static inline void
atomic_signal_fence(memory_order order OVS_UNUSED)
{
    /* Nothing to do. */
}

#define atomic_is_lock_free(OBJ) false

/* Types:
 *
 * c
 * sc
 * uc
 * s
 * us
 * i
 * u
 * l
 * ul
 * ll
 * ull
 *
 * s8
 * s16
 * s32
 * s64
 * u8
 * u16
 * u32
 * u64
 *
 * e8
 * e16
 * e32
 *
 * p
 */

static inline void
atomic_thread_fence_if_seq_cst(memory_order order)
{
    if (order == memory_order_seq_cst) {
        MemoryBarrier();
    }
}

#define ATOMIC_BASIC_TYPES \
    ATOMIC_BASIC_TYPE(c, char) \
    ATOMIC_BASIC_TYPE(sc, signed char) \
    ATOMIC_BASIC_TYPE(uc, unsigned char) \
    ATOMIC_BASIC_TYPE(s, short) \
    ATOMIC_BASIC_TYPE(us, unsigned short) \
    ATOMIC_BASIC_TYPE(i, int) \
    ATOMIC_BASIC_TYPE(u, unsigned) \
    ATOMIC_BASIC_TYPE(l, long) \
    ATOMIC_BASIC_TYPE(ul, unsigned long) \
    ATOMIC_BASIC_TYPE(ll, long long) \
    ATOMIC_BASIC_TYPE(ull, unsigned long long) \
    ATOMIC_BASIC_TYPE(vp, void *)

#define ATOMIC_BASIC_TYPE(name, type) typedef ATOMIC_##name##_type type;
ATOMIC_BASIC_TYPES
#undef ATOMIC_BASIC_TYPE

#if 0
#define ATOMIC_c_TYPE char
#define ATOMIC_sc_TYPE signed char
#define ATOMIC_uc_TYPE unsigned char
#define ATOMIC_s_TYPE short
#define ATOMIC_us_TYPE unsigned short
#define ATOMIC_i_TYPE int
#define ATOMIC_u_TYPE unsigned
#define ATOMIC_l_TYPE long
#define ATOMIC_ul_TYPE unsigned long
#define ATOMIC_ll_TYPE long long
#define ATOMIC_ull_TYPE unsigned long long
#define ATOMIC_vp_TYPE void *
#endif

#define ATOMIC_s8 ATOMIC_sc
#define ATOMIC_s16 ATOMIC_s
#define ATOMIC_s32 ATOMIC_i
#define ATOMIC_s64 ATOMIC_ll
#define ATOMIC_u8 ATOMIC_uc
#define ATOMIC_u16 ATOMIC_us
#define ATOMIC_u32 ATOMIC_u
#define ATOMIC_u64 ATOMIC_ull

#define ATOMIC_e8 ATOMIC_i
#define ATOMIC_e16 ATOMIC_i
#define ATOMIC_e32 ATOMIC_i

#define ATOMIC_TYPE(TYPE) ATOMIC_TYPE_(TYPE)
#define ATOMIC_TYPE_(TYPE) ATOMIC_TYPE__(ATOMIC_##TYPE)
#define ATOMIC_TYPE__(ARG) ATOMIC_TYPE___(ARG)
#define ATOMIC_TYPE___(ARG) ARG##_TYPE

ATOMIC_TYPE(c);
ATOMIC_TYPE(s8);

#define atomic_load(OBJ, TYPE) \
    atomic_load_explicit(OBJ, memory_order_seq_cst, TYPE)
#define atomic_load_explicit(OBJ, ORDER, TYPE) \
    atomic_load_explicit_(OBJ, ORDER, ATOMIC_##TYPE)
#define atomic_load_explicit_(OBJ, ORDER, TYPE) \
    atomic_load_explicit__(OBJ, ORDER, TYPE)
#define atomic_load_explicit__(OBJ, ORDER, TYPE) \
    atomic_load_explicit__##TYPE(OBJ, ORDER)
atomic_load(obj, c);
atomic_load(obj, s8);

#define ATOMIC_BASIC_TYPE(NAME, TYPE)                           \
    static inline TYPE                                          \
    atomic_load_explicit__ATOMIC_##NAME(TYPE *obj, memory_order order) \
    {                                                           \
        atomic_thread_fence_if_seq_cst(order);                  \
        return *(TYPE volatile *) obj;                          \
    }
ATOMIC_BASIC_TYPES
#undef ATOMIC_BASIC_TYPE

#define atomic_read(SRC, DST) atomic_read_locked(SRC, DST)
#define atomic_read_explicit(SRC, DST, ORDER)   \
    ((void) (ORDER), atomic_read(SRC, DST))

#define atomic_compare_exchange_strong(DST, EXP, SRC)   \
    atomic_compare_exchange_locked(DST, EXP, SRC)
#define atomic_compare_exchange_strong_explicit(DST, EXP, SRC, ORD1, ORD2) \
    ((void) (ORD1), (void) (ORD2),                                      \
     atomic_compare_exchange_strong(DST, EXP, SRC))
#define atomic_compare_exchange_weak            \
    atomic_compare_exchange_strong
#define atomic_compare_exchange_weak_explicit   \
    atomic_compare_exchange_strong_explicit

#define atomic_add(RMW, ARG, ORIG) atomic_op_locked(RMW, add, ARG, ORIG)
#define atomic_sub(RMW, ARG, ORIG) atomic_op_locked(RMW, sub, ARG, ORIG)
#define atomic_or( RMW, ARG, ORIG) atomic_op_locked(RMW, or, ARG, ORIG)
#define atomic_xor(RMW, ARG, ORIG) atomic_op_locked(RMW, xor, ARG, ORIG)
#define atomic_and(RMW, ARG, ORIG) atomic_op_locked(RMW, and, ARG, ORIG)

#define atomic_add_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_add(RMW, ARG, ORIG))
#define atomic_sub_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_sub(RMW, ARG, ORIG))
#define atomic_or_explicit(RMW, ARG, ORIG, ORDER)   \
    ((void) (ORDER), atomic_or(RMW, ARG, ORIG))
#define atomic_xor_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_xor(RMW, ARG, ORIG))
#define atomic_and_explicit(RMW, ARG, ORIG, ORDER)  \
    ((void) (ORDER), atomic_and(RMW, ARG, ORIG))

/* atomic_flag */

typedef struct {
    bool b;
} atomic_flag;
#define ATOMIC_FLAG_INIT { false }

static inline bool
atomic_flag_test_and_set(volatile atomic_flag *flag_)
{
    atomic_flag *flag = CONST_CAST(atomic_flag *, flag_);
    bool old_value;

    atomic_lock__(flag);
    old_value = flag->b;
    flag->b = true;
    atomic_unlock__(flag);

    return old_value;
}

static inline bool
atomic_flag_test_and_set_explicit(volatile atomic_flag *flag,
                                  memory_order order OVS_UNUSED)
{
    return atomic_flag_test_and_set(flag);
}

static inline void
atomic_flag_clear(volatile atomic_flag *flag_)
{
    atomic_flag *flag = CONST_CAST(atomic_flag *, flag_);

    atomic_lock__(flag);
    flag->b = false;
    atomic_unlock__(flag);
}

static inline void
atomic_flag_clear_explicit(volatile atomic_flag *flag,
                           memory_order order OVS_UNUSED)
{
    atomic_flag_clear(flag);
}
