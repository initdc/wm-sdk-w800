#include "sl_chacha20poly1305ietf_config.h"
#if defined USE_SL_CHACHA20_POLY1305_IETF || defined USE_SL_SODIUM
# include "osdep_stddef.h"
# include "osdep_stdint.h"
# include "osdep_stdlib.h"
# include "osdep_stdbool.h"
# include "private/common.h"
# include "runtime.h"
# include "pscompilerdep.h"

typedef struct CPUFeatures_ {
    int initialized;
    int has_neon;
    int has_sse2;
    int has_sse3;
    int has_ssse3;
    int has_sse41;
    int has_avx;
    int has_avx2;
    int has_pclmul;
    int has_aesni;
} CPUFeatures;

static CPUFeatures _cpu_features;

# define CPUID_EBX_AVX2    0x00000020

# define CPUID_ECX_SSE3    0x00000001
# define CPUID_ECX_PCLMUL  0x00000002
# define CPUID_ECX_SSSE3   0x00000200
# define CPUID_ECX_SSE41   0x00080000
# define CPUID_ECX_AESNI   0x02000000
# define CPUID_ECX_XSAVE   0x04000000
# define CPUID_ECX_OSXSAVE 0x08000000
# define CPUID_ECX_AVX     0x10000000

# define CPUID_EDX_SSE2    0x04000000

# define XCR0_SSE 0x00000002
# define XCR0_AVX 0x00000004

static int
SLSodium_runtime_arm_cpu_features(CPUFeatures * const cpu_features)
{
# if !defined(__arm__) && !defined(__aarch64__) && !defined(__aarch32__)
    cpu_features->has_neon = 0;
    return -1;
#else /* some ARM platform. */
#  define NO_INTEL /* This architecture is definitely not x86/x86-64.
                      No need to probe for Intel CPU features. */
    /* Customization for INSIDE Secure FIPS Toolkit: */
    /* Use sl_cpu.c for ARM feature detection, instead of
       the default sodium code. */
    
    extern bool SL_ArmDetectionDone;
    extern bool SL_hasNEON;
    void SL_DetectArmFeatures(void);

    if (!SL_ArmDetectionDone)
    {
        if (!getenv("SAFEZONE_DISABLE_HW"))
        {
            SL_DetectArmFeatures();
        }
        else
        {
            SL_ArmDetectionDone = 1;
        }
    }
    cpu_features->has_neon = SL_hasNEON;
    return 0;
# endif /* ARM variant (including ARMv7 or ARMv8). */
}

#ifndef NO_INTEL
static void
_cpuid(unsigned int cpu_info[4U], const unsigned int cpu_info_type)
{
# if defined(_MSC_VER) && \
    (defined(_M_X64) || defined(_M_AMD64) || defined(_M_IX86))
    __cpuid((int *) cpu_info, cpu_info_type);
# elif defined(HAVE_CPUID)
    cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
#  ifdef __i386__
    __asm__ __volatile__(
        "pushfl; pushfl; "
        "popl %0; "
        "movl %0, %1; xorl %2, %0; "
        "pushl %0; "
        "popfl; pushfl; popl %0; popfl"
        : "=&r"(cpu_info[0]), "=&r"(cpu_info[1])
        : "i"(0x200000));
    if (((cpu_info[0] ^ cpu_info[1]) & 0x200000) == 0x0) {
        return; /* LCOV_EXCL_LINE */
    }
#  endif
#  ifdef __i386__
    __asm__ __volatile__("xchgl %%ebx, %k1; cpuid; xchgl %%ebx, %k1"
                         : "=a"(cpu_info[0]), "=&r"(cpu_info[1]),
                           "=c"(cpu_info[2]), "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
#  elif defined(__x86_64__)
    __asm__ __volatile__("xchgq %%rbx, %q1; cpuid; xchgq %%rbx, %q1"
                         : "=a"(cpu_info[0]), "=&r"(cpu_info[1]),
                           "=c"(cpu_info[2]), "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
#  else
    __asm__ __volatile__("cpuid"
                         : "=a"(cpu_info[0]), "=b"(cpu_info[1]),
                           "=c"(cpu_info[2]), "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
#  endif
# else
    (void) cpu_info_type;
    cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
# endif
}
#endif

static int
SLSodium_runtime_intel_cpu_features(CPUFeatures * const cpu_features)
{
#ifndef NO_INTEL
    unsigned int cpu_info[4];
    unsigned int id;

    _cpuid(cpu_info, 0x0);
    if ((id = cpu_info[0]) == 0U) {
        return -1; /* LCOV_EXCL_LINE */
    }
    _cpuid(cpu_info, 0x00000001);
# ifdef HAVE_EMMINTRIN_H
    cpu_features->has_sse2 = ((cpu_info[3] & CPUID_EDX_SSE2) != 0x0);
# else
    cpu_features->has_sse2   = 0;
# endif

# ifdef HAVE_PMMINTRIN_H
    cpu_features->has_sse3 = ((cpu_info[2] & CPUID_ECX_SSE3) != 0x0);
# else
    cpu_features->has_sse3   = 0;
# endif

# ifdef HAVE_TMMINTRIN_H
    cpu_features->has_ssse3 = ((cpu_info[2] & CPUID_ECX_SSSE3) != 0x0);
# else
    cpu_features->has_ssse3  = 0;
# endif

# ifdef HAVE_SMMINTRIN_H
    cpu_features->has_sse41 = ((cpu_info[2] & CPUID_ECX_SSE41) != 0x0);
# else
    cpu_features->has_sse41  = 0;
# endif

    cpu_features->has_avx = 0;
# ifdef HAVE_AVXINTRIN_H
    if ((cpu_info[2] & (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) ==
        (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) {
        uint32_t xcr0 = 0U;
#  if defined(HAVE__XGETBV) || \
        (defined(_MSC_VER) && defined(_XCR_XFEATURE_ENABLED_MASK) && _MSC_FULL_VER >= 160040219)
        xcr0 = (uint32_t) _xgetbv(0);
#  elif defined(_MSC_VER) && defined(_M_IX86)
        __asm {
            xor ecx, ecx
            _asm _emit 0x0f _asm _emit 0x01 _asm _emit 0xd0
            mov xcr0, eax
        }
#  elif defined(HAVE_AVX_ASM)
        __asm__ __volatile__(".byte 0x0f, 0x01, 0xd0" /* XGETBV */
                             : "=a"(xcr0)
                             : "c"((uint32_t) 0U)
                             : "%edx");
#  endif
        if ((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX)) {
            cpu_features->has_avx = 1;
        }
    }
# endif

    cpu_features->has_avx2 = 0;
# ifdef HAVE_AVX2INTRIN_H
    if (cpu_features->has_avx) {
        unsigned int cpu_info7[4];

        _cpuid(cpu_info7, 0x00000007);
        cpu_features->has_avx2 = ((cpu_info7[1] & CPUID_EBX_AVX2) != 0x0);
    }
# endif

# ifdef HAVE_WMMINTRIN_H
    cpu_features->has_pclmul = ((cpu_info[2] & CPUID_ECX_PCLMUL) != 0x0);
    cpu_features->has_aesni  = ((cpu_info[2] & CPUID_ECX_AESNI) != 0x0);
# else
    cpu_features->has_pclmul = 0;
    cpu_features->has_aesni  = 0;
# endif

    return 0;
#else
    return -1; /* Unable to probe for Intel CPU features. */
#endif
}

int
SLSodium_runtime_get_cpu_features(void)
{
    int ret = -1;

    ret &= SLSodium_runtime_arm_cpu_features(&_cpu_features);
    ret &= SLSodium_runtime_intel_cpu_features(&_cpu_features);
    _cpu_features.initialized = 1;

    return ret;
}

int
SLSodium_runtime_has_neon(void)
{
    return _cpu_features.has_neon;
}

int
SLSodium_runtime_has_sse2(void)
{
    return _cpu_features.has_sse2;
}

int
SLSodium_runtime_has_sse3(void)
{
    return _cpu_features.has_sse3;
}

int
SLSodium_runtime_has_ssse3(void)
{
    return _cpu_features.has_ssse3;
}

int
SLSodium_runtime_has_sse41(void)
{
    return _cpu_features.has_sse41;
}

int
SLSodium_runtime_has_avx(void)
{
    return _cpu_features.has_avx;
}

int
SLSodium_runtime_has_avx2(void)
{
    return _cpu_features.has_avx2;
}

int
SLSodium_runtime_has_pclmul(void)
{
    return _cpu_features.has_pclmul;
}

int
SLSodium_runtime_has_aesni(void)
{
    return _cpu_features.has_aesni;
}

#endif /* USE_SL_CHACHA20_POLY1305_IETF || USE_SL_SODIUM */
