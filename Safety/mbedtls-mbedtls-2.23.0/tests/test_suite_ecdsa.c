#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_ecdsa.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : suites/main_test.function
 *      Platform code file  : suites/host_test.function
 *      Helper file         : suites/helpers.function
 *      Test suite file     : suites/test_suite_ecdsa.function
 *      Test suite data     : suites/test_suite_ecdsa.data
 *
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L // for fileno() from <stdio.h>
#endif
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

/* Test code may use deprecated identifiers only if the preprocessor symbol
 * MBEDTLS_TEST_DEPRECATED is defined. When building tests, set
 * MBEDTLS_TEST_DEPRECATED explicitly if MBEDTLS_DEPRECATED_WARNING is
 * enabled but the corresponding warnings are not treated as errors.
 */
#if !defined(MBEDTLS_DEPRECATED_REMOVED) && !defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_TEST_DEPRECATED
#endif

/*----------------------------------------------------------------------------*/
/* Common helper code */

#line 2 "suites/helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <test/macros.h>
#include <test/helpers.h>
#include <test/random.h>

#include <stdlib.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#if defined(MBEDTLS_CHECK_PARAMS)
#include "mbedtls/platform_util.h"
#include <setjmp.h>
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT8 uint8_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#include <stdint.h>
#endif

#include <string.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#include <strings.h>
#endif

/* Type for Hex parameters */
typedef struct data_tag
{
    uint8_t *   x;
    uint32_t    len;
} data_t;

/*----------------------------------------------------------------------------*/
/* Status and error constants */

#define DEPENDENCY_SUPPORTED            0   /* Dependency supported by build */
#define KEY_VALUE_MAPPING_FOUND         0   /* Integer expression found */
#define DISPATCH_TEST_SUCCESS           0   /* Test dispatch successful */

#define KEY_VALUE_MAPPING_NOT_FOUND     -1  /* Integer expression not found */
#define DEPENDENCY_NOT_SUPPORTED        -2  /* Dependency not supported */
#define DISPATCH_TEST_FN_NOT_FOUND      -3  /* Test function not found */
#define DISPATCH_INVALID_TEST_DATA      -4  /* Invalid test parameter type.
                                               Only int, string, binary data
                                               and integer expressions are
                                               allowed */
#define DISPATCH_UNSUPPORTED_SUITE      -5  /* Test suite not supported by the
                                               build */

typedef enum
{
    PARAMFAIL_TESTSTATE_IDLE = 0,           /* No parameter failure call test */
    PARAMFAIL_TESTSTATE_PENDING,            /* Test call to the parameter failure
                                             * is pending */
    PARAMFAIL_TESTSTATE_CALLED              /* The test call to the parameter
                                             * failure function has been made */
} paramfail_test_state_t;


/*----------------------------------------------------------------------------*/
/* Macros */

/**
 * \brief   This macro tests the expression passed to it as a test step or
 *          individual test in a test case.
 *
 *          It allows a library function to return a value and return an error
 *          code that can be tested.
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), will be assumed to be a test
 *          failure.
 *
 *          This macro is not suitable for negative parameter validation tests,
 *          as it assumes the test step will not create an error.
 *
 *          Failing the test means:
 *          - Mark this test case as failed.
 *          - Print a message identifying the failure.
 *          - Jump to the \c exit label.
 *
 *          This macro expands to an instruction, not an expression.
 *          It may jump to the \c exit label.
 *
 * \param   TEST    The test expression to be tested.
 */
#define TEST_ASSERT( TEST )                                 \
    do {                                                    \
       if( ! (TEST) )                                       \
       {                                                    \
          test_fail( #TEST, __LINE__, __FILE__ );           \
          goto exit;                                        \
       }                                                    \
    } while( 0 )

/** Evaluate two expressions and fail the test case if they have different
 * values.
 *
 * \param expr1     An expression to evaluate.
 * \param expr2     The expected value of \p expr1. This can be any
 *                  expression, but it is typically a constant.
 */
#define TEST_EQUAL( expr1, expr2 )              \
    TEST_ASSERT( ( expr1 ) == ( expr2 ) )

/** Allocate memory dynamically and fail the test case if this fails.
 *
 * You must set \p pointer to \c NULL before calling this macro and
 * put `mbedtls_free( pointer )` in the test's cleanup code.
 *
 * If \p length is zero, the resulting \p pointer will be \c NULL.
 * This is usually what we want in tests since API functions are
 * supposed to accept null pointers when a buffer size is zero.
 *
 * This macro expands to an instruction, not an expression.
 * It may jump to the \c exit label.
 *
 * \param pointer   An lvalue where the address of the allocated buffer
 *                  will be stored.
 *                  This expression may be evaluated multiple times.
 * \param length    Number of elements to allocate.
 *                  This expression may be evaluated multiple times.
 *
 */
#define ASSERT_ALLOC( pointer, length )                           \
    do                                                            \
    {                                                             \
        TEST_ASSERT( ( pointer ) == NULL );                       \
        if( ( length ) != 0 )                                     \
        {                                                         \
            ( pointer ) = mbedtls_calloc( sizeof( *( pointer ) ), \
                                          ( length ) );           \
            TEST_ASSERT( ( pointer ) != NULL );                   \
        }                                                         \
    }                                                             \
    while( 0 )

/** Allocate memory dynamically. If the allocation fails, skip the test case.
 *
 * This macro behaves like #ASSERT_ALLOC, except that if the allocation
 * fails, it marks the test as skipped rather than failed.
 */
#define ASSERT_ALLOC_WEAK( pointer, length )                      \
    do                                                            \
    {                                                             \
        TEST_ASSERT( ( pointer ) == NULL );                       \
        if( ( length ) != 0 )                                     \
        {                                                         \
            ( pointer ) = mbedtls_calloc( sizeof( *( pointer ) ), \
                                          ( length ) );           \
            TEST_ASSUME( ( pointer ) != NULL );                   \
        }                                                         \
    }                                                             \
    while( 0 )

/** Compare two buffers and fail the test case if they differ.
 *
 * This macro expands to an instruction, not an expression.
 * It may jump to the \c exit label.
 *
 * \param p1        Pointer to the start of the first buffer.
 * \param size1     Size of the first buffer in bytes.
 *                  This expression may be evaluated multiple times.
 * \param p2        Pointer to the start of the second buffer.
 * \param size2     Size of the second buffer in bytes.
 *                  This expression may be evaluated multiple times.
 */
#define ASSERT_COMPARE( p1, size1, p2, size2 )                          \
    do                                                                  \
    {                                                                   \
        TEST_ASSERT( ( size1 ) == ( size2 ) );                          \
        if( ( size1 ) != 0 )                                            \
            TEST_ASSERT( memcmp( ( p1 ), ( p2 ), ( size1 ) ) == 0 );    \
    }                                                                   \
    while( 0 )

/**
 * \brief   This macro tests the expression passed to it and skips the
 *          running test if it doesn't evaluate to 'true'.
 *
 * \param   TEST    The test expression to be tested.
 */
#define TEST_ASSUME( TEST )                         \
    do {                                            \
        if( ! (TEST) )                              \
        {                                           \
            test_skip( #TEST, __LINE__, __FILE__ ); \
            goto exit;                              \
        }                                           \
    } while( 0 )

#if defined(MBEDTLS_CHECK_PARAMS) && !defined(MBEDTLS_PARAM_FAILED_ALT)
/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will fail
 *          and will generate an error.
 *
 *          It allows a library function to return a value and tests the return
 *          code on return to confirm the given error code was returned.
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure, and the test will pass.
 *
 *          This macro is intended for negative parameter validation tests,
 *          where the failing function may return an error value or call
 *          MBEDTLS_PARAM_FAILED() to indicate the error.
 *
 * \param   PARAM_ERROR_VALUE   The expected error code.
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_INVALID_PARAM_RET( PARAM_ERR_VALUE, TEST )                     \
    do {                                                                    \
        test_info.paramfail_test_state = PARAMFAIL_TESTSTATE_PENDING;       \
        if( (TEST) != (PARAM_ERR_VALUE) ||                                  \
            test_info.paramfail_test_state != PARAMFAIL_TESTSTATE_CALLED )  \
        {                                                                   \
            test_fail( #TEST, __LINE__, __FILE__ );                         \
            goto exit;                                                      \
        }                                                                   \
   } while( 0 )

/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will fail
 *          and will generate an error.
 *
 *          It assumes the library function under test cannot return a value and
 *          assumes errors can only be indicated byt calls to
 *          MBEDTLS_PARAM_FAILED().
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure. If MBEDTLS_CHECK_PARAMS is not enabled, no test
 *          can be made.
 *
 *          This macro is intended for negative parameter validation tests,
 *          where the failing function can only return an error by calling
 *          MBEDTLS_PARAM_FAILED() to indicate the error.
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_INVALID_PARAM( TEST )                                          \
    do {                                                                    \
        memcpy(jmp_tmp, param_fail_jmp, sizeof(jmp_buf));                   \
        if( setjmp( param_fail_jmp ) == 0 )                                 \
        {                                                                   \
            TEST;                                                           \
            test_fail( #TEST, __LINE__, __FILE__ );                         \
            goto exit;                                                      \
        }                                                                   \
        memcpy(param_fail_jmp, jmp_tmp, sizeof(jmp_buf));                   \
    } while( 0 )
#endif /* MBEDTLS_CHECK_PARAMS && !MBEDTLS_PARAM_FAILED_ALT */

/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will not fail.
 *
 *          It assumes the library function under test cannot return a value and
 *          assumes errors can only be indicated by calls to
 *          MBEDTLS_PARAM_FAILED().
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure. If MBEDTLS_CHECK_PARAMS is not enabled, no test
 *          can be made.
 *
 *          This macro is intended to test that functions returning void
 *          accept all of the parameter values they're supposed to accept - eg
 *          that they don't call MBEDTLS_PARAM_FAILED() when a parameter
 *          that's allowed to be NULL happens to be NULL.
 *
 *          Note: for functions that return something other that void,
 *          checking that they accept all the parameters they're supposed to
 *          accept is best done by using TEST_ASSERT() and checking the return
 *          value as well.
 *
 *          Note: this macro is available even when #MBEDTLS_CHECK_PARAMS is
 *          disabled, as it makes sense to check that the functions accept all
 *          legal values even if this option is disabled - only in that case,
 *          the test is more about whether the function segfaults than about
 *          whether it invokes MBEDTLS_PARAM_FAILED().
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_VALID_PARAM( TEST )                                    \
    TEST_ASSERT( ( TEST, 1 ) );

/** Allocate memory dynamically and fail the test case if this fails.
 *
 * You must set \p pointer to \c NULL before calling this macro and
 * put `mbedtls_free( pointer )` in the test's cleanup code.
 *
 * If \p length is zero, the resulting \p pointer will be \c NULL.
 * This is usually what we want in tests since API functions are
 * supposed to accept null pointers when a buffer size is zero.
 *
 * This macro expands to an instruction, not an expression.
 * It may jump to the \c exit label.
 *
 * \param pointer   An lvalue where the address of the allocated buffer
 *                  will be stored.
 *                  This expression may be evaluated multiple times.
 * \param length    Number of elements to allocate.
 *                  This expression may be evaluated multiple times.
 *
 */
#define ASSERT_ALLOC( pointer, length )                           \
    do                                                            \
    {                                                             \
        TEST_ASSERT( ( pointer ) == NULL );                       \
        if( ( length ) != 0 )                                     \
        {                                                         \
            ( pointer ) = mbedtls_calloc( sizeof( *( pointer ) ), \
                                          ( length ) );           \
            TEST_ASSERT( ( pointer ) != NULL );                   \
        }                                                         \
    }                                                             \
    while( 0 )

/*----------------------------------------------------------------------------*/
/* Global variables */

typedef enum
{
    TEST_RESULT_SUCCESS = 0,
    TEST_RESULT_FAILED,
    TEST_RESULT_SKIPPED
} test_result_t;

typedef struct
{
    paramfail_test_state_t paramfail_test_state;
    test_result_t result;
    const char *test;
    const char *filename;
    int line_no;
    unsigned long step;
}
test_info_t;
static test_info_t test_info;

#if defined(MBEDTLS_CHECK_PARAMS)
jmp_buf param_fail_jmp;
jmp_buf jmp_tmp;
#endif

/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if defined(MBEDTLS_TEST_NULL_ENTROPY) ||             \
    ( !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
      ( !defined(MBEDTLS_NO_PLATFORM_ENTROPY)  ||     \
         defined(MBEDTLS_HAVEGE_C)             ||     \
         defined(MBEDTLS_ENTROPY_HARDWARE_ALT) ||     \
         defined(ENTROPY_NV_SEED) ) )
#define ENTROPY_HAVE_STRONG
#endif


/*----------------------------------------------------------------------------*/
/* Helper Functions */

/** Set the test step number for failure reports.
 *
 * Call this function to display "step NNN" in addition to the line number
 * and file name if a test fails. Typically the "step number" is the index
 * of a for loop but it can be whatever you want.
 *
 * \param step  The step number to report.
 */
void test_set_step( unsigned long step )
{
    test_info.step = step;
}

void test_fail( const char *test, int line_no, const char* filename )
{
    test_info.result = TEST_RESULT_FAILED;
    test_info.test = test;
    test_info.line_no = line_no;
    test_info.filename = filename;
}

void test_skip( const char *test, int line_no, const char* filename )
{
    test_info.result = TEST_RESULT_SKIPPED;
    test_info.test = test;
    test_info.line_no = line_no;
    test_info.filename = filename;
}

#if defined(MBEDTLS_CHECK_PARAMS)
void mbedtls_param_failed( const char *failure_condition,
                           const char *file,
                           int line )
{
    /* If we are testing the callback function...  */
    if( test_info.paramfail_test_state == PARAMFAIL_TESTSTATE_PENDING )
    {
        test_info.paramfail_test_state = PARAMFAIL_TESTSTATE_CALLED;
    }
    else
    {
        /* ...else we treat this as an error */

        /* Record the location of the failure, but not as a failure yet, in case
         * it was part of the test */
        test_fail( failure_condition, line, file );
        test_info.result = TEST_RESULT_SUCCESS;

        longjmp( param_fail_jmp, 1 );
    }
}
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output( FILE** out_stream, const char* path )
{
    int stdout_fd = dup( fileno( *out_stream ) );

    if( stdout_fd == -1 )
    {
        return -1;
    }

    fflush( *out_stream );
    fclose( *out_stream );
    *out_stream = fopen( path, "w" );

    if( *out_stream == NULL )
    {
        close( stdout_fd );
        return -1;
    }

    return stdout_fd;
}

static int restore_output( FILE** out_stream, int old_fd )
{
    fflush( *out_stream );
    fclose( *out_stream );

    *out_stream = fdopen( old_fd, "w" );
    if( *out_stream == NULL )
    {
        return -1;
    }

    return 0;
}

static void close_output( FILE* out_stream )
{
    fclose( out_stream );
}
#endif /* __unix__ || __APPLE__ __MACH__ */


#line 53 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test Suite Code */


#define TEST_SUITE_ACTIVE

#if defined(MBEDTLS_ECDSA_C)
#line 2 "suites/test_suite_ecdsa.function"
#include "mbedtls/ecdsa.h"
#if defined(MBEDTLS_CHECK_PARAMS)
#if !defined(MBEDTLS_PARAM_FAILED_ALT)
#line 11 "suites/test_suite_ecdsa.function"
void test_ecdsa_invalid_param( )
{
    mbedtls_ecdsa_context ctx;
    mbedtls_ecp_keypair key;
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_id valid_group = MBEDTLS_ECP_DP_SECP192R1;
    mbedtls_ecp_point P;
    mbedtls_md_type_t valid_md = MBEDTLS_MD_SHA256;
    mbedtls_mpi m;
    size_t slen;
    unsigned char buf[42] = { 0 };

    TEST_INVALID_PARAM( mbedtls_ecdsa_init( NULL ) );
    TEST_VALID_PARAM( mbedtls_ecdsa_free( NULL ) );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    TEST_INVALID_PARAM( mbedtls_ecdsa_restart_init( NULL ) );
    TEST_VALID_PARAM( mbedtls_ecdsa_restart_free( NULL ) );
#endif /* MBEDTLS_ECP_RESTARTABLE */

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecdsa_sign( NULL, &m, &m, &m,
                                                buf, sizeof( buf ),
                                                mbedtls_test_rnd_std_rand,
                                                NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecdsa_sign( &grp, NULL, &m, &m,
                                                buf, sizeof( buf ),
                                                mbedtls_test_rnd_std_rand,
                                                NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_sign( &grp, &m, NULL, &m,
                                                buf, sizeof( buf ),
                                                mbedtls_test_rnd_std_rand,
                                                NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_sign( &grp, &m, &m, NULL,
                                                buf, sizeof( buf ),
                                                mbedtls_test_rnd_std_rand,
                                                NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_sign( &grp, &m, &m, &m,
                                                NULL, sizeof( buf ),
                                                mbedtls_test_rnd_std_rand,
                                                NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_sign( &grp, &m, &m, &m,
                                                buf, sizeof( buf ),
                                                NULL, NULL ) );

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_sign_det_ext( NULL, &m, &m, &m,
                                                   buf, sizeof( buf ),
                                                   valid_md,
                                                   mbedtls_test_rnd_std_rand,
                                                   NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_sign_det_ext( &grp, NULL, &m, &m,
                                                   buf, sizeof( buf ),
                                                   valid_md,
                                                   mbedtls_test_rnd_std_rand,
                                                   NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_sign_det_ext( &grp, &m, NULL, &m,
                                                   buf, sizeof( buf ),
                                                   valid_md,
                                                   mbedtls_test_rnd_std_rand,
                                                   NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_sign_det_ext( &grp, &m, &m, NULL,
                                                   buf, sizeof( buf ),
                                                   valid_md,
                                                   mbedtls_test_rnd_std_rand,
                                                   NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_sign_det_ext( &grp, &m, &m, &m,
                                                   NULL, sizeof( buf ),
                                                   valid_md,
                                                   mbedtls_test_rnd_std_rand,
                                                   NULL ) );
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_verify( NULL,
                                                  buf, sizeof( buf ),
                                                  &P, &m, &m ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_verify( &grp,
                                                  NULL, sizeof( buf ),
                                                  &P, &m, &m ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_verify( &grp,
                                                  buf, sizeof( buf ),
                                                  NULL, &m, &m ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_verify( &grp,
                                                  buf, sizeof( buf ),
                                                  &P, NULL, &m ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_verify( &grp,
                                                  buf, sizeof( buf ),
                                                  &P, &m, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
         mbedtls_ecdsa_write_signature( NULL, valid_md, buf, sizeof( buf ),
                                        buf, &slen, mbedtls_test_rnd_std_rand,
                                        NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
         mbedtls_ecdsa_write_signature( &ctx, valid_md, NULL, sizeof( buf ),
                                        buf, &slen, mbedtls_test_rnd_std_rand,
                                        NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
         mbedtls_ecdsa_write_signature( &ctx, valid_md, buf, sizeof( buf ),
                                        NULL, &slen, mbedtls_test_rnd_std_rand,
                                        NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
         mbedtls_ecdsa_write_signature( &ctx, valid_md, buf, sizeof( buf ),
                                        buf, NULL, mbedtls_test_rnd_std_rand,
                                        NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
         mbedtls_ecdsa_write_signature_restartable( NULL, valid_md, buf,
                                                    sizeof( buf ), buf, &slen,
                                                    mbedtls_test_rnd_std_rand,
                                                    NULL, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
         mbedtls_ecdsa_write_signature_restartable( &ctx, valid_md, NULL,
                                                    sizeof( buf ), buf, &slen,
                                                    mbedtls_test_rnd_std_rand,
                                                    NULL, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
         mbedtls_ecdsa_write_signature_restartable( &ctx, valid_md, buf,
                                                    sizeof( buf ), NULL, &slen,
                                                    mbedtls_test_rnd_std_rand,
                                                    NULL, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
         mbedtls_ecdsa_write_signature_restartable( &ctx, valid_md, buf,
                                                    sizeof( buf ), buf, NULL,
                                                    mbedtls_test_rnd_std_rand,
                                                    NULL, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_read_signature( NULL,
                                                        buf, sizeof( buf ),
                                                        buf, sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_read_signature( &ctx,
                                                        NULL, sizeof( buf ),
                                                        buf, sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_read_signature( &ctx,
                                                        buf, sizeof( buf ),
                                                        NULL, sizeof( buf ) ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_read_signature_restartable( NULL,
                                                        buf, sizeof( buf ),
                                                        buf, sizeof( buf ),
                                                        NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_read_signature_restartable( &ctx,
                                                        NULL, sizeof( buf ),
                                                        buf, sizeof( buf ),
                                                        NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_read_signature_restartable( &ctx,
                                                        buf, sizeof( buf ),
                                                        NULL, sizeof( buf ),
                                                        NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_genkey( NULL, valid_group,
                                             mbedtls_test_rnd_std_rand,
                                             NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_genkey( &ctx, valid_group,
                                                  NULL, NULL ) );


    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_from_keypair( NULL, &key ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                       mbedtls_ecdsa_from_keypair( &ctx, NULL ) );

exit:
    return;
}

void test_ecdsa_invalid_param_wrapper( void ** params )
{
    (void)params;

    test_ecdsa_invalid_param(  );
}
#endif /* !MBEDTLS_PARAM_FAILED_ALT */
#endif /* MBEDTLS_CHECK_PARAMS */
#line 208 "suites/test_suite_ecdsa.function"
void test_ecdsa_prim_random( int id )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s;
    mbedtls_test_rnd_pseudo_info rnd_info;
    unsigned char buf[MBEDTLS_MD_MAX_SIZE];

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &Q );
    mbedtls_mpi_init( &d ); mbedtls_mpi_init( &r ); mbedtls_mpi_init( &s );
    memset( &rnd_info, 0x00, sizeof( mbedtls_test_rnd_pseudo_info ) );
    memset( buf, 0, sizeof( buf ) );

    /* prepare material for signature */
    TEST_ASSERT( mbedtls_test_rnd_pseudo_rand( &rnd_info,
                                               buf, sizeof( buf ) ) == 0 );
    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );
    TEST_ASSERT( mbedtls_ecp_gen_keypair( &grp, &d, &Q,
                                          &mbedtls_test_rnd_pseudo_rand,
                                          &rnd_info ) == 0 );

    TEST_ASSERT( mbedtls_ecdsa_sign( &grp, &r, &s, &d, buf, sizeof( buf ),
                                     &mbedtls_test_rnd_pseudo_rand,
                                     &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_ecdsa_verify( &grp, buf, sizeof( buf ), &Q, &r, &s ) == 0 );

exit:
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &Q );
    mbedtls_mpi_free( &d ); mbedtls_mpi_free( &r ); mbedtls_mpi_free( &s );
}

void test_ecdsa_prim_random_wrapper( void ** params )
{

    test_ecdsa_prim_random( *( (int *) params[0] ) );
}
#line 243 "suites/test_suite_ecdsa.function"
void test_ecdsa_prim_test_vectors( int id, char * d_str, char * xQ_str,
                              char * yQ_str, data_t * rnd_buf,
                              data_t * hash, char * r_str, char * s_str,
                              int result )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s, r_check, s_check;
    mbedtls_test_rnd_buf_info rnd_info;

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &Q );
    mbedtls_mpi_init( &d ); mbedtls_mpi_init( &r ); mbedtls_mpi_init( &s );
    mbedtls_mpi_init( &r_check ); mbedtls_mpi_init( &s_check );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );
    TEST_ASSERT( mbedtls_ecp_point_read_string( &Q, 16, xQ_str, yQ_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &d, 16, d_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &r_check, 16, r_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &s_check, 16, s_str ) == 0 );
    rnd_info.buf = rnd_buf->x;
    rnd_info.length = rnd_buf->len;

    /* Fix rnd_buf->x by shifting it left if necessary */
    if( grp.nbits % 8 != 0 )
    {
        unsigned char shift = 8 - ( grp.nbits % 8 );
        size_t i;

        for( i = 0; i < rnd_info.length - 1; i++ )
            rnd_buf->x[i] = rnd_buf->x[i] << shift | rnd_buf->x[i+1] >> ( 8 - shift );

        rnd_buf->x[rnd_info.length-1] <<= shift;
    }

    TEST_ASSERT( mbedtls_ecdsa_sign( &grp, &r, &s, &d, hash->x, hash->len,
                 mbedtls_test_rnd_buffer_rand, &rnd_info ) == result );

    if ( result == 0)
    {
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &r, &r_check ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &s, &s_check ) == 0 );

        TEST_ASSERT( mbedtls_ecdsa_verify( &grp, hash->x, hash->len, &Q, &r_check, &s_check ) == 0 );

        TEST_ASSERT( mbedtls_mpi_sub_int( &r, &r, 1 ) == 0 );
        TEST_ASSERT( mbedtls_mpi_add_int( &s, &s, 1 ) == 0 );

        TEST_ASSERT( mbedtls_ecdsa_verify( &grp, hash->x, hash->len,
                     &Q, &r, &s_check ) == MBEDTLS_ERR_ECP_VERIFY_FAILED );
        TEST_ASSERT( mbedtls_ecdsa_verify( &grp, hash->x, hash->len,
                     &Q, &r_check, &s ) == MBEDTLS_ERR_ECP_VERIFY_FAILED );
        TEST_ASSERT( mbedtls_ecdsa_verify( &grp, hash->x, hash->len,
                     &grp.G, &r_check, &s_check ) == MBEDTLS_ERR_ECP_VERIFY_FAILED );
    }

exit:
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &Q );
    mbedtls_mpi_free( &d ); mbedtls_mpi_free( &r ); mbedtls_mpi_free( &s );
    mbedtls_mpi_free( &r_check ); mbedtls_mpi_free( &s_check );
}

void test_ecdsa_prim_test_vectors_wrapper( void ** params )
{
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_ecdsa_prim_test_vectors( *( (int *) params[0] ), (char *) params[1], (char *) params[2], (char *) params[3], &data4, &data6, (char *) params[8], (char *) params[9], *( (int *) params[10] ) );
}
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#line 308 "suites/test_suite_ecdsa.function"
void test_ecdsa_det_test_vectors( int id, char * d_str, int md_alg, char * msg,
                             char * r_str, char * s_str )
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s, r_check, s_check;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    size_t hlen;
    const mbedtls_md_info_t *md_info;

    mbedtls_ecp_group_init( &grp );
    mbedtls_mpi_init( &d ); mbedtls_mpi_init( &r ); mbedtls_mpi_init( &s );
    mbedtls_mpi_init( &r_check ); mbedtls_mpi_init( &s_check );
    memset( hash, 0, sizeof( hash ) );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &d, 16, d_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &r_check, 16, r_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &s_check, 16, s_str ) == 0 );

    md_info = mbedtls_md_info_from_type( md_alg );
    TEST_ASSERT( md_info != NULL );
    hlen = mbedtls_md_get_size( md_info );
    TEST_ASSERT( mbedtls_md( md_info, (const unsigned char *) msg,
                 strlen( msg ), hash ) == 0 );

    TEST_ASSERT(
                mbedtls_ecdsa_sign_det_ext( &grp, &r, &s, &d, hash, hlen,
                                            md_alg, mbedtls_test_rnd_std_rand,
                                            NULL )
                == 0 );

    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &r, &r_check ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &s, &s_check ) == 0 );

exit:
    mbedtls_ecp_group_free( &grp );
    mbedtls_mpi_free( &d ); mbedtls_mpi_free( &r ); mbedtls_mpi_free( &s );
    mbedtls_mpi_free( &r_check ); mbedtls_mpi_free( &s_check );
}

void test_ecdsa_det_test_vectors_wrapper( void ** params )
{

    test_ecdsa_det_test_vectors( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], (char *) params[4], (char *) params[5] );
}
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */
#if defined(MBEDTLS_SHA256_C)
#line 350 "suites/test_suite_ecdsa.function"
void test_ecdsa_write_read_random( int id )
{
    mbedtls_ecdsa_context ctx;
    mbedtls_test_rnd_pseudo_info rnd_info;
    unsigned char hash[32];
    unsigned char sig[200];
    size_t sig_len, i;

    mbedtls_ecdsa_init( &ctx );
    memset( &rnd_info, 0x00, sizeof( mbedtls_test_rnd_pseudo_info ) );
    memset( hash, 0, sizeof( hash ) );
    memset( sig, 0x2a, sizeof( sig ) );

    /* prepare material for signature */
    TEST_ASSERT( mbedtls_test_rnd_pseudo_rand( &rnd_info,
                                               hash, sizeof( hash ) ) == 0 );

    /* generate signing key */
    TEST_ASSERT( mbedtls_ecdsa_genkey( &ctx, id,
                                       &mbedtls_test_rnd_pseudo_rand,
                                       &rnd_info ) == 0 );

    /* generate and write signature, then read and verify it */
    TEST_ASSERT( mbedtls_ecdsa_write_signature( &ctx, MBEDTLS_MD_SHA256,
                 hash, sizeof( hash ),
                 sig, &sig_len, &mbedtls_test_rnd_pseudo_rand,
                 &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len ) == 0 );

    /* check we didn't write past the announced length */
    for( i = sig_len; i < sizeof( sig ); i++ )
        TEST_ASSERT( sig[i] == 0x2a );

    /* try verification with invalid length */
    TEST_ASSERT( mbedtls_ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len - 1 ) != 0 );
    TEST_ASSERT( mbedtls_ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len + 1 ) != 0 );

    /* try invalid sequence tag */
    sig[0]++;
    TEST_ASSERT( mbedtls_ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len ) != 0 );
    sig[0]--;

    /* try modifying r */
    sig[10]++;
    TEST_ASSERT( mbedtls_ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len ) == MBEDTLS_ERR_ECP_VERIFY_FAILED );
    sig[10]--;

    /* try modifying s */
    sig[sig_len - 1]++;
    TEST_ASSERT( mbedtls_ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len ) == MBEDTLS_ERR_ECP_VERIFY_FAILED );
    sig[sig_len - 1]--;

exit:
    mbedtls_ecdsa_free( &ctx );
}

void test_ecdsa_write_read_random_wrapper( void ** params )
{

    test_ecdsa_write_read_random( *( (int *) params[0] ) );
}
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_ECP_RESTARTABLE)
#line 414 "suites/test_suite_ecdsa.function"
void test_ecdsa_read_restart( int id, char *k_str, char *h_str, char *s_str,
                         int max_ops, int min_restart, int max_restart )
{
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_restart_ctx rs_ctx;
    unsigned char hash[64];
    unsigned char sig[200];
    unsigned char pk[65];
    size_t sig_len, hash_len, pk_len;
    int ret, cnt_restart;

    mbedtls_ecdsa_init( &ctx );
    mbedtls_ecdsa_restart_init( &rs_ctx );

    hash_len = mbedtls_test_unhexify(hash, h_str);
    sig_len = mbedtls_test_unhexify(sig, s_str);
    pk_len = mbedtls_test_unhexify(pk, k_str);

    TEST_ASSERT( mbedtls_ecp_group_load( &ctx.grp, id ) == 0 );
    TEST_ASSERT( mbedtls_ecp_point_read_binary( &ctx.grp, &ctx.Q, pk, pk_len ) == 0 );

    mbedtls_ecp_set_max_ops( max_ops );

    cnt_restart = 0;
    do {
        ret = mbedtls_ecdsa_read_signature_restartable( &ctx,
                            hash, hash_len, sig, sig_len, &rs_ctx );
    } while( ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restart );

    TEST_ASSERT( ret == 0 );
    TEST_ASSERT( cnt_restart >= min_restart );
    TEST_ASSERT( cnt_restart <= max_restart );

    /* try modifying r */
    sig[10]++;
    do {
        ret = mbedtls_ecdsa_read_signature_restartable( &ctx,
                            hash, hash_len, sig, sig_len, &rs_ctx );
    } while( ret == MBEDTLS_ERR_ECP_IN_PROGRESS );
    TEST_ASSERT( ret == MBEDTLS_ERR_ECP_VERIFY_FAILED );
    sig[10]--;

    /* try modifying s */
    sig[sig_len - 1]++;
    do {
        ret = mbedtls_ecdsa_read_signature_restartable( &ctx,
                            hash, hash_len, sig, sig_len, &rs_ctx );
    } while( ret == MBEDTLS_ERR_ECP_IN_PROGRESS );
    TEST_ASSERT( ret == MBEDTLS_ERR_ECP_VERIFY_FAILED );
    sig[sig_len - 1]--;

    /* Do we leak memory when aborting an operation?
     * This test only makes sense when we actually restart */
    if( min_restart > 0 )
    {
        ret = mbedtls_ecdsa_read_signature_restartable( &ctx,
                            hash, hash_len, sig, sig_len, &rs_ctx );
        TEST_ASSERT( ret == MBEDTLS_ERR_ECP_IN_PROGRESS );
    }

exit:
    mbedtls_ecdsa_free( &ctx );
    mbedtls_ecdsa_restart_free( &rs_ctx );
}

void test_ecdsa_read_restart_wrapper( void ** params )
{

    test_ecdsa_read_restart( *( (int *) params[0] ), (char *) params[1], (char *) params[2], (char *) params[3], *( (int *) params[4] ), *( (int *) params[5] ), *( (int *) params[6] ) );
}
#endif /* MBEDTLS_ECP_RESTARTABLE */
#if defined(MBEDTLS_ECP_RESTARTABLE)
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#line 481 "suites/test_suite_ecdsa.function"
void test_ecdsa_write_restart( int id, char *d_str, int md_alg,
                          char *msg, char *sig_str,
                          int max_ops, int min_restart, int max_restart )
{
    int ret, cnt_restart;
    mbedtls_ecdsa_restart_ctx rs_ctx;
    mbedtls_ecdsa_context ctx;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char sig_check[MBEDTLS_ECDSA_MAX_LEN];
    size_t hlen, slen, slen_check;
    const mbedtls_md_info_t *md_info;

    mbedtls_ecdsa_restart_init( &rs_ctx );
    mbedtls_ecdsa_init( &ctx );
    memset( hash, 0, sizeof( hash ) );
    memset( sig, 0, sizeof( sig ) );
    memset( sig_check, 0, sizeof( sig_check ) );

    TEST_ASSERT( mbedtls_ecp_group_load( &ctx.grp, id ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.d, 16, d_str ) == 0 );
    slen_check = mbedtls_test_unhexify( sig_check, sig_str );

    md_info = mbedtls_md_info_from_type( md_alg );
    TEST_ASSERT( md_info != NULL );

    hlen = mbedtls_md_get_size( md_info );
    TEST_ASSERT( mbedtls_md( md_info,
                             (const unsigned char *) msg, strlen( msg ),
                             hash ) == 0 );

    mbedtls_ecp_set_max_ops( max_ops );

    slen = sizeof( sig );
    cnt_restart = 0;
    do {
        ret = mbedtls_ecdsa_write_signature_restartable( &ctx,
                md_alg, hash, hlen, sig, &slen, NULL, NULL, &rs_ctx );
    } while( ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restart );

    TEST_ASSERT( ret == 0 );
    TEST_ASSERT( slen == slen_check );
    TEST_ASSERT( memcmp( sig, sig_check, slen ) == 0 );

    TEST_ASSERT( cnt_restart >= min_restart );
    TEST_ASSERT( cnt_restart <= max_restart );

    /* Do we leak memory when aborting an operation?
     * This test only makes sense when we actually restart */
    if( min_restart > 0 )
    {
        ret = mbedtls_ecdsa_write_signature_restartable( &ctx,
                md_alg, hash, hlen, sig, &slen, NULL, NULL, &rs_ctx );
        TEST_ASSERT( ret == MBEDTLS_ERR_ECP_IN_PROGRESS );
    }

exit:
    mbedtls_ecdsa_restart_free( &rs_ctx );
    mbedtls_ecdsa_free( &ctx );
}

void test_ecdsa_write_restart_wrapper( void ** params )
{

    test_ecdsa_write_restart( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ), (char *) params[3], (char *) params[4], *( (int *) params[5] ), *( (int *) params[6] ), *( (int *) params[7] ) );
}
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */
#endif /* MBEDTLS_ECP_RESTARTABLE */
#endif /* MBEDTLS_ECDSA_C */


#line 64 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */


/**
 * \brief       Evaluates an expression/macro into its literal integer value.
 *              For optimizing space for embedded targets each expression/macro
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and evaluation code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Expression identifier.
 * \param out_value Pointer to int to hold the integer.
 *
 * \return       0 if exp_id is found. 1 otherwise.
 */
int get_expression( int32_t exp_id, int32_t * out_value )
{
    int ret = KEY_VALUE_MAPPING_FOUND;

    (void) exp_id;
    (void) out_value;

    switch( exp_id )
    {

#if defined(MBEDTLS_ECDSA_C)

        case 0:
            {
                *out_value = MBEDTLS_ECP_DP_SECP192R1;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_ECP_DP_SECP224R1;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_ECP_DP_SECP256R1;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_ECP_DP_SECP384R1;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_ECP_DP_SECP521R1;
            }
            break;
        case 5:
            {
                *out_value = MBEDTLS_MD_SHA1;
            }
            break;
        case 6:
            {
                *out_value = MBEDTLS_MD_SHA224;
            }
            break;
        case 7:
            {
                *out_value = MBEDTLS_MD_SHA256;
            }
            break;
        case 8:
            {
                *out_value = MBEDTLS_MD_SHA384;
            }
            break;
        case 9:
            {
                *out_value = MBEDTLS_MD_SHA512;
            }
            break;
        case 10:
            {
                *out_value = MBEDTLS_ERR_ECP_INVALID_KEY;
            }
            break;
#endif

#line 93 "suites/main_test.function"
        default:
           {
                ret = KEY_VALUE_MAPPING_NOT_FOUND;
           }
           break;
    }
    return( ret );
}


/**
 * \brief       Checks if the dependency i.e. the compile flag is set.
 *              For optimizing space for embedded targets each dependency
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and check code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Dependency identifier.
 *
 * \return       DEPENDENCY_SUPPORTED if set else DEPENDENCY_NOT_SUPPORTED
 */
int dep_check( int dep_id )
{
    int ret = DEPENDENCY_NOT_SUPPORTED;

    (void) dep_id;

    switch( dep_id )
    {

#if defined(MBEDTLS_ECDSA_C)

        case 0:
            {
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 3:
            {
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 4:
            {
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 5:
            {
#if defined(MBEDTLS_SHA1_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 6:
            {
#if defined(MBEDTLS_SHA256_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 7:
            {
#if defined(MBEDTLS_SHA512_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 8:
            {
#if !defined(MBEDTLS_SHA512_NO_SHA384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
#endif

#line 124 "suites/main_test.function"
        default:
            break;
    }
    return( ret );
}


/**
 * \brief       Function pointer type for test function wrappers.
 *
 *
 * \param void **   Pointer to void pointers. Represents an array of test
 *                  function parameters.
 *
 * \return       void
 */
typedef void (*TestWrapper_t)( void ** );


/**
 * \brief       Table of test function wrappers. Used by dispatch_test().
 *              This table is populated by script:
 *              generate_test_code.py
 *
 */
TestWrapper_t test_funcs[] =
{
/* Function Id: 0 */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_CHECK_PARAMS) && !defined(MBEDTLS_PARAM_FAILED_ALT)
    test_ecdsa_invalid_param_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_ECDSA_C)
    test_ecdsa_prim_random_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_ECDSA_C)
    test_ecdsa_prim_test_vectors_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC)
    test_ecdsa_det_test_vectors_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_SHA256_C)
    test_ecdsa_write_read_random_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    test_ecdsa_read_restart_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE) && defined(MBEDTLS_ECDSA_DETERMINISTIC)
    test_ecdsa_write_restart_wrapper,
#else
    NULL,
#endif

#line 153 "suites/main_test.function"
};

/**
 * \brief        Execute the test function.
 *
 *               This is a wrapper function around the test function execution
 *               to allow the setjmp() call used to catch any calls to the
 *               parameter failure callback, to be used. Calls to setjmp()
 *               can invalidate the state of any local auto variables.
 *
 * \param fp     Function pointer to the test function
 * \param params Parameters to pass
 *
 */
void execute_function_ptr(TestWrapper_t fp, void **params)
{
#if defined(MBEDTLS_CHECK_PARAMS)
    if ( setjmp( param_fail_jmp ) == 0 )
    {
        fp( params );
    }
    else
    {
        /* Unexpected parameter validation error */
        test_info.result = TEST_RESULT_FAILED;
    }

    memset( param_fail_jmp, 0, sizeof(jmp_buf) );
#else
    fp( params );
#endif
}

/**
 * \brief        Dispatches test functions based on function index.
 *
 * \param exp_id    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int dispatch_test( size_t func_idx, void ** params )
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if ( func_idx < (int)( sizeof( test_funcs ) / sizeof( TestWrapper_t ) ) )
    {
        fp = test_funcs[func_idx];
        if ( fp )
            execute_function_ptr(fp, params);
        else
            ret = DISPATCH_UNSUPPORTED_SUITE;
    }
    else
    {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return( ret );
}


/**
 * \brief       Checks if test function is supported
 *
 * \param exp_id    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int check_test( size_t func_idx )
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if ( func_idx < (int)( sizeof(test_funcs)/sizeof( TestWrapper_t ) ) )
    {
        fp = test_funcs[func_idx];
        if ( fp == NULL )
            ret = DISPATCH_UNSUPPORTED_SUITE;
    }
    else
    {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return( ret );
}


#line 2 "suites/host_test.function"

/**
 * \brief       Verifies that string is in string parameter format i.e. "<str>"
 *              It also strips enclosing '"' from the input string.
 *
 * \param str   String parameter.
 *
 * \return      0 if success else 1
 */
int verify_string( char **str )
{
    if( ( *str )[0] != '"' ||
        ( *str )[strlen( *str ) - 1] != '"' )
    {
        mbedtls_fprintf( stderr,
            "Expected string (with \"\") for parameter and got: %s\n", *str );
        return( -1 );
    }

    ( *str )++;
    ( *str )[strlen( *str ) - 1] = '\0';

    return( 0 );
}

/**
 * \brief       Verifies that string is an integer. Also gives the converted
 *              integer value.
 *
 * \param str   Input string.
 * \param value Pointer to int for output value.
 *
 * \return      0 if success else 1
 */
int verify_int( char *str, int *value )
{
    size_t i;
    int minus = 0;
    int digits = 1;
    int hex = 0;

    for( i = 0; i < strlen( str ); i++ )
    {
        if( i == 0 && str[i] == '-' )
        {
            minus = 1;
            continue;
        }

        if( ( ( minus && i == 2 ) || ( !minus && i == 1 ) ) &&
            str[i - 1] == '0' && ( str[i] == 'x' || str[i] == 'X' ) )
        {
            hex = 1;
            continue;
        }

        if( ! ( ( str[i] >= '0' && str[i] <= '9' ) ||
                ( hex && ( ( str[i] >= 'a' && str[i] <= 'f' ) ||
                           ( str[i] >= 'A' && str[i] <= 'F' ) ) ) ) )
        {
            digits = 0;
            break;
        }
    }

    if( digits )
    {
        if( hex )
            *value = strtol( str, NULL, 16 );
        else
            *value = strtol( str, NULL, 10 );

        return( 0 );
    }

    mbedtls_fprintf( stderr,
                    "Expected integer for parameter and got: %s\n", str );
    return( KEY_VALUE_MAPPING_NOT_FOUND );
}


/**
 * \brief       Usage string.
 *
 */
#define USAGE \
    "Usage: %s [OPTIONS] files...\n\n" \
    "   Command line arguments:\n" \
    "     files...          One or more test data files. If no file is\n" \
    "                       specified the following default test case\n" \
    "                       file is used:\n" \
    "                           %s\n\n" \
    "   Options:\n" \
    "     -v | --verbose    Display full information about each test\n" \
    "     -h | --help       Display this information\n\n", \
    argv[0], \
    "TESTCASE_FILENAME"


/**
 * \brief       Read a line from the passed file pointer.
 *
 * \param f     FILE pointer
 * \param buf   Pointer to memory to hold read line.
 * \param len   Length of the buf.
 *
 * \return      0 if success else -1
 */
int get_line( FILE *f, char *buf, size_t len )
{
    char *ret;
    int i = 0, str_len = 0, has_string = 0;

    /* Read until we get a valid line */
    do
    {
        ret = fgets( buf, len, f );
        if( ret == NULL )
            return( -1 );

        str_len = strlen( buf );

        /* Skip empty line and comment */
        if ( str_len == 0 || buf[0] == '#' )
            continue;
        has_string = 0;
        for ( i = 0; i < str_len; i++ )
        {
            char c = buf[i];
            if ( c != ' ' && c != '\t' && c != '\n' &&
                 c != '\v' && c != '\f' && c != '\r' )
            {
                has_string = 1;
                break;
            }
        }
    } while( !has_string );

    /* Strip new line and carriage return */
    ret = buf + strlen( buf );
    if( ret-- > buf && *ret == '\n' )
        *ret = '\0';
    if( ret-- > buf && *ret == '\r' )
        *ret = '\0';

    return( 0 );
}

/**
 * \brief       Splits string delimited by ':'. Ignores '\:'.
 *
 * \param buf           Input string
 * \param len           Input string length
 * \param params        Out params found
 * \param params_len    Out params array len
 *
 * \return      Count of strings found.
 */
static int parse_arguments( char *buf, size_t len, char **params,
                            size_t params_len )
{
    size_t cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while( *p != '\0' && p < ( buf + len ) )
    {
        if( *p == '\\' )
        {
            p++;
            p++;
            continue;
        }
        if( *p == ':' )
        {
            if( p + 1 < buf + len )
            {
                cur = p + 1;
                TEST_HELPER_ASSERT( cnt < params_len );
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    /* Replace newlines, question marks and colons in strings */
    for( i = 0; i < cnt; i++ )
    {
        p = params[i];
        q = params[i];

        while( *p != '\0' )
        {
            if( *p == '\\' && *( p + 1 ) == 'n' )
            {
                p += 2;
                *( q++ ) = '\n';
            }
            else if( *p == '\\' && *( p + 1 ) == ':' )
            {
                p += 2;
                *( q++ ) = ':';
            }
            else if( *p == '\\' && *( p + 1 ) == '?' )
            {
                p += 2;
                *( q++ ) = '?';
            }
            else
                *( q++ ) = *( p++ );
        }
        *q = '\0';
    }

    return( cnt );
}

/**
 * \brief       Converts parameters into test function consumable parameters.
 *              Example: Input:  {"int", "0", "char*", "Hello",
 *                                "hex", "abef", "exp", "1"}
 *                      Output:  {
 *                                0,                // Verified int
 *                                "Hello",          // Verified string
 *                                2, { 0xab, 0xef },// Converted len,hex pair
 *                                9600              // Evaluated expression
 *                               }
 *
 *
 * \param cnt               Parameter array count.
 * \param params            Out array of found parameters.
 * \param int_params_store  Memory for storing processed integer parameters.
 *
 * \return      0 for success else 1
 */
static int convert_params( size_t cnt , char ** params , int * int_params_store )
{
    char ** cur = params;
    char ** out = params;
    int ret = DISPATCH_TEST_SUCCESS;

    while ( cur < params + cnt )
    {
        char * type = *cur++;
        char * val = *cur++;

        if ( strcmp( type, "char*" ) == 0 )
        {
            if ( verify_string( &val ) == 0 )
            {
              *out++ = val;
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "int" ) == 0 )
        {
            if ( verify_int( val, int_params_store ) == 0 )
            {
              *out++ = (char *) int_params_store++;
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "hex" ) == 0 )
        {
            if ( verify_string( &val ) == 0 )
            {
                *int_params_store = mbedtls_test_unhexify(
                                        (unsigned char *) val, val );
                *out++ = val;
                *out++ = (char *)(int_params_store++);
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "exp" ) == 0 )
        {
            int exp_id = strtol( val, NULL, 10 );
            if ( get_expression ( exp_id, int_params_store ) == 0 )
            {
              *out++ = (char *)int_params_store++;
            }
            else
            {
              ret = ( DISPATCH_INVALID_TEST_DATA );
              break;
            }
        }
        else
        {
          ret = ( DISPATCH_INVALID_TEST_DATA );
          break;
        }
    }
    return( ret );
}

/**
 * \brief       Tests snprintf implementation with test input.
 *
 * \note
 * At high optimization levels (e.g. gcc -O3), this function may be
 * inlined in run_test_snprintf. This can trigger a spurious warning about
 * potential misuse of snprintf from gcc -Wformat-truncation (observed with
 * gcc 7.2). This warning makes tests in run_test_snprintf redundant on gcc
 * only. They are still valid for other compilers. Avoid this warning by
 * forbidding inlining of this function by gcc.
 *
 * \param n         Buffer test length.
 * \param ref_buf   Expected buffer.
 * \param ref_ret   Expected snprintf return value.
 *
 * \return      0 for success else 1
 */
#if defined(__GNUC__)
__attribute__((__noinline__))
#endif
static int test_snprintf( size_t n, const char ref_buf[10], int ref_ret )
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    if( n >= sizeof( buf ) )
        return( -1 );
    ret = mbedtls_snprintf( buf, n, "%s", "123" );
    if( ret < 0 || (size_t) ret >= n )
        ret = -1;

    if( strncmp( ref_buf, buf, sizeof( buf ) ) != 0 ||
        ref_ret != ret ||
        memcmp( buf + n, ref + n, sizeof( buf ) - n ) != 0 )
    {
        return( 1 );
    }

    return( 0 );
}

/**
 * \brief       Tests snprintf implementation.
 *
 * \param none
 *
 * \return      0 for success else 1
 */
static int run_test_snprintf( void )
{
    return( test_snprintf( 0, "xxxxxxxxx",  -1 ) != 0 ||
            test_snprintf( 1, "",           -1 ) != 0 ||
            test_snprintf( 2, "1",          -1 ) != 0 ||
            test_snprintf( 3, "12",         -1 ) != 0 ||
            test_snprintf( 4, "123",         3 ) != 0 ||
            test_snprintf( 5, "123",         3 ) != 0 );
}

/** \brief Write the description of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param argv0         The test suite name.
 * \param test_case     The test case description.
 */
static void write_outcome_entry( FILE *outcome_file,
                                 const char *argv0,
                                 const char *test_case )
{
    /* The non-varying fields are initialized on first use. */
    static const char *platform = NULL;
    static const char *configuration = NULL;
    static const char *test_suite = NULL;

    if( outcome_file == NULL )
        return;

    if( platform == NULL )
    {
        platform = getenv( "MBEDTLS_TEST_PLATFORM" );
        if( platform == NULL )
            platform = "unknown";
    }
    if( configuration == NULL )
    {
        configuration = getenv( "MBEDTLS_TEST_CONFIGURATION" );
        if( configuration == NULL )
            configuration = "unknown";
    }
    if( test_suite == NULL )
    {
        test_suite = strrchr( argv0, '/' );
        if( test_suite != NULL )
            test_suite += 1; // skip the '/'
        else
            test_suite = argv0;
    }

    /* Write the beginning of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    mbedtls_fprintf( outcome_file, "%s;%s;%s;%s;",
                     platform, configuration, test_suite, test_case );
}

/** \brief Write the result of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param unmet_dep_count            The number of unmet dependencies.
 * \param unmet_dependencies         The array of unmet dependencies.
 * \param missing_unmet_dependencies Non-zero if there was a problem tracking
 *                                   all unmet dependencies, 0 otherwise.
 * \param ret           The test dispatch status (DISPATCH_xxx).
 * \param test_info     A pointer to the test info structure.
 */
static void write_outcome_result( FILE *outcome_file,
                                  size_t unmet_dep_count,
                                  int unmet_dependencies[],
                                  int missing_unmet_dependencies,
                                  int ret,
                                  const test_info_t *info )
{
    if( outcome_file == NULL )
        return;

    /* Write the end of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    switch( ret )
    {
        case DISPATCH_TEST_SUCCESS:
            if( unmet_dep_count > 0 )
            {
                size_t i;
                mbedtls_fprintf( outcome_file, "SKIP" );
                for( i = 0; i < unmet_dep_count; i++ )
                {
                    mbedtls_fprintf( outcome_file, "%c%d",
                                     i == 0 ? ';' : ':',
                                     unmet_dependencies[i] );
                }
                if( missing_unmet_dependencies )
                    mbedtls_fprintf( outcome_file, ":..." );
                break;
            }
            switch( info->result )
            {
                case TEST_RESULT_SUCCESS:
                    mbedtls_fprintf( outcome_file, "PASS;" );
                    break;
                case TEST_RESULT_SKIPPED:
                    mbedtls_fprintf( outcome_file, "SKIP;Runtime skip" );
                    break;
                default:
                    mbedtls_fprintf( outcome_file, "FAIL;%s:%d:%s",
                                     info->filename, info->line_no,
                                     info->test );
                    break;
            }
            break;
        case DISPATCH_TEST_FN_NOT_FOUND:
            mbedtls_fprintf( outcome_file, "FAIL;Test function not found" );
            break;
        case DISPATCH_INVALID_TEST_DATA:
            mbedtls_fprintf( outcome_file, "FAIL;Invalid test data" );
            break;
        case DISPATCH_UNSUPPORTED_SUITE:
            mbedtls_fprintf( outcome_file, "SKIP;Unsupported suite" );
            break;
        default:
            mbedtls_fprintf( outcome_file, "FAIL;Unknown cause" );
            break;
    }
    mbedtls_fprintf( outcome_file, "\n" );
    fflush( outcome_file );
}

/**
 * \brief       Desktop implementation of execute_tests().
 *              Parses command line and executes tests from
 *              supplied or default data file.
 *
 * \param argc  Command line argument count.
 * \param argv  Argument array.
 *
 * \return      Program exit status.
 */
int execute_tests( int argc , const char ** argv )
{
    /* Local Configurations and options */
    const char *default_filename = "./test_suite_ecdsa.datax";
    const char *test_filename = NULL;
    const char **test_files = NULL;
    size_t testfile_count = 0;
    int option_verbose = 0;
    size_t function_id = 0;

    /* Other Local variables */
    int arg_index = 1;
    const char *next_arg;
    size_t testfile_index, i, cnt;
    int ret;
    unsigned total_errors = 0, total_tests = 0, total_skipped = 0;
    FILE *file;
    char buf[5000];
    char *params[50];
    /* Store for proccessed integer params. */
    int int_params[50];
    void *pointer;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    int stdout_fd = -1;
#endif /* __unix__ || __APPLE__ __MACH__ */
    const char *outcome_file_name = getenv( "MBEDTLS_TEST_OUTCOME_FILE" );
    FILE *outcome_file = NULL;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof( alloc_buf ) );
#endif

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset( &pointer, 0, sizeof( void * ) );
    if( pointer != NULL )
    {
        mbedtls_fprintf( stderr, "all-bits-zero is not a NULL pointer\n" );
        return( 1 );
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if( run_test_snprintf() != 0 )
    {
        mbedtls_fprintf( stderr, "the snprintf implementation is broken\n" );
        return( 1 );
    }

    if( outcome_file_name != NULL && *outcome_file_name != '\0' )
    {
        outcome_file = fopen( outcome_file_name, "a" );
        if( outcome_file == NULL )
        {
            mbedtls_fprintf( stderr, "Unable to open outcome file. Continuing anyway.\n" );
        }
    }

    while( arg_index < argc )
    {
        next_arg = argv[arg_index];

        if( strcmp( next_arg, "--verbose" ) == 0 ||
                 strcmp( next_arg, "-v" ) == 0 )
        {
            option_verbose = 1;
        }
        else if( strcmp(next_arg, "--help" ) == 0 ||
                 strcmp(next_arg, "-h" ) == 0 )
        {
            mbedtls_fprintf( stdout, USAGE );
            mbedtls_exit( EXIT_SUCCESS );
        }
        else
        {
            /* Not an option, therefore treat all further arguments as the file
             * list.
             */
            test_files = &argv[ arg_index ];
            testfile_count = argc - arg_index;
        }

        arg_index++;
    }

    /* If no files were specified, assume a default */
    if ( test_files == NULL || testfile_count == 0 )
    {
        test_files = &default_filename;
        testfile_count = 1;
    }

    /* Initialize the struct that holds information about the last test */
    memset( &test_info, 0, sizeof( test_info ) );

    /* Now begin to execute the tests in the testfiles */
    for ( testfile_index = 0;
          testfile_index < testfile_count;
          testfile_index++ )
    {
        size_t unmet_dep_count = 0;
        int unmet_dependencies[20];
        int missing_unmet_dependencies = 0;

        test_filename = test_files[ testfile_index ];

        file = fopen( test_filename, "r" );
        if( file == NULL )
        {
            mbedtls_fprintf( stderr, "Failed to open test file: %s\n",
                             test_filename );
            if( outcome_file != NULL )
                fclose( outcome_file );
            return( 1 );
        }

        while( !feof( file ) )
        {
            if( unmet_dep_count > 0 )
            {
                mbedtls_fprintf( stderr,
                    "FATAL: Dep count larger than zero at start of loop\n" );
                mbedtls_exit( MBEDTLS_EXIT_FAILURE );
            }
            unmet_dep_count = 0;
            missing_unmet_dependencies = 0;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            mbedtls_fprintf( stdout, "%s%.66s",
                    test_info.result == TEST_RESULT_FAILED ? "\n" : "", buf );
            mbedtls_fprintf( stdout, " " );
            for( i = strlen( buf ) + 1; i < 67; i++ )
                mbedtls_fprintf( stdout, "." );
            mbedtls_fprintf( stdout, " " );
            fflush( stdout );
            write_outcome_entry( outcome_file, argv[0], buf );

            total_tests++;

            if( ( ret = get_line( file, buf, sizeof( buf ) ) ) != 0 )
                break;
            cnt = parse_arguments( buf, strlen( buf ), params,
                                   sizeof( params ) / sizeof( params[0] ) );

            if( strcmp( params[0], "depends_on" ) == 0 )
            {
                for( i = 1; i < cnt; i++ )
                {
                    int dep_id = strtol( params[i], NULL, 10 );
                    if( dep_check( dep_id ) != DEPENDENCY_SUPPORTED )
                    {
                        if( unmet_dep_count <
                            ARRAY_LENGTH( unmet_dependencies ) )
                        {
                            unmet_dependencies[unmet_dep_count] = dep_id;
                            unmet_dep_count++;
                        }
                        else
                        {
                            missing_unmet_dependencies = 1;
                        }
                    }
                }

                if( ( ret = get_line( file, buf, sizeof( buf ) ) ) != 0 )
                    break;
                cnt = parse_arguments( buf, strlen( buf ), params,
                                       sizeof( params ) / sizeof( params[0] ) );
            }

            // If there are no unmet dependencies execute the test
            if( unmet_dep_count == 0 )
            {
                test_info.result = TEST_RESULT_SUCCESS;
                test_info.paramfail_test_state = PARAMFAIL_TESTSTATE_IDLE;
                test_info.step = (unsigned long)( -1 );

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                /* Suppress all output from the library unless we're verbose
                 * mode
                 */
                if( !option_verbose )
                {
                    stdout_fd = redirect_output( &stdout, "/dev/null" );
                    if( stdout_fd == -1 )
                    {
                        /* Redirection has failed with no stdout so exit */
                        exit( 1 );
                    }
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

                function_id = strtoul( params[0], NULL, 10 );
                if ( (ret = check_test( function_id )) == DISPATCH_TEST_SUCCESS )
                {
                    ret = convert_params( cnt - 1, params + 1, int_params );
                    if ( DISPATCH_TEST_SUCCESS == ret )
                    {
                        ret = dispatch_test( function_id, (void **)( params + 1 ) );
                    }
                }

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                if( !option_verbose && restore_output( &stdout, stdout_fd ) )
                {
                        /* Redirection has failed with no stdout so exit */
                        exit( 1 );
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

            }

            write_outcome_result( outcome_file,
                                  unmet_dep_count, unmet_dependencies,
                                  missing_unmet_dependencies,
                                  ret, &test_info );
            if( unmet_dep_count > 0 || ret == DISPATCH_UNSUPPORTED_SUITE )
            {
                total_skipped++;
                mbedtls_fprintf( stdout, "----" );

                if( 1 == option_verbose && ret == DISPATCH_UNSUPPORTED_SUITE )
                {
                    mbedtls_fprintf( stdout, "\n   Test Suite not enabled" );
                }

                if( 1 == option_verbose && unmet_dep_count > 0 )
                {
                    mbedtls_fprintf( stdout, "\n   Unmet dependencies: " );
                    for( i = 0; i < unmet_dep_count; i++ )
                    {
                        mbedtls_fprintf( stdout, "%d ",
                                        unmet_dependencies[i] );
                    }
                    if( missing_unmet_dependencies )
                        mbedtls_fprintf( stdout, "..." );
                }
                mbedtls_fprintf( stdout, "\n" );
                fflush( stdout );

                unmet_dep_count = 0;
                missing_unmet_dependencies = 0;
            }
            else if( ret == DISPATCH_TEST_SUCCESS )
            {
                if( test_info.result == TEST_RESULT_SUCCESS )
                {
                    mbedtls_fprintf( stdout, "PASS\n" );
                }
                else if( test_info.result == TEST_RESULT_SKIPPED )
                {
                    mbedtls_fprintf( stdout, "----\n" );
                    total_skipped++;
                }
                else
                {
                    total_errors++;
                    mbedtls_fprintf( stdout, "FAILED\n" );
                    mbedtls_fprintf( stdout, "  %s\n  at ",
                                     test_info.test );
                    if( test_info.step != (unsigned long)( -1 ) )
                    {
                        mbedtls_fprintf( stdout, "step %lu, ",
                                         test_info.step );
                    }
                    mbedtls_fprintf( stdout, "line %d, %s",
                                     test_info.line_no, test_info.filename );
                }
                fflush( stdout );
            }
            else if( ret == DISPATCH_INVALID_TEST_DATA )
            {
                mbedtls_fprintf( stderr, "FAILED: FATAL PARSE ERROR\n" );
                fclose( file );
                mbedtls_exit( 2 );
            }
            else if( ret == DISPATCH_TEST_FN_NOT_FOUND )
            {
                mbedtls_fprintf( stderr, "FAILED: FATAL TEST FUNCTION NOT FOUND\n" );
                fclose( file );
                mbedtls_exit( 2 );
            }
            else
                total_errors++;
        }
        fclose( file );
    }

    if( outcome_file != NULL )
        fclose( outcome_file );

    mbedtls_fprintf( stdout, "\n----------------------------------------------------------------------------\n\n");
    if( total_errors == 0 )
        mbedtls_fprintf( stdout, "PASSED" );
    else
        mbedtls_fprintf( stdout, "FAILED" );

    mbedtls_fprintf( stdout, " (%u / %u tests (%u skipped))\n",
                     total_tests - total_errors, total_tests, total_skipped );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    if( stdout_fd != -1 )
        close_output( stdout );
#endif /* __unix__ || __APPLE__ __MACH__ */

    return( total_errors != 0 );
}


#line 249 "suites/main_test.function"

/*----------------------------------------------------------------------------*/
/* Main Test code */


/**
 * \brief       Program main. Invokes platform specific execute_tests().
 *
 * \param argc      Command line arguments count.
 * \param argv      Array of command line arguments.
 *
 * \return       Exit code.
 */
int main( int argc, const char *argv[] )
{
    int ret = mbedtls_test_platform_setup();
    if( ret != 0 )
    {
        mbedtls_fprintf( stderr,
                         "FATAL: Failed to initialize platform - error %d\n",
                         ret );
        return( -1 );
    }

    ret = execute_tests( argc, argv );
    mbedtls_test_platform_teardown();
    return( ret );
}
