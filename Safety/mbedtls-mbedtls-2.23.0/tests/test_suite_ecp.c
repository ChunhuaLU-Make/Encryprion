#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_ecp.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : suites/main_test.function
 *      Platform code file  : suites/host_test.function
 *      Helper file         : suites/helpers.function
 *      Test suite file     : suites/test_suite_ecp.function
 *      Test suite data     : suites/test_suite_ecp.data
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

#if defined(MBEDTLS_ECP_C)
#line 2 "suites/test_suite_ecp.function"
#include "mbedtls/ecp.h"

#define ECP_PF_UNKNOWN     -1

#define ECP_PT_RESET( x )           \
    mbedtls_ecp_point_free( x );    \
    mbedtls_ecp_point_init( x );
#line 17 "suites/test_suite_ecp.function"
void test_ecp_valid_param( )
{
    TEST_VALID_PARAM( mbedtls_ecp_group_free( NULL ) );
    TEST_VALID_PARAM( mbedtls_ecp_keypair_free( NULL ) );
    TEST_VALID_PARAM( mbedtls_ecp_point_free( NULL ) );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    TEST_VALID_PARAM( mbedtls_ecp_restart_free( NULL ) );
#endif /* MBEDTLS_ECP_RESTARTABLE */

exit:
    return;
}

void test_ecp_valid_param_wrapper( void ** params )
{
    (void)params;

    test_ecp_valid_param(  );
}
#if defined(MBEDTLS_CHECK_PARAMS)
#if !defined(MBEDTLS_PARAM_FAILED_ALT)
#line 33 "suites/test_suite_ecp.function"
void test_ecp_invalid_param( )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_keypair kp;
    mbedtls_ecp_point P;
    mbedtls_mpi m;
    const char *x = "deadbeef";
    int valid_fmt   = MBEDTLS_ECP_PF_UNCOMPRESSED;
    int invalid_fmt = 42;
    size_t olen;
    unsigned char buf[42] = { 0 };
    const unsigned char *null_buf = NULL;
    mbedtls_ecp_group_id valid_group = MBEDTLS_ECP_DP_SECP192R1;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx restart_ctx;
#endif /* MBEDTLS_ECP_RESTARTABLE */

    TEST_INVALID_PARAM( mbedtls_ecp_point_init( NULL ) );
    TEST_INVALID_PARAM( mbedtls_ecp_keypair_init( NULL ) );
    TEST_INVALID_PARAM( mbedtls_ecp_group_init( NULL ) );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    TEST_INVALID_PARAM( mbedtls_ecp_restart_init( NULL ) );
    TEST_INVALID_PARAM( mbedtls_ecp_check_budget( NULL, &restart_ctx, 42 ) );
#endif /* MBEDTLS_ECP_RESTARTABLE */

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_copy( NULL, &P ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_copy( &P, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_group_copy( NULL, &grp ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_group_copy( &grp, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_gen_privkey( NULL,
                                                     &m,
                                                     mbedtls_test_rnd_std_rand,
                                                     NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_gen_privkey( &grp,
                                                     NULL,
                                                     mbedtls_test_rnd_std_rand,
                                                     NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_gen_privkey( &grp,
                                                     &m,
                                                     NULL,
                                                     NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_set_zero( NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_is_zero( NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_cmp( NULL, &P ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_cmp( &P, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_read_string( NULL, 2,
                                                           x, x ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_read_string( &P, 2,
                                                           NULL, x ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_read_string( &P, 2,
                                                           x, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_write_binary( NULL, &P,
                                                      valid_fmt,
                                                      &olen,
                                                      buf, sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_write_binary( &grp, NULL,
                                                      valid_fmt,
                                                      &olen,
                                                      buf, sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_write_binary( &grp, &P,
                                                      invalid_fmt,
                                                      &olen,
                                                      buf, sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_write_binary( &grp, &P,
                                                      valid_fmt,
                                                      NULL,
                                                      buf, sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_write_binary( &grp, &P,
                                                      valid_fmt,
                                                      &olen,
                                                      NULL, sizeof( buf ) ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_read_binary( NULL, &P, buf,
                                                     sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_read_binary( &grp, NULL, buf,
                                                     sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_point_read_binary( &grp, &P, NULL,
                                                     sizeof( buf ) ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_read_point( NULL, &P,
                                                 (const unsigned char **) &buf,
                                                 sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_read_point( &grp, NULL,
                                                 (const unsigned char **) &buf,
                                                 sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_read_point( &grp, &P, &null_buf,
                                                        sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_read_point( &grp, &P, NULL,
                                                    sizeof( buf ) ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_write_point( NULL, &P,
                                                     valid_fmt,
                                                     &olen,
                                                     buf,
                                                     sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_write_point( &grp, NULL,
                                                     valid_fmt,
                                                     &olen,
                                                     buf,
                                                     sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_write_point( &grp, &P,
                                                     invalid_fmt,
                                                     &olen,
                                                     buf,
                                                     sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_write_point( &grp, &P,
                                                     valid_fmt,
                                                     NULL,
                                                     buf,
                                                     sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_write_point( &grp, &P,
                                                     valid_fmt,
                                                     &olen,
                                                     NULL,
                                                     sizeof( buf ) ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_group_load( NULL, valid_group ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_read_group( NULL,
                                                 (const unsigned char **) &buf,
                                                 sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_read_group( &grp, NULL,
                                                        sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_read_group( &grp, &null_buf,
                                                        sizeof( buf ) ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_read_group_id( NULL,
                                                 (const unsigned char **) &buf,
                                                 sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_read_group_id( &valid_group, NULL,
                                                        sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_read_group_id( &valid_group,
                                                           &null_buf,
                                                           sizeof( buf ) ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_write_group( NULL, &olen,
                                                       buf, sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_write_group( &grp, NULL,
                                                       buf, sizeof( buf ) ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_tls_write_group( &grp, &olen,
                                                       NULL, sizeof( buf ) ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_mul( NULL, &P, &m, &P,
                                             mbedtls_test_rnd_std_rand,
                                             NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_mul( &grp, NULL, &m, &P,
                                             mbedtls_test_rnd_std_rand,
                                             NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_mul( &grp, &P, NULL, &P,
                                             mbedtls_test_rnd_std_rand,
                                             NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_mul( &grp, &P, &m, NULL,
                                             mbedtls_test_rnd_std_rand,
                                             NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_mul_restartable( NULL, &P, &m, &P,
                                                     mbedtls_test_rnd_std_rand,
                                                     NULL , NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_mul_restartable( &grp, NULL, &m, &P,
                                                     mbedtls_test_rnd_std_rand,
                                                     NULL , NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_mul_restartable( &grp, &P, NULL, &P,
                                                     mbedtls_test_rnd_std_rand,
                                                     NULL , NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_mul_restartable( &grp, &P, &m, NULL,
                                                     mbedtls_test_rnd_std_rand,
                                                     NULL , NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd( NULL, &P, &m, &P,
                                                &m, &P ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd( &grp, NULL, &m, &P,
                                                &m, &P ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd( &grp, &P, NULL, &P,
                                                &m, &P ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd( &grp, &P, &m, NULL,
                                                &m, &P ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd( &grp, &P, &m, &P,
                                                NULL, &P ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd( &grp, &P, &m, &P,
                                                &m, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd_restartable( NULL, &P, &m, &P,
                                                            &m, &P, NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd_restartable( &grp, NULL, &m, &P,
                                                            &m, &P, NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd_restartable( &grp, &P, NULL, &P,
                                                            &m, &P, NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd_restartable( &grp, &P, &m, NULL,
                                                            &m, &P, NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd_restartable( &grp, &P, &m, &P,
                                                            NULL, &P, NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_muladd_restartable( &grp, &P, &m, &P,
                                                            &m, NULL, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_check_pubkey( NULL, &P ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_check_pubkey( &grp, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_check_pub_priv( NULL, &kp ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_check_pub_priv( &kp, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_check_privkey( NULL, &m ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_check_privkey( &grp, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
        mbedtls_ecp_gen_keypair_base( NULL, &P, &m, &P,
                                      mbedtls_test_rnd_std_rand, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
        mbedtls_ecp_gen_keypair_base( &grp, NULL, &m, &P,
                                      mbedtls_test_rnd_std_rand, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
        mbedtls_ecp_gen_keypair_base( &grp, &P, NULL, &P,
                                      mbedtls_test_rnd_std_rand, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
        mbedtls_ecp_gen_keypair_base( &grp, &P, &m, NULL,
                                      mbedtls_test_rnd_std_rand, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
        mbedtls_ecp_gen_keypair_base( &grp, &P, &m, &P, NULL, NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_gen_keypair( NULL,
                                                     &m, &P,
                                                     mbedtls_test_rnd_std_rand,
                                                     NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_gen_keypair( &grp,
                                                     NULL, &P,
                                                     mbedtls_test_rnd_std_rand,
                                                     NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_gen_keypair( &grp,
                                                     &m, NULL,
                                                     mbedtls_test_rnd_std_rand,
                                                     NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_gen_keypair( &grp,
                                                     &m, &P,
                                                     NULL,
                                                     NULL ) );

    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_gen_key( valid_group, NULL,
                                                 mbedtls_test_rnd_std_rand,
                                                 NULL ) );
    TEST_INVALID_PARAM_RET( MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                            mbedtls_ecp_gen_key( valid_group, &kp,
                                                 NULL, NULL ) );

exit:
    return;
}

void test_ecp_invalid_param_wrapper( void ** params )
{
    (void)params;

    test_ecp_invalid_param(  );
}
#endif /* !MBEDTLS_PARAM_FAILED_ALT */
#endif /* MBEDTLS_CHECK_PARAMS */
#line 364 "suites/test_suite_ecp.function"
void test_mbedtls_ecp_curve_info( int id, int tls_id, int size, char * name )
{
    const mbedtls_ecp_curve_info *by_id, *by_tls, *by_name;

    by_id   = mbedtls_ecp_curve_info_from_grp_id( id     );
    by_tls  = mbedtls_ecp_curve_info_from_tls_id( tls_id );
    by_name = mbedtls_ecp_curve_info_from_name(   name   );
    TEST_ASSERT( by_id   != NULL );
    TEST_ASSERT( by_tls  != NULL );
    TEST_ASSERT( by_name != NULL );

    TEST_ASSERT( by_id == by_tls  );
    TEST_ASSERT( by_id == by_name );

    TEST_ASSERT( by_id->bit_size == size );
exit:
    ;
}

void test_mbedtls_ecp_curve_info_wrapper( void ** params )
{

    test_mbedtls_ecp_curve_info( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), (char *) params[3] );
}
#line 383 "suites/test_suite_ecp.function"
void test_ecp_check_pub( int grp_id, char * x_hex, char * y_hex, char * z_hex,
                    int ret )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &P );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, grp_id ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &P.X, 16, x_hex ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &P.Y, 16, y_hex ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &P.Z, 16, z_hex ) == 0 );

    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &P ) == ret );

exit:
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &P );
}

void test_ecp_check_pub_wrapper( void ** params )
{

    test_ecp_check_pub( *( (int *) params[0] ), (char *) params[1], (char *) params[2], (char *) params[3], *( (int *) params[4] ) );
}
#if defined(MBEDTLS_ECP_RESTARTABLE)
#line 407 "suites/test_suite_ecp.function"
void test_ecp_test_vect_restart( int id,
                            char *dA_str, char *xA_str, char *yA_str,
                            char *dB_str,  char *xZ_str, char *yZ_str,
                            int max_ops, int min_restarts, int max_restarts )
{
    /*
     * Test for early restart. Based on test vectors like ecp_test_vect(),
     * but for the sake of simplicity only does half of each side. It's
     * important to test both base point and random point, though, as memory
     * management is different in each case.
     *
     * Don't try using too precise bounds for restarts as the exact number
     * will depend on settings such as MBEDTLS_ECP_FIXED_POINT_OPTIM and
     * MBEDTLS_ECP_WINDOW_SIZE, as well as implementation details that may
     * change in the future. A factor 2 is a minimum safety margin.
     *
     * For reference, with mbed TLS 2.4 and default settings, for P-256:
     * - Random point mult:     ~3250M
     * - Cold base point mult:  ~3300M
     * - Hot base point mult:   ~1100M
     * With MBEDTLS_ECP_WINDOW_SIZE set to 2 (minimum):
     * - Random point mult:     ~3850M
     */
    mbedtls_ecp_restart_ctx ctx;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, P;
    mbedtls_mpi dA, xA, yA, dB, xZ, yZ;
    int cnt_restarts;
    int ret;

    mbedtls_ecp_restart_init( &ctx );
    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &R ); mbedtls_ecp_point_init( &P );
    mbedtls_mpi_init( &dA ); mbedtls_mpi_init( &xA ); mbedtls_mpi_init( &yA );
    mbedtls_mpi_init( &dB ); mbedtls_mpi_init( &xZ ); mbedtls_mpi_init( &yZ );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &dA, 16, dA_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &xA, 16, xA_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &yA, 16, yA_str ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &dB, 16, dB_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &xZ, 16, xZ_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &yZ, 16, yZ_str ) == 0 );

    mbedtls_ecp_set_max_ops( (unsigned) max_ops );

    /* Base point case */
    cnt_restarts = 0;
    do {
        ECP_PT_RESET( &R );
        ret = mbedtls_ecp_mul_restartable( &grp, &R, &dA, &grp.G, NULL, NULL, &ctx );
    } while( ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restarts );

    TEST_ASSERT( ret == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.X, &xA ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.Y, &yA ) == 0 );

    TEST_ASSERT( cnt_restarts >= min_restarts );
    TEST_ASSERT( cnt_restarts <= max_restarts );

    /* Non-base point case */
    mbedtls_ecp_copy( &P, &R );
    cnt_restarts = 0;
    do {
        ECP_PT_RESET( &R );
        ret = mbedtls_ecp_mul_restartable( &grp, &R, &dB, &P, NULL, NULL, &ctx );
    } while( ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restarts );

    TEST_ASSERT( ret == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.X, &xZ ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.Y, &yZ ) == 0 );

    TEST_ASSERT( cnt_restarts >= min_restarts );
    TEST_ASSERT( cnt_restarts <= max_restarts );

    /* Do we leak memory when aborting an operation?
     * This test only makes sense when we actually restart */
    if( min_restarts > 0 )
    {
        ret = mbedtls_ecp_mul_restartable( &grp, &R, &dB, &P, NULL, NULL, &ctx );
        TEST_ASSERT( ret == MBEDTLS_ERR_ECP_IN_PROGRESS );
    }

exit:
    mbedtls_ecp_restart_free( &ctx );
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &R ); mbedtls_ecp_point_free( &P );
    mbedtls_mpi_free( &dA ); mbedtls_mpi_free( &xA ); mbedtls_mpi_free( &yA );
    mbedtls_mpi_free( &dB ); mbedtls_mpi_free( &xZ ); mbedtls_mpi_free( &yZ );
}

void test_ecp_test_vect_restart_wrapper( void ** params )
{

    test_ecp_test_vect_restart( *( (int *) params[0] ), (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], (char *) params[5], (char *) params[6], *( (int *) params[7] ), *( (int *) params[8] ), *( (int *) params[9] ) );
}
#endif /* MBEDTLS_ECP_RESTARTABLE */
#if defined(MBEDTLS_ECP_RESTARTABLE)
#line 502 "suites/test_suite_ecp.function"
void test_ecp_muladd_restart( int id, char *xR_str, char *yR_str,
                         char *u1_str, char *u2_str,
                         char *xQ_str, char *yQ_str,
                         int max_ops, int min_restarts, int max_restarts )
{
    /*
     * Compute R = u1 * G + u2 * Q
     * (test vectors mostly taken from ECDSA intermediate results)
     *
     * See comments at the top of ecp_test_vect_restart()
     */
    mbedtls_ecp_restart_ctx ctx;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, Q;
    mbedtls_mpi u1, u2, xR, yR;
    int cnt_restarts;
    int ret;

    mbedtls_ecp_restart_init( &ctx );
    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &R );
    mbedtls_ecp_point_init( &Q );
    mbedtls_mpi_init( &u1 ); mbedtls_mpi_init( &u2 );
    mbedtls_mpi_init( &xR ); mbedtls_mpi_init( &yR );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &u1, 16, u1_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &u2, 16, u2_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &xR, 16, xR_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &yR, 16, yR_str ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &Q.X, 16, xQ_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Q.Y, 16, yQ_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_lset( &Q.Z, 1 ) == 0 );

    mbedtls_ecp_set_max_ops( (unsigned) max_ops );

    cnt_restarts = 0;
    do {
        ECP_PT_RESET( &R );
        ret = mbedtls_ecp_muladd_restartable( &grp, &R,
                                              &u1, &grp.G, &u2, &Q, &ctx );
    } while( ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restarts );

    TEST_ASSERT( ret == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.X, &xR ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.Y, &yR ) == 0 );

    TEST_ASSERT( cnt_restarts >= min_restarts );
    TEST_ASSERT( cnt_restarts <= max_restarts );

    /* Do we leak memory when aborting an operation?
     * This test only makes sense when we actually restart */
    if( min_restarts > 0 )
    {
        ret = mbedtls_ecp_muladd_restartable( &grp, &R,
                                              &u1, &grp.G, &u2, &Q, &ctx );
        TEST_ASSERT( ret == MBEDTLS_ERR_ECP_IN_PROGRESS );
    }

exit:
    mbedtls_ecp_restart_free( &ctx );
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &R );
    mbedtls_ecp_point_free( &Q );
    mbedtls_mpi_free( &u1 ); mbedtls_mpi_free( &u2 );
    mbedtls_mpi_free( &xR ); mbedtls_mpi_free( &yR );
}

void test_ecp_muladd_restart_wrapper( void ** params )
{

    test_ecp_muladd_restart( *( (int *) params[0] ), (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], (char *) params[5], (char *) params[6], *( (int *) params[7] ), *( (int *) params[8] ), *( (int *) params[9] ) );
}
#endif /* MBEDTLS_ECP_RESTARTABLE */
#line 574 "suites/test_suite_ecp.function"
void test_ecp_test_vect( int id, char * dA_str, char * xA_str, char * yA_str,
                    char * dB_str, char * xB_str, char * yB_str,
                    char * xZ_str, char * yZ_str )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, yA, dB, xB, yB, xZ, yZ;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init( &grp ); mbedtls_ecp_point_init( &R );
    mbedtls_mpi_init( &dA ); mbedtls_mpi_init( &xA ); mbedtls_mpi_init( &yA ); mbedtls_mpi_init( &dB );
    mbedtls_mpi_init( &xB ); mbedtls_mpi_init( &yB ); mbedtls_mpi_init( &xZ ); mbedtls_mpi_init( &yZ );
    memset( &rnd_info, 0x00, sizeof( mbedtls_test_rnd_pseudo_info ) );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );

    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &grp.G ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &dA, 16, dA_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &xA, 16, xA_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &yA, 16, yA_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &dB, 16, dB_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &xB, 16, xB_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &yB, 16, yB_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &xZ, 16, xZ_str ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &yZ, 16, yZ_str ) == 0 );

    TEST_ASSERT( mbedtls_ecp_mul( &grp, &R, &dA, &grp.G,
                          &mbedtls_test_rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.X, &xA ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.Y, &yA ) == 0 );
    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( mbedtls_ecp_mul( &grp, &R, &dB, &R, NULL, NULL ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.X, &xZ ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.Y, &yZ ) == 0 );
    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &R ) == 0 );

    TEST_ASSERT( mbedtls_ecp_mul( &grp, &R, &dB, &grp.G, NULL, NULL ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.X, &xB ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.Y, &yB ) == 0 );
    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( mbedtls_ecp_mul( &grp, &R, &dA, &R,
                          &mbedtls_test_rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.X, &xZ ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.Y, &yZ ) == 0 );
    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &R ) == 0 );

exit:
    mbedtls_ecp_group_free( &grp ); mbedtls_ecp_point_free( &R );
    mbedtls_mpi_free( &dA ); mbedtls_mpi_free( &xA ); mbedtls_mpi_free( &yA ); mbedtls_mpi_free( &dB );
    mbedtls_mpi_free( &xB ); mbedtls_mpi_free( &yB ); mbedtls_mpi_free( &xZ ); mbedtls_mpi_free( &yZ );
}

void test_ecp_test_vect_wrapper( void ** params )
{

    test_ecp_test_vect( *( (int *) params[0] ), (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], (char *) params[5], (char *) params[6], (char *) params[7], (char *) params[8] );
}
#line 629 "suites/test_suite_ecp.function"
void test_ecp_test_vec_x( int id, char * dA_hex, char * xA_hex, char * dB_hex,
                     char * xB_hex, char * xS_hex )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, dB, xB, xS;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init( &grp ); mbedtls_ecp_point_init( &R );
    mbedtls_mpi_init( &dA ); mbedtls_mpi_init( &xA );
    mbedtls_mpi_init( &dB ); mbedtls_mpi_init( &xB );
    mbedtls_mpi_init( &xS );
    memset( &rnd_info, 0x00, sizeof( mbedtls_test_rnd_pseudo_info ) );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );

    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &grp.G ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &dA, 16, dA_hex ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &dB, 16, dB_hex ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &xA, 16, xA_hex ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &xB, 16, xB_hex ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &xS, 16, xS_hex ) == 0 );

    TEST_ASSERT( mbedtls_ecp_mul( &grp, &R, &dA, &grp.G,
                          &mbedtls_test_rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.X, &xA ) == 0 );

    TEST_ASSERT( mbedtls_ecp_mul( &grp, &R, &dB, &R,
                          &mbedtls_test_rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.X, &xS ) == 0 );

    TEST_ASSERT( mbedtls_ecp_mul( &grp, &R, &dB, &grp.G, NULL, NULL ) == 0 );
    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.X, &xB ) == 0 );

    TEST_ASSERT( mbedtls_ecp_mul( &grp, &R, &dA, &R, NULL, NULL ) == 0 );
    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R.X, &xS ) == 0 );

exit:
    mbedtls_ecp_group_free( &grp ); mbedtls_ecp_point_free( &R );
    mbedtls_mpi_free( &dA ); mbedtls_mpi_free( &xA );
    mbedtls_mpi_free( &dB ); mbedtls_mpi_free( &xB );
    mbedtls_mpi_free( &xS );
}

void test_ecp_test_vec_x_wrapper( void ** params )
{

    test_ecp_test_vec_x( *( (int *) params[0] ), (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], (char *) params[5] );
}
#line 680 "suites/test_suite_ecp.function"
void test_ecp_test_mul( int id, data_t * n_hex,
                   data_t *  Px_hex, data_t *  Py_hex, data_t *  Pz_hex,
                   data_t * nPx_hex, data_t * nPy_hex, data_t * nPz_hex,
                   int expected_ret )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P, nP, R;
    mbedtls_mpi n;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init( &grp ); mbedtls_ecp_point_init( &R );
    mbedtls_ecp_point_init( &P ); mbedtls_ecp_point_init( &nP );
    mbedtls_mpi_init( &n );
    memset( &rnd_info, 0x00, sizeof( mbedtls_test_rnd_pseudo_info ) );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );

    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &grp.G ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_binary( &n, n_hex->x, n_hex->len ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_binary( &P.X, Px_hex->x, Px_hex->len ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_binary( &P.Y, Py_hex->x, Py_hex->len ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_binary( &P.Z, Pz_hex->x, Pz_hex->len ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_binary( &nP.X, nPx_hex->x, nPx_hex->len )
                 == 0 );
    TEST_ASSERT( mbedtls_mpi_read_binary( &nP.Y, nPy_hex->x, nPy_hex->len )
                 == 0 );
    TEST_ASSERT( mbedtls_mpi_read_binary( &nP.Z, nPz_hex->x, nPz_hex->len )
                 == 0 );

    TEST_ASSERT( mbedtls_ecp_mul( &grp, &R, &n, &P,
                                  &mbedtls_test_rnd_pseudo_rand, &rnd_info )
                 == expected_ret );

    if( expected_ret == 0 )
    {
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &nP.X, &R.X ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &nP.Y, &R.Y ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &nP.Z, &R.Z ) == 0 );
    }

exit:
    mbedtls_ecp_group_free( &grp ); mbedtls_ecp_point_free( &R );
    mbedtls_ecp_point_free( &P ); mbedtls_ecp_point_free( &nP );
    mbedtls_mpi_free( &n );
}

void test_ecp_test_mul_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};
    data_t data7 = {(uint8_t *) params[7], *( (uint32_t *) params[8] )};
    data_t data9 = {(uint8_t *) params[9], *( (uint32_t *) params[10] )};
    data_t data11 = {(uint8_t *) params[11], *( (uint32_t *) params[12] )};
    data_t data13 = {(uint8_t *) params[13], *( (uint32_t *) params[14] )};

    test_ecp_test_mul( *( (int *) params[0] ), &data1, &data3, &data5, &data7, &data9, &data11, &data13, *( (int *) params[15] ) );
}
#line 730 "suites/test_suite_ecp.function"
void test_ecp_test_mul_rng( int id, data_t * d_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init( &grp ); mbedtls_mpi_init( &d );
    mbedtls_ecp_point_init( &Q );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );

    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &grp.G ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_binary( &d, d_hex->x, d_hex->len ) == 0 );

    TEST_ASSERT( mbedtls_ecp_mul( &grp, &Q, &d, &grp.G,
                                  &mbedtls_test_rnd_zero_rand, NULL )
                 == MBEDTLS_ERR_ECP_RANDOM_FAILED );

exit:
    mbedtls_ecp_group_free( &grp ); mbedtls_mpi_free( &d );
    mbedtls_ecp_point_free( &Q );
}

void test_ecp_test_mul_rng_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_ecp_test_mul_rng( *( (int *) params[0] ), &data1 );
}
#line 756 "suites/test_suite_ecp.function"
void test_ecp_fast_mod( int id, char * N_str )
{
    mbedtls_ecp_group grp;
    mbedtls_mpi N, R;

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &R );
    mbedtls_ecp_group_init( &grp );

    TEST_ASSERT( mbedtls_mpi_read_string( &N, 16, N_str ) == 0 );
    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );
    TEST_ASSERT( grp.modp != NULL );

    /*
     * Store correct result before we touch N
     */
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &R, &N, &grp.P ) == 0 );

    TEST_ASSERT( grp.modp( &N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_bitlen( &N ) <= grp.pbits + 3 );

    /*
     * Use mod rather than addition/subtraction in case previous test fails
     */
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &N, &N, &grp.P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &N, &R ) == 0 );

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &R );
    mbedtls_ecp_group_free( &grp );
}

void test_ecp_fast_mod_wrapper( void ** params )
{

    test_ecp_fast_mod( *( (int *) params[0] ), (char *) params[1] );
}
#line 789 "suites/test_suite_ecp.function"
void test_ecp_write_binary( int id, char * x, char * y, char * z, int format,
                       data_t * out, int blen, int ret )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    unsigned char buf[256];
    size_t olen;

    memset( buf, 0, sizeof( buf ) );

    mbedtls_ecp_group_init( &grp ); mbedtls_ecp_point_init( &P );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &P.X, 16, x ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &P.Y, 16, y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &P.Z, 16, z ) == 0 );

    TEST_ASSERT( mbedtls_ecp_point_write_binary( &grp, &P, format,
                                   &olen, buf, blen ) == ret );

    if( ret == 0 )
    {
        TEST_ASSERT( mbedtls_test_hexcmp( buf, out->x, olen, out->len ) == 0 );
    }

exit:
    mbedtls_ecp_group_free( &grp ); mbedtls_ecp_point_free( &P );
}

void test_ecp_write_binary_wrapper( void ** params )
{
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};

    test_ecp_write_binary( *( (int *) params[0] ), (char *) params[1], (char *) params[2], (char *) params[3], *( (int *) params[4] ), &data5, *( (int *) params[7] ), *( (int *) params[8] ) );
}
#line 821 "suites/test_suite_ecp.function"
void test_ecp_read_binary( int id, data_t * buf, char * x, char * y, char * z,
                      int ret )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_mpi X, Y, Z;


    mbedtls_ecp_group_init( &grp ); mbedtls_ecp_point_init( &P );
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, 16, x ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, 16, y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Z, 16, z ) == 0 );

    TEST_ASSERT( mbedtls_ecp_point_read_binary( &grp, &P, buf->x, buf->len ) == ret );

    if( ret == 0 )
    {
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &P.X, &X ) == 0 );
        if( mbedtls_ecp_get_type( &grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
        {
            TEST_ASSERT( mbedtls_mpi_cmp_int( &Y, 0 ) == 0 );
            TEST_ASSERT( P.Y.p == NULL );
            TEST_ASSERT( mbedtls_mpi_cmp_int( &Z, 1 ) == 0 );
            TEST_ASSERT( mbedtls_mpi_cmp_int( &P.Z, 1 ) == 0 );
        }
        else
        {
            TEST_ASSERT( mbedtls_mpi_cmp_mpi( &P.Y, &Y ) == 0 );
            TEST_ASSERT( mbedtls_mpi_cmp_mpi( &P.Z, &Z ) == 0 );
        }
    }

exit:
    mbedtls_ecp_group_free( &grp ); mbedtls_ecp_point_free( &P );
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z );
}

void test_ecp_read_binary_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_ecp_read_binary( *( (int *) params[0] ), &data1, (char *) params[3], (char *) params[4], (char *) params[5], *( (int *) params[6] ) );
}
#line 864 "suites/test_suite_ecp.function"
void test_mbedtls_ecp_tls_read_point( int id, data_t * buf, char * x, char * y,
                                 char * z, int ret )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_mpi X, Y, Z;
    const unsigned char *vbuf = buf->x;


    mbedtls_ecp_group_init( &grp ); mbedtls_ecp_point_init( &P );
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );

    TEST_ASSERT( mbedtls_mpi_read_string( &X, 16, x ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Y, 16, y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Z, 16, z ) == 0 );

    TEST_ASSERT( mbedtls_ecp_tls_read_point( &grp, &P, &vbuf, buf->len ) == ret );

    if( ret == 0 )
    {
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &P.X, &X ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &P.Y, &Y ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &P.Z, &Z ) == 0 );
        TEST_ASSERT( (uint32_t)( vbuf - buf->x ) == buf->len );
    }

exit:
    mbedtls_ecp_group_free( &grp ); mbedtls_ecp_point_free( &P );
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z );
}

void test_mbedtls_ecp_tls_read_point_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_mbedtls_ecp_tls_read_point( *( (int *) params[0] ), &data1, (char *) params[3], (char *) params[4], (char *) params[5], *( (int *) params[6] ) );
}
#line 899 "suites/test_suite_ecp.function"
void test_ecp_tls_write_read_point( int id )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pt;
    unsigned char buf[256];
    const unsigned char *vbuf;
    size_t olen;

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &pt );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );

    memset( buf, 0x00, sizeof( buf ) ); vbuf = buf;
    TEST_ASSERT( mbedtls_ecp_tls_write_point( &grp, &grp.G,
                    MBEDTLS_ECP_PF_COMPRESSED, &olen, buf, 256 ) == 0 );
    TEST_ASSERT( mbedtls_ecp_tls_read_point( &grp, &pt, &vbuf, olen )
                 == MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
    TEST_ASSERT( vbuf == buf + olen );

    memset( buf, 0x00, sizeof( buf ) ); vbuf = buf;
    TEST_ASSERT( mbedtls_ecp_tls_write_point( &grp, &grp.G,
                    MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, 256 ) == 0 );
    TEST_ASSERT( mbedtls_ecp_tls_read_point( &grp, &pt, &vbuf, olen ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &grp.G.X, &pt.X ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &grp.G.Y, &pt.Y ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &grp.G.Z, &pt.Z ) == 0 );
    TEST_ASSERT( vbuf == buf + olen );

    memset( buf, 0x00, sizeof( buf ) ); vbuf = buf;
    TEST_ASSERT( mbedtls_ecp_set_zero( &pt ) == 0 );
    TEST_ASSERT( mbedtls_ecp_tls_write_point( &grp, &pt,
                    MBEDTLS_ECP_PF_COMPRESSED, &olen, buf, 256 ) == 0 );
    TEST_ASSERT( mbedtls_ecp_tls_read_point( &grp, &pt, &vbuf, olen ) == 0 );
    TEST_ASSERT( mbedtls_ecp_is_zero( &pt ) );
    TEST_ASSERT( vbuf == buf + olen );

    memset( buf, 0x00, sizeof( buf ) ); vbuf = buf;
    TEST_ASSERT( mbedtls_ecp_set_zero( &pt ) == 0 );
    TEST_ASSERT( mbedtls_ecp_tls_write_point( &grp, &pt,
                    MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, 256 ) == 0 );
    TEST_ASSERT( mbedtls_ecp_tls_read_point( &grp, &pt, &vbuf, olen ) == 0 );
    TEST_ASSERT( mbedtls_ecp_is_zero( &pt ) );
    TEST_ASSERT( vbuf == buf + olen );

exit:
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &pt );
}

void test_ecp_tls_write_read_point_wrapper( void ** params )
{

    test_ecp_tls_write_read_point( *( (int *) params[0] ) );
}
#line 951 "suites/test_suite_ecp.function"
void test_mbedtls_ecp_tls_read_group( data_t * buf, int result, int bits,
                                 int record_len )
{
    mbedtls_ecp_group grp;
    const unsigned char *vbuf = buf->x;
    int ret;

    mbedtls_ecp_group_init( &grp );

    ret = mbedtls_ecp_tls_read_group( &grp, &vbuf, buf->len );

    TEST_ASSERT( ret == result );
    if( ret == 0)
    {
        TEST_ASSERT( mbedtls_mpi_bitlen( &grp.P ) == (size_t) bits );
        TEST_ASSERT( vbuf - buf->x ==  record_len);
    }

exit:
    mbedtls_ecp_group_free( &grp );
}

void test_mbedtls_ecp_tls_read_group_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};

    test_mbedtls_ecp_tls_read_group( &data0, *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ) );
}
#line 975 "suites/test_suite_ecp.function"
void test_ecp_tls_write_read_group( int id )
{
    mbedtls_ecp_group grp1, grp2;
    unsigned char buf[10];
    const unsigned char *vbuf = buf;
    size_t len;
    int ret;

    mbedtls_ecp_group_init( &grp1 );
    mbedtls_ecp_group_init( &grp2 );
    memset( buf, 0x00, sizeof( buf ) );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp1, id ) == 0 );

    TEST_ASSERT( mbedtls_ecp_tls_write_group( &grp1, &len, buf, 10 ) == 0 );
    ret = mbedtls_ecp_tls_read_group( &grp2, &vbuf, len );
    TEST_ASSERT( ret == 0 );

    if( ret == 0 )
    {
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &grp1.N, &grp2.N ) == 0 );
        TEST_ASSERT( grp1.id == grp2.id );
    }

exit:
    mbedtls_ecp_group_free( &grp1 );
    mbedtls_ecp_group_free( &grp2 );
}

void test_ecp_tls_write_read_group_wrapper( void ** params )
{

    test_ecp_tls_write_read_group( *( (int *) params[0] ) );
}
#line 1006 "suites/test_suite_ecp.function"
void test_mbedtls_ecp_check_privkey( int id, char * key_hex, int ret )
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;

    mbedtls_ecp_group_init( &grp );
    mbedtls_mpi_init( &d );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &d, 16, key_hex ) == 0 );

    TEST_ASSERT( mbedtls_ecp_check_privkey( &grp, &d ) == ret );

exit:
    mbedtls_ecp_group_free( &grp );
    mbedtls_mpi_free( &d );
}

void test_mbedtls_ecp_check_privkey_wrapper( void ** params )
{

    test_mbedtls_ecp_check_privkey( *( (int *) params[0] ), (char *) params[1], *( (int *) params[2] ) );
}
#line 1026 "suites/test_suite_ecp.function"
void test_mbedtls_ecp_check_pub_priv( int id_pub, char * Qx_pub, char * Qy_pub,
                                 int id, char * d, char * Qx, char * Qy,
                                 int ret )
{
    mbedtls_ecp_keypair pub, prv;

    mbedtls_ecp_keypair_init( &pub );
    mbedtls_ecp_keypair_init( &prv );

    if( id_pub != MBEDTLS_ECP_DP_NONE )
        TEST_ASSERT( mbedtls_ecp_group_load( &pub.grp, id_pub ) == 0 );
    TEST_ASSERT( mbedtls_ecp_point_read_string( &pub.Q, 16, Qx_pub, Qy_pub ) == 0 );

    if( id != MBEDTLS_ECP_DP_NONE )
        TEST_ASSERT( mbedtls_ecp_group_load( &prv.grp, id ) == 0 );
    TEST_ASSERT( mbedtls_ecp_point_read_string( &prv.Q, 16, Qx, Qy ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &prv.d, 16, d ) == 0 );

    TEST_ASSERT( mbedtls_ecp_check_pub_priv( &pub, &prv ) == ret );

exit:
    mbedtls_ecp_keypair_free( &pub );
    mbedtls_ecp_keypair_free( &prv );
}

void test_mbedtls_ecp_check_pub_priv_wrapper( void ** params )
{

    test_mbedtls_ecp_check_pub_priv( *( (int *) params[0] ), (char *) params[1], (char *) params[2], *( (int *) params[3] ), (char *) params[4], (char *) params[5], (char *) params[6], *( (int *) params[7] ) );
}
#line 1053 "suites/test_suite_ecp.function"
void test_mbedtls_ecp_gen_keypair( int id )
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &Q );
    mbedtls_mpi_init( &d );
    memset( &rnd_info, 0x00, sizeof( mbedtls_test_rnd_pseudo_info ) );

    TEST_ASSERT( mbedtls_ecp_group_load( &grp, id ) == 0 );

    TEST_ASSERT( mbedtls_ecp_gen_keypair( &grp, &d, &Q,
                                          &mbedtls_test_rnd_pseudo_rand,
                                          &rnd_info ) == 0 );

    TEST_ASSERT( mbedtls_ecp_check_pubkey( &grp, &Q ) == 0 );
    TEST_ASSERT( mbedtls_ecp_check_privkey( &grp, &d ) == 0 );

exit:
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &Q );
    mbedtls_mpi_free( &d );
}

void test_mbedtls_ecp_gen_keypair_wrapper( void ** params )
{

    test_mbedtls_ecp_gen_keypair( *( (int *) params[0] ) );
}
#line 1082 "suites/test_suite_ecp.function"
void test_mbedtls_ecp_gen_key( int id )
{
    mbedtls_ecp_keypair key;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_keypair_init( &key );
    memset( &rnd_info, 0x00, sizeof( mbedtls_test_rnd_pseudo_info ) );

    TEST_ASSERT( mbedtls_ecp_gen_key( id, &key,
                                      &mbedtls_test_rnd_pseudo_rand,
                                      &rnd_info ) == 0 );

    TEST_ASSERT( mbedtls_ecp_check_pubkey( &key.grp, &key.Q ) == 0 );
    TEST_ASSERT( mbedtls_ecp_check_privkey( &key.grp, &key.d ) == 0 );

exit:
    mbedtls_ecp_keypair_free( &key );
}

void test_mbedtls_ecp_gen_key_wrapper( void ** params )
{

    test_mbedtls_ecp_gen_key( *( (int *) params[0] ) );
}
#line 1103 "suites/test_suite_ecp.function"
void test_mbedtls_ecp_read_key( int grp_id, data_t* in_key, int expected )
{
    int ret = 0;
    mbedtls_ecp_keypair key;

    mbedtls_ecp_keypair_init( &key );

    ret = mbedtls_ecp_read_key( grp_id, &key, in_key->x, in_key->len );
    TEST_ASSERT( ret == expected );

    if( expected == 0 )
    {
        ret = mbedtls_ecp_check_privkey( &key.grp, &key.d );
        TEST_ASSERT( ret == 0 );
    }

exit:
    mbedtls_ecp_keypair_free( &key );
}

void test_mbedtls_ecp_read_key_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_mbedtls_ecp_read_key( *( (int *) params[0] ), &data1, *( (int *) params[3] ) );
}
#if defined(MBEDTLS_SELF_TEST)
#line 1125 "suites/test_suite_ecp.function"
void test_ecp_selftest(  )
{
    TEST_ASSERT( mbedtls_ecp_self_test( 1 ) == 0 );
exit:
    ;
}

void test_ecp_selftest_wrapper( void ** params )
{
    (void)params;

    test_ecp_selftest(  );
}
#endif /* MBEDTLS_SELF_TEST */
#endif /* MBEDTLS_ECP_C */


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

#if defined(MBEDTLS_ECP_C)

        case 0:
            {
                *out_value = MBEDTLS_ECP_DP_BP512R1;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_ECP_DP_BP384R1;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_ECP_DP_BP256R1;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_ECP_DP_SECP521R1;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_ECP_DP_SECP384R1;
            }
            break;
        case 5:
            {
                *out_value = MBEDTLS_ECP_DP_SECP256R1;
            }
            break;
        case 6:
            {
                *out_value = MBEDTLS_ECP_DP_SECP224R1;
            }
            break;
        case 7:
            {
                *out_value = MBEDTLS_ECP_DP_SECP192R1;
            }
            break;
        case 8:
            {
                *out_value = MBEDTLS_ECP_DP_CURVE25519;
            }
            break;
        case 9:
            {
                *out_value = MBEDTLS_ERR_ECP_INVALID_KEY;
            }
            break;
        case 10:
            {
                *out_value = MBEDTLS_ECP_DP_SECP224K1;
            }
            break;
        case 11:
            {
                *out_value = MBEDTLS_ECP_PF_UNCOMPRESSED;
            }
            break;
        case 12:
            {
                *out_value = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }
            break;
        case 13:
            {
                *out_value = MBEDTLS_ECP_PF_COMPRESSED;
            }
            break;
        case 14:
            {
                *out_value = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            break;
        case 15:
            {
                *out_value = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
            }
            break;
        case 16:
            {
                *out_value = MBEDTLS_ECP_DP_NONE;
            }
            break;
        case 17:
            {
                *out_value = MBEDTLS_ECP_DP_CURVE448;
            }
            break;
        case 18:
            {
                *out_value = INT_MAX;
            }
            break;
        case 19:
            {
                *out_value = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
            }
            break;
        case 20:
            {
                *out_value = MBEDTLS_ECP_DP_SECP192K1;
            }
            break;
        case 21:
            {
                *out_value = MBEDTLS_ECP_DP_SECP256K1;
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

#if defined(MBEDTLS_ECP_C)

        case 0:
            {
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 3:
            {
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 4:
            {
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 5:
            {
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 6:
            {
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 7:
            {
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 8:
            {
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 9:
            {
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 10:
            {
#if !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 11:
            {
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 12:
            {
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 13:
            {
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
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

#if defined(MBEDTLS_ECP_C)
    test_ecp_valid_param_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_ECP_C) && defined(MBEDTLS_CHECK_PARAMS) && !defined(MBEDTLS_PARAM_FAILED_ALT)
    test_ecp_invalid_param_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_ECP_C)
    test_mbedtls_ecp_curve_info_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_ECP_C)
    test_ecp_check_pub_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_ECP_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    test_ecp_test_vect_restart_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_ECP_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    test_ecp_muladd_restart_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_ECP_C)
    test_ecp_test_vect_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_ECP_C)
    test_ecp_test_vec_x_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_ECP_C)
    test_ecp_test_mul_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_ECP_C)
    test_ecp_test_mul_rng_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_ECP_C)
    test_ecp_fast_mod_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_ECP_C)
    test_ecp_write_binary_wrapper,
#else
    NULL,
#endif
/* Function Id: 12 */

#if defined(MBEDTLS_ECP_C)
    test_ecp_read_binary_wrapper,
#else
    NULL,
#endif
/* Function Id: 13 */

#if defined(MBEDTLS_ECP_C)
    test_mbedtls_ecp_tls_read_point_wrapper,
#else
    NULL,
#endif
/* Function Id: 14 */

#if defined(MBEDTLS_ECP_C)
    test_ecp_tls_write_read_point_wrapper,
#else
    NULL,
#endif
/* Function Id: 15 */

#if defined(MBEDTLS_ECP_C)
    test_mbedtls_ecp_tls_read_group_wrapper,
#else
    NULL,
#endif
/* Function Id: 16 */

#if defined(MBEDTLS_ECP_C)
    test_ecp_tls_write_read_group_wrapper,
#else
    NULL,
#endif
/* Function Id: 17 */

#if defined(MBEDTLS_ECP_C)
    test_mbedtls_ecp_check_privkey_wrapper,
#else
    NULL,
#endif
/* Function Id: 18 */

#if defined(MBEDTLS_ECP_C)
    test_mbedtls_ecp_check_pub_priv_wrapper,
#else
    NULL,
#endif
/* Function Id: 19 */

#if defined(MBEDTLS_ECP_C)
    test_mbedtls_ecp_gen_keypair_wrapper,
#else
    NULL,
#endif
/* Function Id: 20 */

#if defined(MBEDTLS_ECP_C)
    test_mbedtls_ecp_gen_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 21 */

#if defined(MBEDTLS_ECP_C)
    test_mbedtls_ecp_read_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 22 */

#if defined(MBEDTLS_ECP_C) && defined(MBEDTLS_SELF_TEST)
    test_ecp_selftest_wrapper,
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
    const char *default_filename = "./test_suite_ecp.datax";
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
