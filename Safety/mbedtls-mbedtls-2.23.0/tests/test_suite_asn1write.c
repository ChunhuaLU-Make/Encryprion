#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_asn1write.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : suites/main_test.function
 *      Platform code file  : suites/host_test.function
 *      Helper file         : suites/helpers.function
 *      Test suite file     : suites/test_suite_asn1write.function
 *      Test suite data     : suites/test_suite_asn1write.data
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

#if defined(MBEDTLS_ASN1_WRITE_C)
#line 2 "suites/test_suite_asn1write.function"
#include "mbedtls/asn1write.h"

#define GUARD_LEN 4
#define GUARD_VAL 0x2a

typedef struct
{
    unsigned char *output;
    unsigned char *start;
    unsigned char *end;
    unsigned char *p;
    size_t size;
} generic_write_data_t;

int generic_write_start_step( generic_write_data_t *data )
{
    test_set_step( data->size );
    ASSERT_ALLOC( data->output, data->size == 0 ? 1 : data->size );
    data->end = data->output + data->size;
    data->p = data->end;
    data->start = data->end - data->size;
    return( 1 );
exit:
    return( 0 );
}

int generic_write_finish_step( generic_write_data_t *data,
                               const data_t *expected, int ret )
{
    int ok = 0;

    if( data->size < expected->len )
    {
        TEST_EQUAL( ret, MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
    }
    else
    {
        TEST_EQUAL( ret, data->end - data->p );
        TEST_ASSERT( data->p >= data->start );
        TEST_ASSERT( data->p <= data->end );
        ASSERT_COMPARE( data->p, (size_t)( data->end - data->p ),
                        expected->x, expected->len );
    }
    ok = 1;

exit:
    mbedtls_free( data->output );
    data->output = NULL;
    return( ok );
}

#line 61 "suites/test_suite_asn1write.function"
void test_mbedtls_asn1_write_null( data_t *expected )
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for( data.size = 0; data.size < expected->len + 1; data.size++ )
    {
        if( ! generic_write_start_step( &data ) )
            goto exit;
        ret = mbedtls_asn1_write_null( &data.p, data.start );
        if( ! generic_write_finish_step( &data, expected, ret ) )
            goto exit;
    }

exit:
    mbedtls_free( data.output );
}

void test_mbedtls_asn1_write_null_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};

    test_mbedtls_asn1_write_null( &data0 );
}
#line 81 "suites/test_suite_asn1write.function"
void test_mbedtls_asn1_write_bool( int val, data_t *expected )
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for( data.size = 0; data.size < expected->len + 1; data.size++ )
    {
        if( ! generic_write_start_step( &data ) )
            goto exit;
        ret = mbedtls_asn1_write_bool( &data.p, data.start, val );
        if( ! generic_write_finish_step( &data, expected, ret ) )
            goto exit;
    }

exit:
    mbedtls_free( data.output );
}

void test_mbedtls_asn1_write_bool_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_mbedtls_asn1_write_bool( *( (int *) params[0] ), &data1 );
}
#line 101 "suites/test_suite_asn1write.function"
void test_mbedtls_asn1_write_int( int val, data_t *expected )
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for( data.size = 0; data.size < expected->len + 1; data.size++ )
    {
        if( ! generic_write_start_step( &data ) )
            goto exit;
        ret = mbedtls_asn1_write_int( &data.p, data.start, val );
        if( ! generic_write_finish_step( &data, expected, ret ) )
            goto exit;
    }

exit:
    mbedtls_free( data.output );
}

void test_mbedtls_asn1_write_int_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_mbedtls_asn1_write_int( *( (int *) params[0] ), &data1 );
}
#line 122 "suites/test_suite_asn1write.function"
void test_mbedtls_asn1_write_enum( int val, data_t *expected )
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for( data.size = 0; data.size < expected->len + 1; data.size++ )
    {
        if( ! generic_write_start_step( &data ) )
            goto exit;
        ret = mbedtls_asn1_write_enum( &data.p, data.start, val );
        if( ! generic_write_finish_step( &data, expected, ret ) )
            goto exit;
    }

exit:
    mbedtls_free( data.output );
}

void test_mbedtls_asn1_write_enum_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_mbedtls_asn1_write_enum( *( (int *) params[0] ), &data1 );
}
#if defined(MBEDTLS_BIGNUM_C)
#line 142 "suites/test_suite_asn1write.function"
void test_mbedtls_asn1_write_mpi( data_t *val, data_t *expected )
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    mbedtls_mpi mpi;
    int ret;

    mbedtls_mpi_init( &mpi );
    TEST_ASSERT( mbedtls_mpi_read_binary( &mpi, val->x, val->len ) == 0 );

    for( data.size = 0; data.size < expected->len + 1; data.size++ )
    {
        if( ! generic_write_start_step( &data ) )
            goto exit;
        ret = mbedtls_asn1_write_mpi( &data.p, data.start, &mpi );
        if( ! generic_write_finish_step( &data, expected, ret ) )
            goto exit;
        if( expected->len > 10 && data.size == 8 )
            data.size = expected->len - 2;
    }

exit:
    mbedtls_mpi_free( &mpi );
    mbedtls_free( data.output );
}

void test_mbedtls_asn1_write_mpi_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};

    test_mbedtls_asn1_write_mpi( &data0, &data2 );
}
#endif /* MBEDTLS_BIGNUM_C */
#line 169 "suites/test_suite_asn1write.function"
void test_mbedtls_asn1_write_string( int tag, data_t *content, data_t *expected )
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for( data.size = 0; data.size < expected->len + 1; data.size++ )
    {
        if( ! generic_write_start_step( &data ) )
            goto exit;
        switch( tag )
        {
            case MBEDTLS_ASN1_OCTET_STRING:
                ret = mbedtls_asn1_write_octet_string(
                    &data.p, data.start, content->x, content->len );
                break;
            case MBEDTLS_ASN1_OID:
                ret = mbedtls_asn1_write_oid(
                    &data.p, data.start,
                    (const char *) content->x, content->len );
                break;
            case MBEDTLS_ASN1_UTF8_STRING:
                ret = mbedtls_asn1_write_utf8_string(
                    &data.p, data.start,
                    (const char *) content->x, content->len );
                break;
            case MBEDTLS_ASN1_PRINTABLE_STRING:
                ret = mbedtls_asn1_write_printable_string(
                    &data.p, data.start,
                    (const char *) content->x, content->len );
                break;
            case MBEDTLS_ASN1_IA5_STRING:
                ret = mbedtls_asn1_write_ia5_string(
                    &data.p, data.start,
                    (const char *) content->x, content->len );
                break;
            default:
                ret = mbedtls_asn1_write_tagged_string(
                    &data.p, data.start, tag,
                    (const char *) content->x, content->len );
        }
        if( ! generic_write_finish_step( &data, expected, ret ) )
            goto exit;
        if( expected->len > 10 && data.size == 8 )
            data.size = expected->len - 2;
    }

exit:
    mbedtls_free( data.output );
}

void test_mbedtls_asn1_write_string_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_mbedtls_asn1_write_string( *( (int *) params[0] ), &data1, &data3 );
}
#line 221 "suites/test_suite_asn1write.function"
void test_mbedtls_asn1_write_algorithm_identifier( data_t *oid,
                                              int par_len,
                                              data_t *expected )
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for( data.size = 0; data.size < expected->len + 1; data.size++ )
    {
        if( ! generic_write_start_step( &data ) )
            goto exit;
        ret = mbedtls_asn1_write_algorithm_identifier(
            &data.p, data.start,
            (const char *) oid->x, oid->len, par_len );
        /* If params_len != 0, mbedtls_asn1_write_algorithm_identifier()
         * assumes that the parameters are already present in the buffer
         * and returns a length that accounts for this, but our test
         * data omits the parameters. */
        if( ret >= 0 )
            ret -= par_len;
        if( ! generic_write_finish_step( &data, expected, ret ) )
            goto exit;
    }

exit:
    mbedtls_free( data.output );
}

void test_mbedtls_asn1_write_algorithm_identifier_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_mbedtls_asn1_write_algorithm_identifier( &data0, *( (int *) params[2] ), &data3 );
}
#if defined(MBEDTLS_ASN1_PARSE_C)
#line 251 "suites/test_suite_asn1write.function"
void test_mbedtls_asn1_write_len( int len, data_t * asn1, int buf_len,
                             int result )
{
    int ret;
    unsigned char buf[150];
    unsigned char *p;
    size_t i;
    size_t read_len;

    memset( buf, GUARD_VAL, sizeof( buf ) );

    p = buf + GUARD_LEN + buf_len;

    ret = mbedtls_asn1_write_len( &p, buf + GUARD_LEN, (size_t) len );

    TEST_ASSERT( ret == result );

    /* Check for buffer overwrite on both sides */
    for( i = 0; i < GUARD_LEN; i++ )
    {
        TEST_ASSERT( buf[i] == GUARD_VAL );
        TEST_ASSERT( buf[GUARD_LEN + buf_len + i] == GUARD_VAL );
    }

    if( result >= 0 )
    {
        TEST_ASSERT( p + asn1->len == buf + GUARD_LEN + buf_len );

        TEST_ASSERT( memcmp( p, asn1->x, asn1->len ) == 0 );

        /* Read back with mbedtls_asn1_get_len() to check */
        ret = mbedtls_asn1_get_len( &p, buf + GUARD_LEN + buf_len, &read_len );

        if( len == 0 )
        {
            TEST_ASSERT( ret == 0 );
        }
        else
        {
            /* Return will be MBEDTLS_ERR_ASN1_OUT_OF_DATA because the rest of
             * the buffer is missing
             */
            TEST_ASSERT( ret == MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        }
        TEST_ASSERT( read_len == (size_t) len );
        TEST_ASSERT( p == buf + GUARD_LEN + buf_len );
    }
exit:
    ;
}

void test_mbedtls_asn1_write_len_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_mbedtls_asn1_write_len( *( (int *) params[0] ), &data1, *( (int *) params[3] ), *( (int *) params[4] ) );
}
#endif /* MBEDTLS_ASN1_PARSE_C */
#line 302 "suites/test_suite_asn1write.function"
void test_test_asn1_write_bitstrings( data_t *bitstring, int bits,
                                 data_t *expected, int is_named )
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;
    int ( *func )( unsigned char **p, unsigned char *start,
                   const unsigned char *buf, size_t bits ) =
        ( is_named ? mbedtls_asn1_write_named_bitstring :
          mbedtls_asn1_write_bitstring );

    for( data.size = 0; data.size < expected->len + 1; data.size++ )
    {
        if( ! generic_write_start_step( &data ) )
            goto exit;
        ret = ( *func )( &data.p, data.start, bitstring->x, bits );
        if( ! generic_write_finish_step( &data, expected, ret ) )
            goto exit;
    }

exit:
    mbedtls_free( data.output );
}

void test_test_asn1_write_bitstrings_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_test_asn1_write_bitstrings( &data0, *( (int *) params[2] ), &data3, *( (int *) params[5] ) );
}
#line 327 "suites/test_suite_asn1write.function"
void test_store_named_data_find( data_t *oid0, data_t *oid1,
                            data_t *oid2, data_t *oid3,
                            data_t *needle, int from, int position )
{
    data_t *oid[4] = {oid0, oid1, oid2, oid3};
    mbedtls_asn1_named_data nd[] ={
        { {0x06, 0, NULL}, {0, 0, NULL}, NULL, 0 },
        { {0x06, 0, NULL}, {0, 0, NULL}, NULL, 0 },
        { {0x06, 0, NULL}, {0, 0, NULL}, NULL, 0 },
        { {0x06, 0, NULL}, {0, 0, NULL}, NULL, 0 },
    };
    mbedtls_asn1_named_data *pointers[ARRAY_LENGTH( nd ) + 1];
    size_t i;
    mbedtls_asn1_named_data *head = NULL;
    mbedtls_asn1_named_data *found = NULL;

    for( i = 0; i < ARRAY_LENGTH( nd ); i++ )
        pointers[i] = &nd[i];
    pointers[ARRAY_LENGTH( nd )] = NULL;
    for( i = 0; i < ARRAY_LENGTH( nd ); i++ )
    {
        ASSERT_ALLOC( nd[i].oid.p, oid[i]->len );
        memcpy( nd[i].oid.p, oid[i]->x, oid[i]->len );
        nd[i].oid.len = oid[i]->len;
        nd[i].next = pointers[i+1];
    }

    head = pointers[from];
    found = mbedtls_asn1_store_named_data( &head,
                                           (const char *) needle->x,
                                           needle->len,
                                           NULL, 0 );

    /* In any case, the existing list structure must be unchanged. */
    for( i = 0; i < ARRAY_LENGTH( nd ); i++ )
        TEST_ASSERT( nd[i].next == pointers[i+1] );

    if( position >= 0 )
    {
        /* position should have been found and modified. */
        TEST_ASSERT( head == pointers[from] );
        TEST_ASSERT( found == pointers[position] );
    }
    else
    {
        /* A new entry should have been created. */
        TEST_ASSERT( found == head );
        TEST_ASSERT( head->next == pointers[from] );
        for( i = 0; i < ARRAY_LENGTH( nd ); i++ )
            TEST_ASSERT( found != &nd[i] );
    }

exit:
    if( found != NULL && found == head && found != pointers[from] )
    {
        mbedtls_free( found->oid.p );
        mbedtls_free( found );
    }
    for( i = 0; i < ARRAY_LENGTH( nd ); i++ )
        mbedtls_free( nd[i].oid.p );
}

void test_store_named_data_find_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};

    test_store_named_data_find( &data0, &data2, &data4, &data6, &data8, *( (int *) params[10] ), *( (int *) params[11] ) );
}
#line 391 "suites/test_suite_asn1write.function"
void test_store_named_data_val_found( int old_len, int new_len )
{
    mbedtls_asn1_named_data nd =
        { {0x06, 3, (unsigned char *) "OID"}, {0, 0, NULL}, NULL, 0 };
    mbedtls_asn1_named_data *head = &nd;
    mbedtls_asn1_named_data *found = NULL;
    unsigned char *old_val = NULL;
    unsigned char *new_val = (unsigned char *) "new value";

    if( old_len != 0 )
    {
        ASSERT_ALLOC( nd.val.p, (size_t) old_len );
        old_val = nd.val.p;
        nd.val.len = old_len;
        memset( old_val, 'x', old_len );
    }
    if( new_len <= 0 )
    {
        new_len = - new_len;
        new_val = NULL;
    }

    found = mbedtls_asn1_store_named_data( &head, "OID", 3,
                                           new_val, new_len );
    TEST_ASSERT( head == &nd );
    TEST_ASSERT( found == head );

    if( new_val != NULL)
        ASSERT_COMPARE( found->val.p, found->val.len,
                        new_val, (size_t) new_len );
    if( new_len == 0)
        TEST_ASSERT( found->val.p == NULL );
    else if( new_len == old_len )
        TEST_ASSERT( found->val.p == old_val );
    else
        TEST_ASSERT( found->val.p != old_val );

exit:
    mbedtls_free( nd.val.p );
}

void test_store_named_data_val_found_wrapper( void ** params )
{

    test_store_named_data_val_found( *( (int *) params[0] ), *( (int *) params[1] ) );
}
#line 434 "suites/test_suite_asn1write.function"
void test_store_named_data_val_new( int new_len )
{
    mbedtls_asn1_named_data *head = NULL;
    mbedtls_asn1_named_data *found = NULL;
    const unsigned char *oid = (unsigned char *) "OID";
    size_t oid_len = strlen( (const char *) oid );
    const unsigned char *new_val = (unsigned char *) "new value";

    if( new_len <= 0 )
        new_val = NULL;
    if( new_len < 0 )
        new_len = - new_len;

    found = mbedtls_asn1_store_named_data( &head,
                                           (const char *) oid, oid_len,
                                           new_val, (size_t) new_len );
    TEST_ASSERT( found != NULL );
    TEST_ASSERT( found == head );
    TEST_ASSERT( found->oid.p != oid );
    ASSERT_COMPARE( found->oid.p, found->oid.len, oid, oid_len );
    if( new_len == 0 )
        TEST_ASSERT( found->val.p == NULL );
    else if( new_val == NULL )
        TEST_ASSERT( found->val.p != NULL );
    else
    {
        TEST_ASSERT( found->val.p != new_val );
        ASSERT_COMPARE( found->val.p, found->val.len,
                        new_val, (size_t) new_len );
    }

exit:
    if( found != NULL )
    {
        mbedtls_free( found->oid.p );
        mbedtls_free( found->val.p );
    }
    mbedtls_free( found );
}

void test_store_named_data_val_new_wrapper( void ** params )
{

    test_store_named_data_val_new( *( (int *) params[0] ) );
}
#endif /* MBEDTLS_ASN1_WRITE_C */


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

#if defined(MBEDTLS_ASN1_WRITE_C)

        case 0:
            {
                *out_value = MBEDTLS_ASN1_OCTET_STRING;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_ASN1_UTF8_STRING;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_ASN1_PRINTABLE_STRING;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_ASN1_IA5_STRING;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_ASN1_IA5_STRING | MBEDTLS_ASN1_CONTEXT_SPECIFIC;
            }
            break;
        case 5:
            {
                *out_value = MBEDTLS_ASN1_OID;
            }
            break;
        case 6:
            {
                *out_value = MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
            }
            break;
        case 7:
            {
                *out_value = -1;
            }
            break;
        case 8:
            {
                *out_value = -4;
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

#if defined(MBEDTLS_ASN1_WRITE_C)

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

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_null_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_bool_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_int_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_enum_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_ASN1_WRITE_C) && defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_asn1_write_mpi_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_string_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_algorithm_identifier_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_ASN1_WRITE_C) && defined(MBEDTLS_ASN1_PARSE_C)
    test_mbedtls_asn1_write_len_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_test_asn1_write_bitstrings_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_store_named_data_find_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_store_named_data_val_found_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_store_named_data_val_new_wrapper,
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
    const char *default_filename = "./test_suite_asn1write.datax";
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
