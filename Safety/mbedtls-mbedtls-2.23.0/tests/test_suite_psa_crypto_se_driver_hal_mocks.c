#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_psa_crypto_se_driver_hal_mocks.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : suites/main_test.function
 *      Platform code file  : suites/host_test.function
 *      Helper file         : suites/helpers.function
 *      Test suite file     : suites/test_suite_psa_crypto_se_driver_hal_mocks.function
 *      Test suite data     : suites/test_suite_psa_crypto_se_driver_hal_mocks.data
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

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
#line 2 "suites/test_suite_psa_crypto_se_driver_hal_mocks.function"
#include "test/psa_crypto_helpers.h"
#include "psa/crypto_se_driver.h"

#include "psa_crypto_se.h"
#include "psa_crypto_storage.h"

/** The location and lifetime used for tests that use a single driver. */
#define TEST_DRIVER_LOCATION 1
#define TEST_SE_PERSISTENT_LIFETIME                             \
    ( PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(           \
        PSA_KEY_PERSISTENCE_DEFAULT, TEST_DRIVER_LOCATION ) )

static struct
{
    uint16_t called;
    psa_key_location_t location;
    psa_status_t return_value;
} mock_init_data;

static struct
{
    uint16_t called;
    psa_key_slot_number_t key_slot;
    psa_key_attributes_t attributes;
    size_t pubkey_size;
    psa_status_t return_value;
} mock_generate_data;

static struct
{
    uint16_t called;
    psa_key_slot_number_t key_slot;
    psa_key_attributes_t attributes;
    size_t bits;
    size_t data_length;
    psa_status_t return_value;
} mock_import_data;

static struct
{
    uint16_t called;
    psa_key_slot_number_t slot_number;
    size_t data_size;
    psa_status_t return_value;
} mock_export_data;

static struct
{
    uint16_t called;
    psa_key_slot_number_t slot_number;
    size_t data_size;
    psa_status_t return_value;
} mock_export_public_data;

static struct
{
    uint16_t called;
    psa_key_slot_number_t key_slot;
    psa_algorithm_t alg;
    size_t hash_length;
    size_t signature_size;
    psa_status_t return_value;
} mock_sign_data;

static struct
{
    uint16_t called;
    psa_key_slot_number_t key_slot;
    psa_algorithm_t alg;
    size_t hash_length;
    size_t signature_length;
    psa_status_t return_value;
} mock_verify_data;

static struct
{
    uint16_t called;
    psa_status_t return_value;
} mock_allocate_data;

static struct
{
    uint16_t called;
    psa_key_slot_number_t slot_number;
    psa_status_t return_value;
} mock_destroy_data;

#define MAX_KEY_ID_FOR_TEST 10
static void psa_purge_storage( void )
{
    psa_key_id_t id;
    psa_key_location_t location;
    /* The tests may have potentially created key ids from 1 to
     * MAX_KEY_ID_FOR_TEST. In addition, run the destroy function on key id
     * 0, which file-based storage uses as a temporary file. */
    for( id = 0; id <= MAX_KEY_ID_FOR_TEST; id++ )
        psa_destroy_persistent_key( id );
    /* Purge the transaction file. */
    psa_crypto_stop_transaction( );
    /* Purge driver persistent data. */
    for( location = 0; location < PSA_MAX_SE_LOCATION; location++ )
        psa_destroy_se_persistent_data( location );
}

static void mock_teardown( void )
{
    memset( &mock_init_data, 0, sizeof( mock_init_data ) );
    memset( &mock_import_data, 0, sizeof( mock_import_data ) );
    memset( &mock_export_data, 0, sizeof( mock_export_data ) );
    memset( &mock_export_public_data, 0, sizeof( mock_export_public_data ) );
    memset( &mock_sign_data, 0, sizeof( mock_sign_data ) );
    memset( &mock_verify_data, 0, sizeof( mock_verify_data ) );
    memset( &mock_allocate_data, 0, sizeof( mock_allocate_data ) );
    memset( &mock_destroy_data, 0, sizeof( mock_destroy_data ) );
    memset( &mock_generate_data, 0, sizeof( mock_generate_data ) );
    psa_purge_storage( );
}

static psa_status_t mock_init( psa_drv_se_context_t *drv_context,
                               void *persistent_data,
                               psa_key_location_t location )
{
    (void) drv_context;
    (void) persistent_data;

    mock_init_data.called++;
    mock_init_data.location = location;
    return( mock_init_data.return_value );
}

static psa_status_t mock_generate( psa_drv_se_context_t *drv_context,
                                   psa_key_slot_number_t key_slot,
                                   const psa_key_attributes_t *attributes,
                                   uint8_t *pubkey,
                                   size_t pubkey_size,
                                   size_t *pubkey_length )
{
    (void) drv_context;
    (void) pubkey;
    (void) pubkey_length;

    mock_generate_data.called++;
    mock_generate_data.key_slot = key_slot;
    mock_generate_data.attributes = *attributes;
    mock_generate_data.pubkey_size = pubkey_size;

    return( mock_generate_data.return_value );
}

static psa_status_t mock_import( psa_drv_se_context_t *drv_context,
                                 psa_key_slot_number_t key_slot,
                                 const psa_key_attributes_t *attributes,
                                 const uint8_t *data,
                                 size_t data_length,
                                 size_t *bits )
{
    (void) drv_context;
    (void) data;

    *bits = mock_import_data.bits;

    mock_import_data.called++;
    mock_import_data.key_slot = key_slot;
    mock_import_data.attributes = *attributes;
    mock_import_data.data_length = data_length;

    return( mock_import_data.return_value );
}

psa_status_t mock_export( psa_drv_se_context_t *context,
                          psa_key_slot_number_t slot_number,
                          uint8_t *p_data,
                          size_t data_size,
                          size_t *p_data_length )
{
    (void) context;
    (void) p_data;
    (void) p_data_length;

    mock_export_data.called++;
    mock_export_data.slot_number = slot_number;
    mock_export_data.data_size = data_size;

    return( mock_export_data.return_value );
}

psa_status_t mock_export_public( psa_drv_se_context_t *context,
                                 psa_key_slot_number_t slot_number,
                                 uint8_t *p_data,
                                 size_t data_size,
                                 size_t *p_data_length )
{
    (void) context;
    (void) p_data;
    (void) p_data_length;

    mock_export_public_data.called++;
    mock_export_public_data.slot_number = slot_number;
    mock_export_public_data.data_size = data_size;

    return( mock_export_public_data.return_value );
}

psa_status_t mock_sign( psa_drv_se_context_t *context,
                        psa_key_slot_number_t key_slot,
                        psa_algorithm_t alg,
                        const uint8_t *p_hash,
                        size_t hash_length,
                        uint8_t *p_signature,
                        size_t signature_size,
                        size_t *p_signature_length )
{
    (void) context;
    (void) p_hash;
    (void) p_signature;
    (void) p_signature_length;

    mock_sign_data.called++;
    mock_sign_data.key_slot = key_slot;
    mock_sign_data.alg = alg;
    mock_sign_data.hash_length = hash_length;
    mock_sign_data.signature_size = signature_size;

    return mock_sign_data.return_value;
}

psa_status_t mock_verify( psa_drv_se_context_t *context,
                          psa_key_slot_number_t key_slot,
                          psa_algorithm_t alg,
                          const uint8_t *p_hash,
                          size_t hash_length,
                          const uint8_t *p_signature,
                          size_t signature_length )
{
    (void) context;
    (void) p_hash;
    (void) p_signature;

    mock_verify_data.called++;
    mock_verify_data.key_slot = key_slot;
    mock_verify_data.alg = alg;
    mock_verify_data.hash_length = hash_length;
    mock_verify_data.signature_length = signature_length;

    return mock_verify_data.return_value;
}

psa_status_t mock_allocate( psa_drv_se_context_t *drv_context,
                            void *persistent_data,
                            const psa_key_attributes_t *attributes,
                            psa_key_creation_method_t method,
                            psa_key_slot_number_t *key_slot )
{
    (void) drv_context;
    (void) persistent_data;
    (void) attributes;
    (void) method;
    (void) key_slot;

    mock_allocate_data.called++;
    *key_slot = 0;

    return( mock_allocate_data.return_value );
}

psa_status_t mock_destroy( psa_drv_se_context_t *context,
                           void *persistent_data,
                           psa_key_slot_number_t slot_number )
{
    (void) context;
    (void) persistent_data;

    mock_destroy_data.called++;
    mock_destroy_data.slot_number = slot_number;

    return( mock_destroy_data.return_value );
}

#line 288 "suites/test_suite_psa_crypto_se_driver_hal_mocks.function"
void test_mock_init( int location_arg,
                int expected_register_status_arg,
                int driver_status_arg,
                int expected_psa_status_arg,
                int expected_called )
{
    psa_key_location_t location = location_arg;
    psa_status_t expected_register_status = expected_register_status_arg;
    psa_status_t driver_status = driver_status_arg;
    psa_status_t expected_psa_status = expected_psa_status_arg;
    psa_drv_se_t driver = {
        .hal_version = PSA_DRV_SE_HAL_VERSION,
        .p_init = mock_init,
    };
    int psa_crypto_init_called = 0;

    mock_init_data.return_value = driver_status;

    TEST_EQUAL( psa_register_se_driver( location, &driver ),
                expected_register_status );

    psa_crypto_init_called = 1;
    TEST_EQUAL( psa_crypto_init( ), expected_psa_status );

    TEST_EQUAL( mock_init_data.called, expected_called );
    if( expected_called )
        TEST_EQUAL( mock_init_data.location, location );

exit:
    if( psa_crypto_init_called )
        PSA_DONE( );
    mock_teardown( );
}

void test_mock_init_wrapper( void ** params )
{

    test_mock_init( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ) );
}
#line 324 "suites/test_suite_psa_crypto_se_driver_hal_mocks.function"
void test_mock_import( int mock_alloc_return_value,
                  int mock_import_return_value,
                  int bits,
                  int expected_result )
{
    psa_drv_se_t driver;
    psa_drv_se_key_management_t key_management;
    psa_key_lifetime_t lifetime = TEST_SE_PERSISTENT_LIFETIME;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( lifetime );
    psa_key_id_t id = 1;
    psa_key_handle_t handle = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    const uint8_t key_material[3] = {0xfa, 0xca, 0xde};

    mock_allocate_data.return_value = mock_alloc_return_value;
    mock_import_data.return_value = mock_import_return_value;
    mock_import_data.bits = bits;
    memset( &driver, 0, sizeof( driver ) );
    memset( &key_management, 0, sizeof( key_management ) );
    driver.hal_version = PSA_DRV_SE_HAL_VERSION;
    driver.key_management = &key_management;
    key_management.p_import = mock_import;
    key_management.p_destroy = mock_destroy;
    key_management.p_allocate = mock_allocate;

    PSA_ASSERT( psa_register_se_driver( location, &driver ) );
    PSA_ASSERT( psa_crypto_init( ) );

    psa_set_key_id( &attributes, id );
    psa_set_key_lifetime( &attributes, lifetime );
    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_EXPORT );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_RAW_DATA );
    TEST_ASSERT( psa_import_key( &attributes,
                                 key_material, sizeof( key_material ),
                                 &handle ) == expected_result );

    TEST_ASSERT( mock_allocate_data.called == 1 );
    TEST_ASSERT( mock_import_data.called ==
        ( mock_alloc_return_value == PSA_SUCCESS? 1 : 0 ) );
    TEST_ASSERT( mock_import_data.attributes.core.id ==
        ( mock_alloc_return_value == PSA_SUCCESS? id : 0 ) );
    TEST_ASSERT( mock_import_data.attributes.core.lifetime ==
        ( mock_alloc_return_value == PSA_SUCCESS? lifetime : 0 ) );
    TEST_ASSERT( mock_import_data.attributes.core.policy.usage ==
        ( mock_alloc_return_value == PSA_SUCCESS? PSA_KEY_USAGE_EXPORT : 0 ) );
    TEST_ASSERT( mock_import_data.attributes.core.type ==
        ( mock_alloc_return_value == PSA_SUCCESS? PSA_KEY_TYPE_RAW_DATA : 0 ) );

    if( expected_result == PSA_SUCCESS )
    {
        PSA_ASSERT( psa_destroy_key( handle ) );
        TEST_ASSERT( mock_destroy_data.called == 1 );
    }
exit:
    PSA_DONE( );
    mock_teardown( );
}

void test_mock_import_wrapper( void ** params )
{

    test_mock_import( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ) );
}
#line 384 "suites/test_suite_psa_crypto_se_driver_hal_mocks.function"
void test_mock_export( int mock_export_return_value, int expected_result )
{
    psa_drv_se_t driver;
    psa_drv_se_key_management_t key_management;
    psa_key_lifetime_t lifetime = TEST_SE_PERSISTENT_LIFETIME;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( lifetime );
    psa_key_id_t id = 1;
    psa_key_handle_t handle = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    const uint8_t key_material[3] = {0xfa, 0xca, 0xde};
    uint8_t exported[sizeof( key_material )];
    size_t exported_length;

    mock_export_data.return_value = mock_export_return_value;
    memset( &driver, 0, sizeof( driver ) );
    memset( &key_management, 0, sizeof( key_management ) );
    driver.hal_version = PSA_DRV_SE_HAL_VERSION;
    driver.key_management = &key_management;
    driver.p_init = mock_init;
    key_management.p_import = mock_import;
    key_management.p_export = mock_export;
    key_management.p_destroy = mock_destroy;
    key_management.p_allocate = mock_allocate;

    PSA_ASSERT( psa_register_se_driver( location, &driver ) );
    PSA_ASSERT( psa_crypto_init( ) );

    psa_set_key_id( &attributes, id );
    psa_set_key_lifetime( &attributes, lifetime );
    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_EXPORT );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_RAW_DATA );
    PSA_ASSERT( psa_import_key( &attributes,
                                key_material, sizeof( key_material ),
                                &handle ) );

    TEST_ASSERT( psa_export_key( handle,
                                exported, sizeof( exported ),
                                &exported_length ) == expected_result );

    TEST_ASSERT( mock_export_data.called == 1 );

    PSA_ASSERT( psa_destroy_key( handle ) );

    TEST_ASSERT( mock_destroy_data.called == 1 );

exit:
    PSA_DONE( );
    mock_teardown( );
}

void test_mock_export_wrapper( void ** params )
{

    test_mock_export( *( (int *) params[0] ), *( (int *) params[1] ) );
}
#line 436 "suites/test_suite_psa_crypto_se_driver_hal_mocks.function"
void test_mock_generate( int mock_alloc_return_value,
                    int mock_generate_return_value,
                    int expected_result )
{
    psa_drv_se_t driver;
    psa_drv_se_key_management_t key_management;
    psa_key_lifetime_t lifetime = TEST_SE_PERSISTENT_LIFETIME;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( lifetime );
    psa_key_id_t id = 1;
    psa_key_handle_t handle = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    mock_allocate_data.return_value = mock_alloc_return_value;
    mock_generate_data.return_value = mock_generate_return_value;
    memset( &driver, 0, sizeof( driver ) );
    memset( &key_management, 0, sizeof( key_management ) );
    driver.hal_version = PSA_DRV_SE_HAL_VERSION;
    driver.key_management = &key_management;
    key_management.p_generate = mock_generate;
    key_management.p_destroy = mock_destroy;
    key_management.p_allocate = mock_allocate;

    PSA_ASSERT( psa_register_se_driver( location, &driver ) );
    PSA_ASSERT( psa_crypto_init( ) );

    psa_set_key_id( &attributes, id );
    psa_set_key_lifetime( &attributes, lifetime );
    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_EXPORT );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_RAW_DATA );
    psa_set_key_bits( &attributes, 8 );
    TEST_ASSERT( psa_generate_key( &attributes, &handle ) == expected_result );
    TEST_ASSERT( mock_allocate_data.called == 1 );
    TEST_ASSERT( mock_generate_data.called ==
        ( mock_alloc_return_value == PSA_SUCCESS? 1 : 0 ) );
    TEST_ASSERT( mock_generate_data.attributes.core.id ==
        ( mock_alloc_return_value == PSA_SUCCESS? id : 0 ) );
    TEST_ASSERT( mock_generate_data.attributes.core.lifetime ==
        ( mock_alloc_return_value == PSA_SUCCESS? lifetime : 0 ) );
    TEST_ASSERT( mock_generate_data.attributes.core.policy.usage ==
        ( mock_alloc_return_value == PSA_SUCCESS? PSA_KEY_USAGE_EXPORT : 0 ) );
    TEST_ASSERT( mock_generate_data.attributes.core.type ==
        ( mock_alloc_return_value == PSA_SUCCESS? PSA_KEY_TYPE_RAW_DATA : 0 ) );

    if( expected_result == PSA_SUCCESS )
    {
        PSA_ASSERT( psa_destroy_key( handle ) );
        TEST_ASSERT( mock_destroy_data.called == 1 );
    }

exit:
    PSA_DONE( );
    mock_teardown( );
}

void test_mock_generate_wrapper( void ** params )
{

    test_mock_generate( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ) );
}
#line 492 "suites/test_suite_psa_crypto_se_driver_hal_mocks.function"
void test_mock_export_public( int mock_export_public_return_value,
                         int expected_result )
{
    psa_drv_se_t driver;
    psa_drv_se_key_management_t key_management;
    psa_key_lifetime_t lifetime = TEST_SE_PERSISTENT_LIFETIME;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( lifetime );
    psa_key_id_t id = 1;
    psa_key_handle_t handle = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    const uint8_t key_material[3] = {0xfa, 0xca, 0xde};
    uint8_t exported[sizeof( key_material )];
    size_t exported_length;

    mock_export_public_data.return_value = mock_export_public_return_value;
    memset( &driver, 0, sizeof( driver ) );
    memset( &key_management, 0, sizeof( key_management ) );
    driver.hal_version = PSA_DRV_SE_HAL_VERSION;
    driver.key_management = &key_management;
    key_management.p_import = mock_import;
    key_management.p_export_public = mock_export_public;
    key_management.p_destroy = mock_destroy;
    key_management.p_allocate = mock_allocate;

    PSA_ASSERT( psa_register_se_driver( location, &driver ) );
    PSA_ASSERT( psa_crypto_init( ) );

    psa_set_key_id( &attributes, id );
    psa_set_key_lifetime( &attributes, lifetime );
    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_EXPORT );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY );

    PSA_ASSERT( psa_import_key( &attributes,
                                key_material, sizeof( key_material ),
                                &handle ) );

    TEST_ASSERT( psa_export_public_key( handle, exported, sizeof(exported),
                                        &exported_length ) == expected_result );
    TEST_ASSERT( mock_export_public_data.called == 1 );

    PSA_ASSERT( psa_destroy_key( handle ) );
    TEST_ASSERT( mock_destroy_data.called == 1 );

exit:
    PSA_DONE( );
    mock_teardown( );
}

void test_mock_export_public_wrapper( void ** params )
{

    test_mock_export_public( *( (int *) params[0] ), *( (int *) params[1] ) );
}
#line 542 "suites/test_suite_psa_crypto_se_driver_hal_mocks.function"
void test_mock_sign( int mock_sign_return_value, int expected_result )
{
    psa_drv_se_t driver;
    psa_drv_se_key_management_t key_management;
    psa_drv_se_asymmetric_t asymmetric;
    psa_key_lifetime_t lifetime = TEST_SE_PERSISTENT_LIFETIME;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( lifetime );
    psa_key_id_t id = 1;
    psa_key_handle_t handle = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    const uint8_t key_material[3] = {0xfa, 0xca, 0xde};
    psa_algorithm_t algorithm = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    const uint8_t hash[1] = {'H'};
    uint8_t signature[1] = {'S'};
    size_t signature_length;

    mock_sign_data.return_value = mock_sign_return_value;
    memset( &driver, 0, sizeof( driver ) );
    memset( &key_management, 0, sizeof( key_management ) );
    memset( &asymmetric, 0, sizeof( asymmetric ) );

    driver.hal_version = PSA_DRV_SE_HAL_VERSION;

    driver.key_management = &key_management;
    key_management.p_import = mock_import;
    key_management.p_destroy = mock_destroy;
    key_management.p_allocate = mock_allocate;

    driver.asymmetric = &asymmetric;
    asymmetric.p_sign = mock_sign;

    PSA_ASSERT( psa_register_se_driver( location, &driver ) );
    PSA_ASSERT( psa_crypto_init( ) );

    psa_set_key_id( &attributes, id );
    psa_set_key_lifetime( &attributes, lifetime );
    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_SIGN_HASH );
    psa_set_key_algorithm( &attributes, algorithm );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_RSA_KEY_PAIR );

    PSA_ASSERT( psa_import_key( &attributes,
                                key_material, sizeof( key_material ),
                                &handle ) );

    TEST_ASSERT( psa_sign_hash( handle, algorithm,
                                hash, sizeof( hash ),
                                signature, sizeof( signature ),
                                &signature_length)
                 == expected_result );
    TEST_ASSERT( mock_sign_data.called == 1 );

    PSA_ASSERT( psa_destroy_key( handle ) );
    TEST_ASSERT( mock_destroy_data.called == 1 );

exit:
    PSA_DONE( );
    mock_teardown( );
}

void test_mock_sign_wrapper( void ** params )
{

    test_mock_sign( *( (int *) params[0] ), *( (int *) params[1] ) );
}
#line 603 "suites/test_suite_psa_crypto_se_driver_hal_mocks.function"
void test_mock_verify( int mock_verify_return_value, int expected_result )
{
    psa_drv_se_t driver;
    psa_drv_se_key_management_t key_management;
    psa_drv_se_asymmetric_t asymmetric;
    psa_key_lifetime_t lifetime = TEST_SE_PERSISTENT_LIFETIME;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( lifetime );
    psa_key_id_t id = 1;
    psa_key_handle_t handle = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    const uint8_t key_material[3] = {0xfa, 0xca, 0xde};
    psa_algorithm_t algorithm = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    const uint8_t hash[1] = {'H'};
    const uint8_t signature[1] = {'S'};

    mock_verify_data.return_value = mock_verify_return_value;
    memset( &driver, 0, sizeof( driver ) );
    memset( &key_management, 0, sizeof( key_management ) );
    memset( &asymmetric, 0, sizeof( asymmetric ) );

    driver.hal_version = PSA_DRV_SE_HAL_VERSION;

    driver.key_management = &key_management;
    key_management.p_import = mock_import;
    key_management.p_destroy = mock_destroy;
    key_management.p_allocate = mock_allocate;

    driver.asymmetric = &asymmetric;
    asymmetric.p_verify = mock_verify;

    PSA_ASSERT( psa_register_se_driver( location, &driver ) );
    PSA_ASSERT( psa_crypto_init( ) );

    psa_set_key_id( &attributes, id );
    psa_set_key_lifetime( &attributes, lifetime );
    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_VERIFY_HASH );
    psa_set_key_algorithm( &attributes, algorithm );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_RAW_DATA );

    PSA_ASSERT( psa_import_key( &attributes,
                                key_material, sizeof( key_material ),
                                &handle ) );

    TEST_ASSERT( psa_verify_hash( handle, algorithm,
                                  hash, sizeof( hash ),
                                  signature, sizeof( signature ) )
                 == expected_result );
    TEST_ASSERT( mock_verify_data.called == 1 );

    PSA_ASSERT( psa_destroy_key( handle ) );
    TEST_ASSERT( mock_destroy_data.called == 1 );

exit:
    PSA_DONE( );
    mock_teardown( );
}

void test_mock_verify_wrapper( void ** params )
{

    test_mock_verify( *( (int *) params[0] ), *( (int *) params[1] ) );
}
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */


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

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)

        case 0:
            {
                *out_value = PSA_SUCCESS;
            }
            break;
        case 1:
            {
                *out_value = PSA_ERROR_HARDWARE_FAILURE;
            }
            break;
        case 2:
            {
                *out_value = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case 3:
            {
                *out_value = PSA_ERROR_BAD_STATE;
            }
            break;
        case 4:
            {
                *out_value = INT_MAX;
            }
            break;
        case 5:
            {
                *out_value = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case 6:
            {
                *out_value = PSA_MAX_KEY_BITS;
            }
            break;
        case 7:
            {
                *out_value = PSA_MAX_KEY_BITS+1;
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

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)

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

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    test_mock_init_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    test_mock_import_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    test_mock_export_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    test_mock_generate_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    test_mock_export_public_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    test_mock_sign_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    test_mock_verify_wrapper,
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
    const char *default_filename = "./test_suite_psa_crypto_se_driver_hal_mocks.datax";
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
