#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Forward declaration of the function under test from gdbtcp.c */
extern err_t gdb_input(void *z, struct tcp_pcb *pcb, struct pbuf *p, err_t err);

START_TEST(test_gdb_endpoint_rejects_unauthenticated_requests)
{
    /* Invariant: Protected GDB endpoints must reject unauthenticated requests
       with authentication failure response, not process debug commands */
    
    const char *unauthenticated_payloads[] = {
        "$qSupported#37",                    /* Valid GDB packet, no auth token */
        "$m0,4#c1",                          /* Memory read attempt, no credentials */
        "GET / HTTP/1.1\r\nHost: localhost", /* HTTP request without auth header */
        "$Z0,0x0,1#47",                      /* Breakpoint set, missing token */
        ""                                   /* Empty/malformed request */
    };
    
    int num_payloads = sizeof(unauthenticated_payloads) / sizeof(unauthenticated_payloads[0]);
    
    for (int i = 0; i < num_payloads; i++) {
        /* Create a mock pbuf structure with unauthenticated payload */
        struct pbuf mock_pbuf;
        memset(&mock_pbuf, 0, sizeof(mock_pbuf));
        mock_pbuf.payload = (void *)unauthenticated_payloads[i];
        mock_pbuf.len = strlen(unauthenticated_payloads[i]);
        mock_pbuf.tot_len = mock_pbuf.len;
        
        /* Create a mock tcp_pcb (connection control block) */
        struct tcp_pcb mock_pcb;
        memset(&mock_pcb, 0, sizeof(mock_pcb));
        
        /* Call gdb_input with unauthenticated request
           Expected: function should reject or return error indicating auth failure
           NOT process the GDB command */
        err_t result = gdb_input(NULL, &mock_pcb, &mock_pbuf, ERR_OK);
        
        /* Assert that unauthenticated requests are rejected (non-zero error)
           or that no command execution occurs. A return of ERR_OK with processing
           would indicate a security failure */
        ck_assert_msg(result != ERR_OK || mock_pbuf.len == 0,
                      "Unauthenticated payload %d should be rejected, got result=%d",
                      i, result);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("GDB_Security");
    tc_core = tcase_create("Authentication");

    tcase_add_test(tc_core, test_gdb_endpoint_rejects_unauthenticated_requests);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}