/**
 * Copyright (c) 2021 Parrot Drones SAS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Parrot Drones SAS Company nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE PARROT DRONES SAS COMPANY BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _TTLS_TEST_H_
#define _TTLS_TEST_H_

#include <CUnit/Automated.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpomp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <transport-packet/tpkt.h>
#include <transport-socket/tskt.h>
#include <transport-socket/tskt_ops.h>
#include <transport-tls/ttls.h>
#include <transport-tls/ttls_utils.h>

#include "certs/ttls_test_certs.h"
#include "ttls_bio.h"
#include "ttls_test_fakes.h"


/* codecheck_ignore[COMPLEX_MACRO] */
#define FN(_name) (char *)_name


/* Test suites, one CU_TestInfo array per source file under test, each
 * implemented in its own tests/ttls_test_*.c file and registered in
 * ttls_test.c. Declared here as they get implemented. */
extern CU_TestInfo g_ttls_test_socket[];
extern CU_TestInfo g_ttls_test_bio[];
extern CU_TestInfo g_ttls_test_async[];
extern CU_TestInfo g_ttls_test_utils[];
/* Opt-in, must stay registered last in ttls_test.c's suite list -- see the
 * comment at the top of ttls_test_async_engine.c for why. */
extern CU_TestInfo g_ttls_test_async_engine[];


/* Write a NUL-terminated PEM buffer (TTLS_TEST_CERT_PEM / TTLS_TEST_KEY_PEM,
 * see certs/ttls_test_certs.h) to a freshly created temporary file, so it can
 * be handed to ttls_ctx_use_certificate()/ttls_ctx_load_ca() as a plain
 * filesystem path: those only accept a URI/path, not raw PEM data, and the
 * fixture is embedded rather than loaded from tests/certs/ at run time so the
 * test binary doesn't depend on being run from any particular working
 * directory (it may be copied to a build staging directory).
 * On success, path_buf is filled with the created file's path (safe to pass
 * directly as a cert_uri/pkey_uri/ca_uri argument) and 0 is returned; the
 * caller must remove(path_buf) once done. Returns a negative errno value on
 * failure. */
int ttls_test_write_temp_pem(const char *pem,
			     char *path_buf,
			     size_t path_buf_len);


#endif /* !_TTLS_TEST_H_ */
