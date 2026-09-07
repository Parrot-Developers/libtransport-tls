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

#include "ttls_test.h"

#include <unistd.h>


int ttls_test_write_temp_pem(const char *pem,
			     char *path_buf,
			     size_t path_buf_len)
{
	int fd;
	FILE *f;
	size_t len;

	if (pem == NULL || path_buf == NULL || path_buf_len == 0)
		return -EINVAL;

	if (snprintf(path_buf, path_buf_len, "/tmp/ttls_test_XXXXXX") >=
	    (int)path_buf_len)
		return -ENAMETOOLONG;

	fd = mkstemp(path_buf);
	if (fd < 0)
		return -errno;

	f = fdopen(fd, "w");
	if (f == NULL) {
		int err = -errno;
		close(fd);
		remove(path_buf);
		return err;
	}

	len = strlen(pem);
	if (fwrite(pem, 1, len, f) != len) {
		fclose(f);
		remove(path_buf);
		return -EIO;
	}

	fclose(f);
	return 0;
}


/* Suites are added here as each tests/ttls_test_*.c file is implemented.
 * "async-engine" must stay last: it may leave a test OpenSSL engine
 * registered as the process-wide default for the remainder of this binary's
 * lifetime (see the comment at the top of ttls_test_async_engine.c). */
static CU_SuiteInfo s_suites[] = {
	{FN("socket"), NULL, NULL, g_ttls_test_socket},
	{FN("bio"), NULL, NULL, g_ttls_test_bio},
	{FN("async"), NULL, NULL, g_ttls_test_async},
	{FN("utils"), NULL, NULL, g_ttls_test_utils},
	{FN("async-engine"), NULL, NULL, g_ttls_test_async_engine},

	CU_SUITE_INFO_NULL,
};


static void run_automated()
{
	CU_automated_run_tests();
	CU_list_tests_to_file();
}


static void run_basic()
{
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
}


int main()
{
	const char *filename;

	OPENSSL_init_ssl(0, NULL);
	if (ttls_init() < 0)
		return 1;
	/* ttls_test_bio.c calls ttls_bio_new() directly against this test
	 * binary's own copy of ttls_bio.c (see atom.mk for why), which is a
	 * separate instance from the one ttls_init() just set up inside
	 * libtransport-tls: it needs its own init too. */
	if (ttls_bio_method_init() < 0)
		return 1;

	CU_initialize_registry();
	CU_register_suites(s_suites);

	/* Set filename */
	filename = getenv("CUNIT_OUT_NAME");
	CU_set_output_filename(filename);

	/* Run tests */
	if (getenv("CUNIT_AUTOMATED") != NULL)
		run_automated();
	else
		run_basic();

	CU_cleanup_registry();

	ttls_bio_method_deinit();
	ttls_deinit();
}
