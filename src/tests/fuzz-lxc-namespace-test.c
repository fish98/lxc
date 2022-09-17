/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <stddef.h>
#include <stdint.h>

#include "conf.h"
#include "confile.h"
#include "lxctest.h"
#include "utils.h"

#include "namespace.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	int fd = -1;
	char tmpf[] = "/tmp/fuzz-lxc-config-read-XXXXXX";
	struct lxc_conf *conf = NULL;

	/*
	 * 100Kb should probably be enough to trigger all the issues
	 * we're interested in without any timeouts
	 */
	if (size > 102400)
		return 0;

	fd = lxc_make_tmpfile(tmpf, false);
	lxc_test_assert_abort(fd >= 0);
	lxc_write_nointr(fd, data, size);
	close(fd);

	conf = lxc_conf_init();
	lxc_test_assert_abort(conf);
	ret = lxc_config_read(tmpf, conf, false);

	if (ret == 0) {
		/* Test namespace with likely garbage config. */
		ns_idx = lxc_namespace_2_ns_idx(conf); // conf -> namespace
		if (ns_idx < 0)
			return ns_idx;

		cloneflag = lxc_namespace_2_cloneflag(conf); // conf -> token
		if (cloneflag < 0)
			return ret_errno(EINVAL);

		// namespace_flags = 0;

		// if (lxc_namespace_2_std_identifiers(arg) < 0)
		// 	return -1;

		// ret = lxc_fill_namespace_flags(arg, &namespace_flags);
		// if (ret)
		// 	return -1;
	}

	lxc_conf_free(conf);

	(void) unlink(tmpf);
	return 0;
}
