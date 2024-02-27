/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_TSS2_MU_YAML_YAML_SCALAR_H_
#define SRC_TSS2_MU_YAML_YAML_SCALAR_H_

#include "yaml-common.h"

TSS2_RC UINT8_generic_marshal(const datum *in, char **out);
TSS2_RC UINT8_generic_unmarshal(const char *in, size_t len, datum *out);


#endif /* SRC_TSS2_MU_YAML_YAML_SCALAR_H_ */
