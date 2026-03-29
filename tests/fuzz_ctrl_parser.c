#include "../src/common.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return 0;
    }

    char buf[SPF_CMD_MAX_LEN + 1];
    size_t n = size;
    if (n > SPF_CMD_MAX_LEN) {
        n = SPF_CMD_MAX_LEN;
    }

    memcpy(buf, data, n);
    buf[n] = '\0';

    (void)spf_ctrl_classify_command(buf);
    return 0;
}
