/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/iotdevice/iotdevice.h>
#include <aws/testing/aws_test_harness.h>

static int s_library_init(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_iotdevice_library_init(allocator);
    aws_iotdevice_library_clean_up();
    return 0;
}

AWS_TEST_CASE(library_init, s_library_init);
