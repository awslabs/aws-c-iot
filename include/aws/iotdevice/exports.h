/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IOTDEVICE_EXPORTS_H
#define AWS_IOTDEVICE_EXPORTS_H

/* clang-format off */
#if defined(USE_WINDOWS_DLL_SEMANTICS) || defined(_WIN32)
#    ifdef AWS_IOTDEVICE_USE_IMPORT_EXPORT
#        ifdef AWS_IOTDEVICE_EXPORTS
#            define AWS_IOTDEVICE_API __declspec(dllexport)
#        else
#            define AWS_IOTDEVICE_API __declspec(dllimport)
#        endif /* AWS_IOTDEVICE_EXPORTS */
#    else
#        define AWS_IOTDEVICE_API
#    endif /* USE_IMPORT_EXPORT */

#else
#    if ((__GNUC__ >= 4) || defined(__clang__)) && defined(AWS_IOTDEVICE_USE_IMPORT_EXPORT) && defined(AWS_IOTDEVICE_EXPORTS)
#        define AWS_IOTDEVICE_API __attribute__((visibility("default")))
#    else
#        define AWS_IOTDEVICE_API
#    endif /* __GNUC__ >= 4 || defined(__clang__) */

#endif /* defined(USE_WINDOWS_DLL_SEMANTICS) || defined(_WIN32) */
/* clang-format on */

#endif /* AWS_IOTDEVICE_EXPORTS_H */
