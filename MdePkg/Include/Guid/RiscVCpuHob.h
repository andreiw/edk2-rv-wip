/** @file
  GUIDs for HOB used to describe the booting RiscV hart.

  Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

  @par Revision Reference:
  GUIDs introduced in PI Version X.X.

**/

#ifndef __RISCV_CPU_GUID_H__
#define __RISCV_CPU__GUID_H__

#define EFI_RISCV_CPU_HOB_GUID  \
  {0xab2f45ab, 0xb021, 0xcf93, {0x9a, 0xbe, 0x10, 0x53, 0xf4, 0x3d, 0x61, 0x11} };

typedef struct {
  UINT64  BootHartId;
} EFI_RISCV_CPU_HOB;

extern EFI_GUID  gEfiRiscVCpuHobGuid;

#endif
