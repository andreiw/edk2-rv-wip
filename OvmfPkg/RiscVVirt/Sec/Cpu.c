/** @file
The library call to pass the device tree to DXE via HOB.

Copyright (c) 2021, Hewlett Packard Enterprise Development LP. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

//
//// The package level header files this module uses
////
#include <PiPei.h>

#include <Library/DebugLib.h>
#include <Library/PrePiLib.h>
#include <Library/HobLib.h>

/**
  Cpu Peim initialization.

  @param  BootHartId      Hardware thread ID of booting hart.
  @return EFI_SUCCESS     The platform initialized successfully.
**/
EFI_STATUS
CpuPeimInitialization (
  IN  UINTN  BootHartId
  )
{
  EFI_HOB_CPU_RISCV *RiscVCpuHob;

  RiscVCpuHob = CreateHob (EFI_HOB_TYPE_CPU_RISCV, sizeof (EFI_HOB_CPU_RISCV));
  RiscVCpuHob->BootHartId = BootHartId;

  //
  // for MMU type >= sv39
  //
  BuildCpuHob (56, 32);

  return EFI_SUCCESS;
}
