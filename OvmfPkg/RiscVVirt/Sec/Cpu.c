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
#include <Library/HobLib.h>
#include <Guid/RiscVCpuHob.h>

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
  EFI_RISCV_CPU_HOB *RiscVCpuHobData;

  RiscVCpuHobData = BuildGuidHob (&gEfiRiscVCpuHobGuid, sizeof *RiscVCpuHobData);
  if (RiscVCpuHobData == NULL) {
    DEBUG ((DEBUG_ERROR, "%a: couldn't build EFI_RISCV_CPU_HOB\n", __func__));
    return EFI_UNSUPPORTED;
  }

  RiscVCpuHobData->BootHartId = BootHartId;
  
  //
  // for MMU type >= sv39
  //
  BuildCpuHob (56, 32);

  return EFI_SUCCESS;
}
