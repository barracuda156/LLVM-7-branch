//===-- RuntimeDyldMachOPPC.h -- MachO/PPC specific code. -*- C++ -*-=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_EXECUTIONENGINE_RUNTIMEDYLD_TARGETS_RUNTIMEDYLDMACHOPPC_H
#define LLVM_LIB_EXECUTIONENGINE_RUNTIMEDYLD_TARGETS_RUNTIMEDYLDMACHOPPC_H

#include "../RuntimeDyldMachO.h"
#include "llvm/Object/MachO.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"

#define DEBUG_TYPE "dyld"

namespace llvm {

class RuntimeDyldMachOPPC
    : public RuntimeDyldMachOCRTPBase<RuntimeDyldMachOPPC> {
public:

  typedef uint32_t TargetPtrT;

  RuntimeDyldMachOPPC(RuntimeDyld::MemoryManager &MM,
                      JITSymbolResolver &Resolver)
      : RuntimeDyldMachOCRTPBase(MM, Resolver) {}

  unsigned getMaxStubSize() override { return 16; }

  unsigned getStubAlignment() override { return 4; }

  Expected<relocation_iterator>
  processRelocationRef(unsigned SectionID, relocation_iterator RelI,
                       const ObjectFile &BaseObjT,
                       ObjSectionToIDMap &ObjSectionToID,
                       StubMap &Stubs) override {
    
    const MachOObjectFile &Obj =
        static_cast<const MachOObjectFile &>(BaseObjT);
    MachO::any_relocation_info RelInfo =
        Obj.getRelocation(RelI->getRawDataRefImpl());

    uint32_t RelType = Obj.getAnyRelocationType(RelInfo);
    
    if (Obj.isRelocationScattered(RelInfo))
      return processScatteredVANILLA(SectionID, RelI, BaseObjT, ObjSectionToID);

    RelocationEntry RE(getRelocationEntry(SectionID, Obj, RelI));
    RE.Addend = memcpyAddend(RE);
    RelocationValueRef Value;
    if (auto ValueOrErr = getRelocationValueRef(Obj, RelI, RE, ObjSectionToID))
      Value = *ValueOrErr;
    else
      return ValueOrErr.takeError();

    bool IsExtern = Obj.getPlainRelocationExternal(RelInfo);
    if (!IsExtern && RE.IsPCRel)
      makeValueAddendPCRel(Value, RelI, 1 << RE.Size);

    switch (RelType) {
    default:
      llvm_unreachable("Unsupported PPC relocation type!");
      
    case MachO::PPC_RELOC_VANILLA:
      // Basic absolute relocation - direct value patching
      break;
      
    case MachO::PPC_RELOC_PAIR:
      // Handle paired relocations - this should be processed with previous reloc
      llvm_unreachable("PPC_RELOC_PAIR should not be processed independently");
      break;
      
    case MachO::PPC_RELOC_BR14:
      // 14-bit conditional branch
      if (!RE.IsPCRel)
        llvm_unreachable("PPC_RELOC_BR14 must be PC-relative");
      break;
      
    case MachO::PPC_RELOC_BR24:
      // 24-bit branch
      if (!RE.IsPCRel)
        llvm_unreachable("PPC_RELOC_BR24 must be PC-relative");
      break;
      
    case MachO::PPC_RELOC_HI16:
    case MachO::PPC_RELOC_LO16:
    case MachO::PPC_RELOC_HA16:
    case MachO::PPC_RELOC_LO14:
      // These require PAIR processing - handled in resolveRelocation
      break;
      
    case MachO::PPC_RELOC_SECTDIFF:
    case MachO::PPC_RELOC_LOCAL_SECTDIFF:
    case MachO::PPC_RELOC_HI16_SECTDIFF:
    case MachO::PPC_RELOC_LO16_SECTDIFF:
    case MachO::PPC_RELOC_HA16_SECTDIFF:
    case MachO::PPC_RELOC_LO14_SECTDIFF:
      // STUB: Section difference relocations need special handling
      // These compute differences between two symbols
      break;
    }

    RE.Addend = Value.Offset;
    if (Value.SymbolName)
      addRelocationForSymbol(RE, Value.SymbolName);
    else
      addRelocationForSection(RE, Value.SectionID);

    return ++RelI;
  }

  void resolveRelocation(const RelocationEntry &RE, uint64_t Value) override {
    LLVM_DEBUG(dumpRelocationToResolve(RE, Value));

    const SectionEntry &Section = Sections[RE.SectionID];
    uint8_t *LocalAddress = Section.getAddressWithOffset(RE.Offset);
    uint64_t FinalAddress = Section.getLoadAddressWithOffset(RE.Offset);
    uint32_t RelType = RE.RelType;

    switch (RelType) {
    default:
      llvm_unreachable("Invalid PPC relocation type!");
      
    case MachO::PPC_RELOC_VANILLA: {
      if (RE.Size == 2) {
        // 32-bit absolute - from PPCMachObjectWriter
        uint32_t FinalValue = (Value + RE.Addend) & 0xffffffff;
        writePPCWord(LocalAddress, FinalValue);
      } else {
        llvm_unreachable("Invalid size for PPC_RELOC_VANILLA");
      }
      break;
    }
    
    case MachO::PPC_RELOC_BR14: {
      // 14-bit conditional branch - from PPCAsmBackend adjustFixupValue
      if (!RE.IsPCRel)
        llvm_unreachable("PPC_RELOC_BR14 must be PC-relative");
      
      int64_t displacement = Value + RE.Addend - FinalAddress;
      // Apply the mask from PPCAsmBackend.cpp: Value & 0xfffc
      displacement &= 0xfffc;
      
      encodePPCBranch14(LocalAddress, displacement);
      break;
    }
    
    case MachO::PPC_RELOC_BR24: {
      // 24-bit branch - from PPCAsmBackend adjustFixupValue
      if (!RE.IsPCRel)
        llvm_unreachable("PPC_RELOC_BR24 must be PC-relative");
        
      int64_t displacement = Value + RE.Addend - FinalAddress;
      // Apply the mask from PPCAsmBackend.cpp: Value & 0x3fffffc  
      displacement &= 0x3fffffc;
      
      encodePPCBranch24(LocalAddress, displacement);
      break;
    }
    
    case MachO::PPC_RELOC_HI16: {
      // High 16 bits - from PPCMachObjectWriter logic
      uint32_t hi16 = (Value + RE.Addend) >> 16;
      uint32_t instruction = readPPCInstruction(LocalAddress);
      // Replace immediate field (bits 16-31)
      instruction = (instruction & 0xffff0000) | (hi16 & 0xffff);
      writePPCInstruction(LocalAddress, instruction);
      break;
    }
    
    case MachO::PPC_RELOC_LO16: {
      // Low 16 bits - from PPCMachObjectWriter logic
      uint32_t lo16 = (Value + RE.Addend) & 0xffff;
      uint32_t instruction = readPPCInstruction(LocalAddress);
      // Replace immediate field (bits 16-31)
      instruction = (instruction & 0xffff0000) | lo16;
      writePPCInstruction(LocalAddress, instruction);
      break;
    }
    
    case MachO::PPC_RELOC_HA16: {
      // High 16 bits adjusted - from PPCMachObjectWriter logic
      uint64_t adjustedValue = Value + RE.Addend;
      uint32_t ha16 = ((adjustedValue >> 16) + ((adjustedValue & 0x8000) ? 1 : 0)) & 0xffff;
      uint32_t instruction = readPPCInstruction(LocalAddress);
      // Replace immediate field (bits 16-31)
      instruction = (instruction & 0xffff0000) | ha16;
      writePPCInstruction(LocalAddress, instruction);
      break;
    }
    
    case MachO::PPC_RELOC_LO14: {
      // Low 14 bits for load/store with 2-bit shift - from PPCAsmBackend
      uint32_t lo14 = (Value + RE.Addend) & 0xfffc;
      uint32_t instruction = readPPCInstruction(LocalAddress);
      // Replace D field in D-form instruction (bits 16-31)
      instruction = (instruction & 0xffff0000) | lo14;
      writePPCInstruction(LocalAddress, instruction);
      break;
    }
    
    case MachO::PPC_RELOC_SECTDIFF:
    case MachO::PPC_RELOC_LOCAL_SECTDIFF:
      // STUB: Section difference - needs symbol address computation
      // Value should contain the difference between two symbols
      writePPCWord(LocalAddress, (Value + RE.Addend) & 0xffffffff);
      break;
      
    case MachO::PPC_RELOC_HI16_SECTDIFF:
    case MachO::PPC_RELOC_LO16_SECTDIFF:
    case MachO::PPC_RELOC_HA16_SECTDIFF:
    case MachO::PPC_RELOC_LO14_SECTDIFF:
      // STUB: Section difference variants - same as non-sectdiff but with
      // symbol difference values
      break;
    }
  }

  Error finalizeSection(const ObjectFile &Obj, unsigned SectionID,
                        const SectionRef &Section) override {
    return Error::success();
  }

private:
  // Helper function implementations - based on endianness from PPCAsmBackend
  void writePPCWord(uint8_t *LocalAddress, uint32_t Value) {
    support::endian::write<uint32_t>(LocalAddress, Value, support::big);
  }

  void writePPCHalfWord(uint8_t *LocalAddress, uint16_t Value) {
    support::endian::write<uint16_t>(LocalAddress, Value, support::big);
  }

  uint32_t readPPCInstruction(uint8_t *LocalAddress) {
    return support::endian::read<uint32_t>(LocalAddress, support::big);
  }

  void writePPCInstruction(uint8_t *LocalAddress, uint32_t Instruction) {
    support::endian::write<uint32_t>(LocalAddress, Instruction, support::big);
  }

  // Branch encoding based on PPCAsmBackend fixup info
  void encodePPCBranch14(uint8_t *LocalAddress, int64_t displacement) {
    uint32_t instruction = readPPCInstruction(LocalAddress);
    // 14-bit branch: bits 16-29 (from PPCAsmBackend getFixupKindInfo)
    // Clear the branch target field and insert new displacement
    instruction = (instruction & 0xffff0003) | ((displacement & 0xfffc) << 0);
    writePPCInstruction(LocalAddress, instruction);
  }

  void encodePPCBranch24(uint8_t *LocalAddress, int64_t displacement) {
    uint32_t instruction = readPPCInstruction(LocalAddress);
    // 24-bit branch: bits 6-29 (from PPCAsmBackend getFixupKindInfo)  
    // Clear the branch target field and insert new displacement
    instruction = (instruction & 0xfc000003) | (displacement & 0x3fffffc);
    writePPCInstruction(LocalAddress, instruction);
  }
};

} // end namespace llvm

#undef DEBUG_TYPE

#endif
