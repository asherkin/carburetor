#include <iostream>
#include <fstream>
#include <chrono>
#include <memory>
#include <sstream>

#include <nlohmann/json.hpp>

#include <base64_default_rfc4648.hpp>

#include <distorm.h>

#include <google_breakpad/processor/call_stack.h>
#include <google_breakpad/processor/code_module.h>
#include <google_breakpad/processor/minidump.h>
#include <google_breakpad/processor/minidump_processor.h>
#include <google_breakpad/processor/process_state.h>
#include <google_breakpad/processor/stack_frame_cpu.h>
#include <google_breakpad/processor/stack_frame.h>
#include <google_breakpad/processor/stackwalker.h>
#include <google_breakpad/processor/system_info.h>
#include <processor/logging.h>
#include <processor/pathname_stripper.h>

#include "compressed_symbol_supplier.h"
#include "repo_source_line_resolver.h"

using nlohmann::json;

using google_breakpad::CallStack;
using google_breakpad::CodeModule;
using google_breakpad::MemoryRegion;
using google_breakpad::Minidump;
using google_breakpad::MinidumpContext;
using google_breakpad::MinidumpException;
using google_breakpad::MinidumpMemoryList;
using google_breakpad::MinidumpMemoryRegion;
using google_breakpad::MinidumpProcessor;
using google_breakpad::MinidumpThreadList;
using google_breakpad::PathnameStripper;
using google_breakpad::ProcessResult;
using google_breakpad::ProcessState;
using google_breakpad::StackFrame;
using google_breakpad::StackFrameAMD64;
using google_breakpad::StackFrameX86;
using google_breakpad::Stackwalker;
using google_breakpad::SystemInfo;

// This really shouldn't be in the google_breakpad namespace.
using google_breakpad::CompressedSymbolSupplier;
using google_breakpad::RepoSourceLineResolver;

string RenderFrame(const StackFrame *frame) {
  std::ostringstream out;
  out << std::hex;
  if (frame->module) {
    out << PathnameStripper::File(frame->module->code_file());
    if (!frame->function_name.empty()) {
      out << "!" << frame->function_name;
      if (!frame->source_file_name.empty()) {
        out << " [" << PathnameStripper::File(frame->source_file_name) << ":" << std::dec << frame->source_line << std::hex << " + 0x" << frame->ReturnAddress() - frame->source_line_base << "]";
      } else {
        out << " + 0x" << frame->ReturnAddress() - frame->function_base;
      }
    } else {
      out << " + 0x" << frame->ReturnAddress() - frame->module->base_address();
    }
  } else {
    out << "0x" << frame->ReturnAddress();
  }
  out << std::dec;
  return out.str();
}

json GetStackContents(const StackFrame *frame, const StackFrame *prev_frame, const string &cpu, const MemoryRegion *memory) {
  int word_length = 0;
  uint64_t stack_begin = 0, stack_end = 0;
  if (cpu == "x86") {
    word_length = 4;
    const StackFrameX86 *frame_x86 = static_cast<const StackFrameX86*>(frame);
    const StackFrameX86 *prev_frame_x86 = static_cast<const StackFrameX86*>(prev_frame);
    if ((frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_ESP) &&
        (prev_frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_ESP)) {
      stack_begin = frame_x86->context.esp;
      stack_end = prev_frame_x86->context.esp;
    }
  } else if (cpu == "amd64") {
    word_length = 8;
    const StackFrameAMD64 *frame_amd64 = static_cast<const StackFrameAMD64*>(frame);
    const StackFrameAMD64 *prev_frame_amd64 = static_cast<const StackFrameAMD64*>(prev_frame);
    if ((frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RSP) &&
        (prev_frame_amd64->context_validity &
         StackFrameAMD64::CONTEXT_VALID_RSP)) {
      stack_begin = frame_amd64->context.rsp;
      stack_end = prev_frame_amd64->context.rsp;
    }
  }

  if (!word_length || !stack_begin || !stack_end) {
    return false;
  }

  size_t stack_offset = stack_begin - memory->GetBase();
  size_t stack_size = stack_end - stack_begin;

  if (stack_size > memory->GetSize() || stack_offset >= (memory->GetSize() - stack_size)) {
    return false;
  }

  string data_as_string;
  data_as_string.reserve(stack_size);
  for (uint64_t address = stack_begin; address < stack_end; ++address) {
      uint8_t value = 0;
      if (!memory->GetMemoryAtAddress(address, &value)) {
        return false;
      }

      data_as_string.push_back(value);
  }

  return base64::encode(data_as_string);
}

json SerializeCodeModule(const CodeModule *codeModule) {
  json body;

  body["base_address"] = codeModule->base_address();
  body["size"] = codeModule->size();
  body["code_file"] = codeModule->code_file();
  if (!codeModule->code_identifier().empty() && codeModule->code_identifier() != "id")
    body["code_identifier"] = codeModule->code_identifier();
  body["debug_file"] = codeModule->debug_file();
  body["debug_identifier"] = codeModule->debug_identifier();
  if (!codeModule->version().empty())
    body["version"] = codeModule->version();

  return body;
}

json SerializeProcessState(Minidump *minidump, const ProcessState *processState, RepoSourceLineResolver *resolver) {
  json body;

  MinidumpMemoryList *memoryList = minidump->GetMemoryList();
  const string &cpu = processState->system_info()->cpu;

  if (processState->time_date_stamp() != 0)
    body["time_date_stamp"] = processState->time_date_stamp();
  if (processState->process_create_time() != 0)
    body["process_create_time"] = processState->process_create_time();
  body["crashed"] = processState->crashed();
  body["crash_reason"] = processState->crash_reason();
  body["crash_address"] = processState->crash_address();
  if (!processState->assertion().empty())
    body["assertion"] = processState->assertion();
  if (processState->requesting_thread() != -1)
    body["requesting_thread"] = processState->requesting_thread();
  if (processState->exploitability() != google_breakpad::EXPLOITABILITY_NOT_ANALYZED)
    body["exploitability"] = processState->exploitability();

  json threads;
  for (const CallStack *callStack: *processState->threads()) {
    json thread;
    for (const StackFrame *stackFrame: *callStack->frames()) {
      json frame;

      frame["return_address"] = stackFrame->ReturnAddress();
      frame["instruction"] = stackFrame->instruction;
      if (stackFrame->module)
        frame["module"] = SerializeCodeModule(stackFrame->module);
      if (!stackFrame->function_name.empty())
        frame["function_name"] = stackFrame->function_name;
      if (stackFrame->function_base != 0)
        frame["function_base"] = stackFrame->function_base;
      if (!stackFrame->source_file_name.empty())
        frame["source_file_name"] = stackFrame->source_file_name;
      if (stackFrame->source_line != 0)
        frame["source_line"] = stackFrame->source_line;
      if (stackFrame->source_line_base != 0)
        frame["source_line_base"] = stackFrame->source_line_base;
      frame["trust"] = stackFrame->trust;
      string url = resolver->LookupRepoUrl(stackFrame);
      if (!url.empty())
        frame["url"] = url;

      frame["rendered"] = RenderFrame(stackFrame);

      uint64_t instructionPtr = 0;

      if (cpu == "x86") {
        json registers;
        const StackFrameX86 *frame_x86 = reinterpret_cast<const StackFrameX86*>(stackFrame);

        if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EIP)
          registers["eip"] = instructionPtr = frame_x86->context.eip;
        if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_ESP)
          registers["esp"] = frame_x86->context.esp;
        if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EBP)
          registers["ebp"] = frame_x86->context.ebp;
        if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EBX)
          registers["ebx"] = frame_x86->context.ebx;
        if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_ESI)
          registers["esi"] = frame_x86->context.esi;
        if (frame_x86->context_validity & StackFrameX86::CONTEXT_VALID_EDI)
          registers["edi"] = frame_x86->context.edi;
        if (frame_x86->context_validity == StackFrameX86::CONTEXT_VALID_ALL) {
          registers["eax"] = frame_x86->context.eax;
          registers["ecx"] = frame_x86->context.ecx;
          registers["edx"] = frame_x86->context.edx;
          registers["efl"] = frame_x86->context.eflags;
        }

        frame["registers"] = registers;
      } else if (cpu == "amd64") {
        json registers;
        const StackFrameAMD64 *frame_amd64 = reinterpret_cast<const StackFrameAMD64*>(stackFrame);

        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RAX)
          registers["rax"] = frame_amd64->context.rax;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RDX)
          registers["rdx"] = frame_amd64->context.rdx;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RCX)
          registers["rcx"] = frame_amd64->context.rcx;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RBX)
          registers["rbx"] = frame_amd64->context.rbx;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RSI)
          registers["rsi"] = frame_amd64->context.rsi;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RDI)
          registers["rdi"] = frame_amd64->context.rdi;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RBP)
          registers["rbp"] = frame_amd64->context.rbp;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RSP)
          registers["rsp"] = frame_amd64->context.rsp;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R8)
          registers["r8"] = frame_amd64->context.r8;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R9)
          registers["r9"] = frame_amd64->context.r9;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R10)
          registers["r10"] = frame_amd64->context.r10;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R11)
          registers["r11"] = frame_amd64->context.r11;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R12)
          registers["r12"] = frame_amd64->context.r12;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R13)
          registers["r13"] = frame_amd64->context.r13;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R14)
          registers["r14"] = frame_amd64->context.r14;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_R15)
          registers["r15"] = frame_amd64->context.r15;
        if (frame_amd64->context_validity & StackFrameAMD64::CONTEXT_VALID_RIP)
          registers["rip"] = instructionPtr = frame_amd64->context.rip;

        frame["registers"] = registers;
      }

      if (instructionPtr != 0 && memoryList) {
        MinidumpMemoryRegion *instructionRegion = memoryList->GetMemoryRegionForAddress(instructionPtr);
        if (instructionRegion) {
          uint64_t instructionMemoryBase = instructionRegion->GetBase();
          const uint8_t *instructionMemory = instructionRegion->GetMemory();
          size_t instructionMemorySize = instructionRegion->GetSize();

          uint64_t instructionLocalOffset = instructionPtr - instructionMemoryBase;
          if (instructionLocalOffset > 128) {
            uint64_t localOffsetDiff = instructionLocalOffset - 128;
            instructionMemoryBase += localOffsetDiff;
            instructionMemory += localOffsetDiff;
            instructionMemorySize -= localOffsetDiff;
          }

          instructionLocalOffset = (instructionMemoryBase + instructionMemorySize) - instructionPtr;
          if (instructionLocalOffset > 128) {
            uint64_t localOffsetDiff = instructionLocalOffset - 128;
            instructionMemorySize -= localOffsetDiff;
          }

          // objdump -D -b binary -m i386 -M intel opcodes.bin
          // frame["instructions_raw"] = base64::encode(instructionMemory, instructionMemorySize);

          json instructions;

          constexpr size_t MAX_INSTRUCTIONS = 256;
          _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
          unsigned int decodedInstructionsCount = 0;
          _DecodeType dt = (cpu == "amd64") ? Decode64Bits : Decode32Bits;
          _DecodeResult res = distorm_decode(instructionMemoryBase, instructionMemory, instructionMemorySize, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);

          for (unsigned int i = 0; i < decodedInstructionsCount; ++i) {
            // Ignore 3 instructions at the start and and, to avoid synchronization issues.
            if (i < 3 || i >= (decodedInstructionsCount - 3)) {
              continue;
            }

            std::string hex = (char *)decodedInstructions[i].instructionHex.p;
            std::string mnemonic = (char *)decodedInstructions[i].mnemonic.p;

            if (decodedInstructions[i].operands.length != 0) {
              mnemonic.append(" ");
              mnemonic.append((char *)decodedInstructions[i].operands.p);
            }

            std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(), ::tolower);

            json opcode;
            opcode["offset"] = decodedInstructions[i].offset;
            opcode["hex"] = hex;
            opcode["mnemonic"] = mnemonic;
            instructions.push_back(opcode);
          }

          frame["instructions"] = instructions;
        }
      }

      size_t callingFrameIndex = thread.size() + 1;
      if (callingFrameIndex < callStack->frames()->size()) {
        size_t threadIndex = threads.size();
        const StackFrame *callingFrame = callStack->frames()->at(callingFrameIndex);
        const MemoryRegion *threadMemory = processState->thread_memory_regions()->at(threadIndex);

        frame["stack"] = GetStackContents(stackFrame, callingFrame, cpu, threadMemory);
      }

      thread.push_back(frame);
    }
    threads.push_back(thread);
  }
  body["threads"] = threads;

  json systemInfo;

  if (!processState->system_info()->os.empty())
    systemInfo["os"] = processState->system_info()->os;
  if (!processState->system_info()->os_short.empty())
    systemInfo["os_short"] = processState->system_info()->os_short;
  if (!processState->system_info()->os_version.empty())
    systemInfo["os_version"] = processState->system_info()->os_version;
  if (!processState->system_info()->cpu.empty())
    systemInfo["cpu"] = processState->system_info()->cpu;
  if (!processState->system_info()->cpu_info.empty())
    systemInfo["cpu_info"] = processState->system_info()->cpu_info;
  systemInfo["cpu_count"] = processState->system_info()->cpu_count;

  body["system_info"] = systemInfo;

  if (processState->modules()) {
    if (processState->modules()->GetMainModule()) {
      body["main_module"] = SerializeCodeModule(processState->modules()->GetMainModule());
    }

    json modules;
    unsigned int module_count = processState->modules()->module_count();
    for (unsigned int i = 0; i < module_count; ++i) {
      modules.push_back(SerializeCodeModule(processState->modules()->GetModuleAtIndex(i)));
    }
    body["modules"] = modules;

    json modulesWithoutSymbols;
    for (const CodeModule *codeModule: *processState->modules_without_symbols()) {
      modulesWithoutSymbols.push_back(SerializeCodeModule(codeModule));
    }
    if (modulesWithoutSymbols.is_array())
      body["modules_without_symbols"] = modulesWithoutSymbols;

    json modulesWithCorruptSymbols;
    for (const CodeModule *codeModule: *processState->modules_with_corrupt_symbols()) {
      modulesWithCorruptSymbols.push_back(SerializeCodeModule(codeModule));
    }
    if (modulesWithCorruptSymbols.is_array())
      body["modules_with_corrupt_symbols"] = modulesWithCorruptSymbols;
  }

  if (memoryList) {
    json memory;

    for (size_t i = 0; i < memoryList->region_count(); ++i) {
      MinidumpMemoryRegion *memoryRegion = memoryList->GetMemoryRegionAtIndex(i);

      json region;
      region["base"] = memoryRegion->GetBase();
      region["size"] = memoryRegion->GetSize();
      region["data"] = base64::encode(memoryRegion->GetMemory(), memoryRegion->GetSize());

      memory.push_back(region);
    }

    body["memory"] = memory;
  }

  return body;
}

int main(int argc, char *argv[]) {
  BPLOG_INIT(&argc, &argv);

  bool showHelp = false;
  bool disableStackScan = false;

  std::vector<std::string> arguments(argv + 1, argv + argc);

  for (auto it = arguments.begin(); it != arguments.end();) {
    if (it->at(0) != '-') {
      ++it;
      continue;
    }

    const auto arg = *it;
    it = arguments.erase(it);

    if (arg == "--") {
      break;
    }

    if (arg == "-h" || arg == "--help") {
      showHelp = true;
      continue;
    }

    if (arg == "--no-scan") {
      disableStackScan = true;
      continue;
    }

    std::cerr << "Unknown argument: " << arg << std::endl;
    showHelp = true;
    break;
  }

  if (showHelp || arguments.empty()) {
    std::cerr << "Usage: " << argv[0] << " [options] [--] <minidump> [symbol directory, ...]" << std::endl;
    return 1;
  }

  MinidumpThreadList::set_max_threads(std::numeric_limits<uint32_t>::max());
  MinidumpMemoryList::set_max_regions(std::numeric_limits<uint32_t>::max());

  if (disableStackScan) {
    Stackwalker::set_max_frames_scanned(0);
  }

  std::string minidumpFile = arguments[0];
  arguments.erase(arguments.begin());

  const std::vector<string> &symbolPaths = arguments;
  CompressedSymbolSupplier symbolSupplier(symbolPaths);

  // The MinidumpProcessor::Process that takes a path has a use-after-free bug.
  BPLOG(INFO) << "Processing minidump in file " << minidumpFile;

  Minidump minidump(minidumpFile);
  if (!minidump.Read()) {
    BPLOG(ERROR) << "Minidump " << minidump.path() << " could not be read";
    return 1;
  }

  auto start = std::chrono::steady_clock::now();

  RepoSourceLineResolver resolver;
  MinidumpProcessor minidumpProcessor(&symbolSupplier, &resolver);

  ProcessState processState;
  ProcessResult processResult = minidumpProcessor.Process(&minidump, &processState);

  if (processResult != google_breakpad::PROCESS_OK) {
    BPLOG(ERROR) << "MinidumpProcessor::Process failed";
    return 1;
  }

  auto end = std::chrono::steady_clock::now();
  double elapsedSeconds = ((end - start).count()) * std::chrono::steady_clock::period::num / static_cast<double>(std::chrono::steady_clock::period::den);

  json serialized = SerializeProcessState(&minidump, &processState, &resolver);
  serialized["input_file"] = minidump.path();
  serialized["processing_time"] = elapsedSeconds;

  std::cout << serialized << std::endl;
  return 0;
}
