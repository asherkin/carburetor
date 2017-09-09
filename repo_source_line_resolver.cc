// Copyright (c) 2010 Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// repo_source_line_resolver.cc: RepoSourceLineResolver implementation.
//
// See repo_source_line_resolver.h and repo_source_line_resolver_types.h
// for documentation.

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <limits>
#include <map>
#include <utility>
#include <vector>
#include <algorithm>

#include "repo_source_line_resolver.h"
#include "repo_source_line_resolver_types.h"

#include <google_breakpad/processor/basic_source_line_resolver.h>

#include <processor/module_factory.h>
#include <processor/tokenize.h>

using std::map;
using std::vector;
using std::make_pair;

namespace google_breakpad {

#ifdef _WIN32
#ifdef _MSC_VER
#define strtok_r strtok_s
#endif
#define strtoull _strtoui64
#endif

static const char *kWhitespace = " \r\n";
static const int kMaxErrorsPrinted = 5;
static const int kMaxErrorsBeforeBailing = 100;

class RepoModuleFactory : public ModuleFactory {
 public:
  virtual ~RepoModuleFactory() { }
  virtual RepoSourceLineResolver::Module* CreateModule(
      const string &name) const {
    return new RepoSourceLineResolver::Module(name);
  }
};

RepoSourceLineResolver::RepoSourceLineResolver() :
    SourceLineResolverBase(new RepoModuleFactory) { }

string RepoSourceLineResolver::LookupRepoUrl(const StackFrame *frame) const {
  if (frame->module) {
    ModuleMap::const_iterator it = modules_->find(frame->module->code_file());
    if (it != modules_->end()) {
      RepoSourceLineResolver::Module *module = (RepoSourceLineResolver::Module *)it->second;
      return module->LookupRepoUrl(frame);
    }
  }
  return string();
}

// static
void RepoSourceLineResolver::Module::LogParseError(
   const string &message,
   int line_number,
   int *num_errors) {
  if (++(*num_errors) <= kMaxErrorsPrinted) {
    if (line_number > 0) {
      BPLOG(ERROR) << "Line " << line_number << ": " << message;
    } else {
      BPLOG(ERROR) << message;
    }
  }
}

bool RepoSourceLineResolver::Module::LoadMapFromMemory(
    char *memory_buffer,
    size_t memory_buffer_size) {
  linked_ptr<Function> cur_func;
  int line_number = 0;
  int num_errors = 0;
  char *save_ptr;

  // If the length is 0, we can still pretend we have a symbol file. This is
  // for scenarios that want to test symbol lookup, but don't necessarily care
  // if certain modules do not have any information, like system libraries.
  if (memory_buffer_size == 0) {
    return true;
  }

  // Make sure the last character is null terminator.
  size_t last_null_terminator = memory_buffer_size - 1;
  if (memory_buffer[last_null_terminator] != '\0') {
    memory_buffer[last_null_terminator] = '\0';
  }

  // Skip any null terminators at the end of the memory buffer, and make sure
  // there are no other null terminators in the middle of the memory buffer.
  bool has_null_terminator_in_the_middle = false;
  while (last_null_terminator > 0 &&
         memory_buffer[last_null_terminator - 1] == '\0') {
    last_null_terminator--;
  }
  for (size_t i = 0; i < last_null_terminator; i++) {
    if (memory_buffer[i] == '\0') {
      memory_buffer[i] = '_';
      has_null_terminator_in_the_middle = true;
    }
  }
  if (has_null_terminator_in_the_middle) {
    LogParseError(
       "Null terminator is not expected in the middle of the symbol data",
       line_number,
       &num_errors);
  }

  char *buffer;
  buffer = strtok_r(memory_buffer, "\r\n", &save_ptr);

  while (buffer != NULL) {
    ++line_number;

    if (strncmp(buffer, "FILE ", 5) == 0) {
      if (!ParseFile(buffer)) {
        LogParseError("ParseFile on buffer failed", line_number, &num_errors);
      }
    } else if (strncmp(buffer, "STACK ", 6) == 0) {
      if (!ParseStackInfo(buffer)) {
        LogParseError("ParseStackInfo failed", line_number, &num_errors);
      }
    } else if (strncmp(buffer, "FUNC ", 5) == 0) {
      cur_func.reset(ParseFunction(buffer));
      if (!cur_func.get()) {
        LogParseError("ParseFunction failed", line_number, &num_errors);
      } else {
        // StoreRange will fail if the function has an invalid address or size.
        // We'll silently ignore this, the function and any corresponding lines
        // will be destroyed when cur_func is released.
        functions_.StoreRange(cur_func->address, cur_func->size, cur_func);
      }
    } else if (strncmp(buffer, "PUBLIC ", 7) == 0) {
      // Clear cur_func: public symbols don't contain line number information.
      cur_func.reset();

      if (!ParsePublicSymbol(buffer)) {
        LogParseError("ParsePublicSymbol failed", line_number, &num_errors);
      }
    } else if (strncmp(buffer, "MODULE ", 7) == 0) {
      // Ignore these.  They're not of any use to RepoSourceLineResolver,
      // which is fed modules by a SymbolSupplier.  These lines are present to
      // aid other tools in properly placing symbol files so that they can
      // be accessed by a SymbolSupplier.
      //
      // MODULE <guid> <age> <filename>
    } else if (strncmp(buffer, "INFO ", 5) == 0) {
      if (strncmp(&buffer[5], "REPO ", 5) == 0) {
        if (!ParseRepo(buffer)) {
          LogParseError("ParseRepo on buffer failed", line_number, &num_errors);
        }
      } else {
        // Ignore these as well, they're similarly just for housekeeping.
        //
        // INFO CODE_ID <code id> <filename>
      }
    } else {
      if (!cur_func.get()) {
        LogParseError("Found source line data without a function",
                       line_number, &num_errors);
      } else {
        Line *line = ParseLine(buffer);
        if (!line) {
          LogParseError("ParseLine failed", line_number, &num_errors);
        } else {
          cur_func->lines.StoreRange(line->address, line->size,
                                     linked_ptr<Line>(line));
        }
      }
    }
    if (num_errors > kMaxErrorsBeforeBailing) {
      break;
    }
    buffer = strtok_r(NULL, "\r\n", &save_ptr);
  }
  is_corrupt_ = num_errors > 0;
  return true;
}

void RepoSourceLineResolver::Module::LookupAddress(StackFrame *frame) const {
  MemAddr address = frame->instruction - frame->module->base_address();

  // First, look for a FUNC record that covers address. Use
  // RetrieveNearestRange instead of RetrieveRange so that, if there
  // is no such function, we can use the next function to bound the
  // extent of the PUBLIC symbol we find, below. This does mean we
  // need to check that address indeed falls within the function we
  // find; do the range comparison in an overflow-friendly way.
  linked_ptr<Function> func;
  linked_ptr<PublicSymbol> public_symbol;
  MemAddr function_base;
  MemAddr function_size;
  MemAddr public_address;
  if (functions_.RetrieveNearestRange(address, &func, &function_base,
                                      NULL /* delta */, &function_size) &&
      address >= function_base && address - function_base < function_size) {
    frame->function_name = func->name;
    frame->function_base = frame->module->base_address() + function_base;

    linked_ptr<Line> line;
    MemAddr line_base;
    if (func->lines.RetrieveRange(address, &line, &line_base, NULL /* delta */,
                                  NULL /* size */)) {
      FileMap::const_iterator it = files_.find(line->source_file_id);
      if (it != files_.end()) {
        frame->source_file_name = files_.find(line->source_file_id)->second;
      }
      frame->source_line = line->line;
      frame->source_line_base = frame->module->base_address() + line_base;
    }
  } else if (public_symbols_.Retrieve(address,
                                      &public_symbol, &public_address) &&
             (!func.get() || public_address > function_base)) {
    frame->function_name = public_symbol->name;
    frame->function_base = frame->module->base_address() + public_address;
  }
}

string RepoSourceLineResolver::Module::LookupRepoUrl(const StackFrame *frame) const {
  if (frame->source_file_name.empty()) {
    return string();
  }
  //printf("\n>>> frame->source_file_name = %s\n", frame->source_file_name.c_str());
  for (RepoMap::const_iterator i = repos_.begin(); i != repos_.end(); ++i) {
    //printf(">>> i->first = %s\n", i->first.c_str());
    if (frame->source_file_name.compare(0, i->first.size(), i->first) != 0) {
      continue;
    }
    string url = i->second.first;
    const string githubGitPrefix = "git@github.com:";
    const string githubHttpsPrefix = "https://github.com/";
    if (url.compare(0, githubGitPrefix.size(), githubGitPrefix) == 0) {
      url = githubHttpsPrefix + url.substr(githubGitPrefix.size(), string::npos);
    } else if (url.compare(0, githubHttpsPrefix.size(), githubHttpsPrefix) != 0) {
      continue;
    }
    if (url.substr(url.length() - 4, string::npos) == ".git") {
      url = url.substr(0, url.length() - 4);
    }
    string path = frame->source_file_name.substr(i->first.size(), string::npos);
    std::replace(path.begin(), path.end(), '\\', '/');
    return url + "/blob/" + i->second.second + path + "#L" + std::to_string(frame->source_line);
  }
  return string();
}

WindowsFrameInfo *RepoSourceLineResolver::Module::FindWindowsFrameInfo(
    const StackFrame *frame) const {
  MemAddr address = frame->instruction - frame->module->base_address();
  scoped_ptr<WindowsFrameInfo> result(new WindowsFrameInfo());

  // We only know about WindowsFrameInfo::STACK_INFO_FRAME_DATA and
  // WindowsFrameInfo::STACK_INFO_FPO. Prefer them in this order.
  // WindowsFrameInfo::STACK_INFO_FRAME_DATA is the newer type that
  // includes its own program string.
  // WindowsFrameInfo::STACK_INFO_FPO is the older type
  // corresponding to the FPO_DATA struct. See stackwalker_x86.cc.
  linked_ptr<WindowsFrameInfo> frame_info;
  if ((windows_frame_info_[WindowsFrameInfo::STACK_INFO_FRAME_DATA]
       .RetrieveRange(address, &frame_info))
      || (windows_frame_info_[WindowsFrameInfo::STACK_INFO_FPO]
          .RetrieveRange(address, &frame_info))) {
    result->CopyFrom(*frame_info.get());
    return result.release();
  }

  // Even without a relevant STACK line, many functions contain
  // information about how much space their parameters consume on the
  // stack. Use RetrieveNearestRange instead of RetrieveRange, so that
  // we can use the function to bound the extent of the PUBLIC symbol,
  // below. However, this does mean we need to check that ADDRESS
  // falls within the retrieved function's range; do the range
  // comparison in an overflow-friendly way.
  linked_ptr<Function> function;
  MemAddr function_base, function_size;
  if (functions_.RetrieveNearestRange(address, &function, &function_base,
                                      NULL /* delta */, &function_size) &&
      address >= function_base && address - function_base < function_size) {
    result->parameter_size = function->parameter_size;
    result->valid |= WindowsFrameInfo::VALID_PARAMETER_SIZE;
    return result.release();
  }

  // PUBLIC symbols might have a parameter size. Use the function we
  // found above to limit the range the public symbol covers.
  linked_ptr<PublicSymbol> public_symbol;
  MemAddr public_address;
  if (public_symbols_.Retrieve(address, &public_symbol, &public_address) &&
      (!function.get() || public_address > function_base)) {
    result->parameter_size = public_symbol->parameter_size;
  }

  return NULL;
}

CFIFrameInfo *RepoSourceLineResolver::Module::FindCFIFrameInfo(
    const StackFrame *frame) const {
  MemAddr address = frame->instruction - frame->module->base_address();
  MemAddr initial_base, initial_size;
  string initial_rules;

  // Find the initial rule whose range covers this address. That
  // provides an initial set of register recovery rules. Then, walk
  // forward from the initial rule's starting address to frame's
  // instruction address, applying delta rules.
  if (!cfi_initial_rules_.RetrieveRange(address, &initial_rules, &initial_base,
                                        NULL /* delta */, &initial_size)) {
    return NULL;
  }

  // Create a frame info structure, and populate it with the rules from
  // the STACK CFI INIT record.
  scoped_ptr<CFIFrameInfo> rules(new CFIFrameInfo());
  if (!ParseCFIRuleSet(initial_rules, rules.get()))
    return NULL;

  // Find the first delta rule that falls within the initial rule's range.
  map<MemAddr, string>::const_iterator delta =
    cfi_delta_rules_.lower_bound(initial_base);

  // Apply delta rules up to and including the frame's address.
  while (delta != cfi_delta_rules_.end() && delta->first <= address) {
    ParseCFIRuleSet(delta->second, rules.get());
    delta++;
  }

  return rules.release();
}

bool RepoSourceLineResolver::Module::ParseRepo(char *repo_line) {
  // INFO REPO <hash> <remote> <prefix>
  assert(strncmp(repo_line, "INFO REPO ", 10) == 0);
  repo_line += 10; // skip prefix 

  vector<char*> tokens;
  if (!Tokenize(repo_line, kWhitespace, 3, &tokens)) {
    return false;
  }

  repos_.insert(make_pair(string(tokens[2]), make_pair(string(tokens[1]), string(tokens[0]))));
  return true;
}

bool RepoSourceLineResolver::Module::ParseFile(char *file_line) {
  long index;
  char *filename;
  if (SymbolParseHelper::ParseFile(file_line, &index, &filename)) {
    files_.insert(make_pair(index, string(filename)));
    return true;
  }
  return false;
}

RepoSourceLineResolver::Function*
RepoSourceLineResolver::Module::ParseFunction(char *function_line) {
  uint64_t address;
  uint64_t size;
  long stack_param_size;
  char *name;
  if (SymbolParseHelper::ParseFunction(function_line, &address, &size,
                                       &stack_param_size, &name)) {
    return new Function(name, address, size, stack_param_size);
  }
  return NULL;
}

RepoSourceLineResolver::Line* RepoSourceLineResolver::Module::ParseLine(
    char *line_line) {
  uint64_t address;
  uint64_t size;
  long line_number;
  long source_file;

  if (SymbolParseHelper::ParseLine(line_line, &address, &size, &line_number,
                                   &source_file)) {
    return new Line(address, size, source_file, line_number);
  }
  return NULL;
}

bool RepoSourceLineResolver::Module::ParsePublicSymbol(char *public_line) {
  uint64_t address;
  long stack_param_size;
  char *name;

  if (SymbolParseHelper::ParsePublicSymbol(public_line, &address,
                                           &stack_param_size, &name)) {
    // A few public symbols show up with an address of 0.  This has been seen
    // in the dumped output of ntdll.pdb for symbols such as _CIlog, _CIpow,
    // RtlDescribeChunkLZNT1, and RtlReserveChunkLZNT1.  They would conflict
    // with one another if they were allowed into the public_symbols_ map,
    // but since the address is obviously invalid, gracefully accept them
    // as input without putting them into the map.
    if (address == 0) {
      return true;
    }

    linked_ptr<PublicSymbol> symbol(new PublicSymbol(name, address,
                                                     stack_param_size));
    return public_symbols_.Store(address, symbol);
  }
  return false;
}

bool RepoSourceLineResolver::Module::ParseStackInfo(char *stack_info_line) {
  // Skip "STACK " prefix.
  stack_info_line += 6;

  // Find the token indicating what sort of stack frame walking
  // information this is.
  while (*stack_info_line == ' ')
    stack_info_line++;
  const char *platform = stack_info_line;
  while (!strchr(kWhitespace, *stack_info_line))
    stack_info_line++;
  *stack_info_line++ = '\0';

  // MSVC stack frame info.
  if (strcmp(platform, "WIN") == 0) {
    int type = 0;
    uint64_t rva, code_size;
    linked_ptr<WindowsFrameInfo>
      stack_frame_info(WindowsFrameInfo::ParseFromString(stack_info_line,
                                                         type,
                                                         rva,
                                                         code_size));
    if (stack_frame_info == NULL)
      return false;

    // TODO(mmentovai): I wanted to use StoreRange's return value as this
    // method's return value, but MSVC infrequently outputs stack info that
    // violates the containment rules.  This happens with a section of code
    // in strncpy_s in test_app.cc (testdata/minidump2).  There, problem looks
    // like this:
    //   STACK WIN 4 4242 1a a 0 ...  (STACK WIN 4 base size prolog 0 ...)
    //   STACK WIN 4 4243 2e 9 0 ...
    // ContainedRangeMap treats these two blocks as conflicting.  In reality,
    // when the prolog lengths are taken into account, the actual code of
    // these blocks doesn't conflict.  However, we can't take the prolog lengths
    // into account directly here because we'd wind up with a different set
    // of range conflicts when MSVC outputs stack info like this:
    //   STACK WIN 4 1040 73 33 0 ...
    //   STACK WIN 4 105a 59 19 0 ...
    // because in both of these entries, the beginning of the code after the
    // prolog is at 0x1073, and the last byte of contained code is at 0x10b2.
    // Perhaps we could get away with storing ranges by rva + prolog_size
    // if ContainedRangeMap were modified to allow replacement of
    // already-stored values.

    windows_frame_info_[type].StoreRange(rva, code_size, stack_frame_info);
    return true;
  } else if (strcmp(platform, "CFI") == 0) {
    // DWARF CFI stack frame info
    return ParseCFIFrameInfo(stack_info_line);
  } else {
    // Something unrecognized.
    return false;
  }
}

bool RepoSourceLineResolver::Module::ParseCFIFrameInfo(
    char *stack_info_line) {
  char *cursor;

  // Is this an INIT record or a delta record?
  char *init_or_address = strtok_r(stack_info_line, " \r\n", &cursor);
  if (!init_or_address)
    return false;

  if (strcmp(init_or_address, "INIT") == 0) {
    // This record has the form "STACK INIT <address> <size> <rules...>".
    char *address_field = strtok_r(NULL, " \r\n", &cursor);
    if (!address_field) return false;

    char *size_field = strtok_r(NULL, " \r\n", &cursor);
    if (!size_field) return false;

    char *initial_rules = strtok_r(NULL, "\r\n", &cursor);
    if (!initial_rules) return false;

    MemAddr address = strtoul(address_field, NULL, 16);
    MemAddr size    = strtoul(size_field,    NULL, 16);
    cfi_initial_rules_.StoreRange(address, size, initial_rules);
    return true;
  }

  // This record has the form "STACK <address> <rules...>".
  char *address_field = init_or_address;
  char *delta_rules = strtok_r(NULL, "\r\n", &cursor);
  if (!delta_rules) return false;
  MemAddr address = strtoul(address_field, NULL, 16);
  cfi_delta_rules_[address] = delta_rules;
  return true;
}

}  // namespace google_breakpad
