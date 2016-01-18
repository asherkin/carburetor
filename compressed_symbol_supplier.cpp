// Copyright (c) 2006, Google Inc.
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

// compressed_symbol_supplier.cc: A simple SymbolSupplier implementation
//
// See compressed_symbol_supplier.h for documentation.
//
// Author: Mark Mentovai

#include "compressed_symbol_supplier.h"

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <algorithm>
#include <iostream>
#include <fstream>

#include <common/using_std_string.h>
#include <google_breakpad/processor/code_module.h>
#include <google_breakpad/processor/system_info.h>
#include <processor/logging.h>
#include <processor/pathname_stripper.h>

#include <zlib.h>

namespace google_breakpad {

static bool file_exists(const string &file_name) {
  struct stat sb;
  return stat(file_name.c_str(), &sb) == 0;
}

SymbolSupplier::SymbolResult CompressedSymbolSupplier::GetSymbolFile(
    const CodeModule *module, const SystemInfo *system_info,
    string *symbol_file) {
  BPLOG_IF(ERROR, !symbol_file) << "CompressedSymbolSupplier::GetSymbolFile "
                                   "requires |symbol_file|";
  assert(symbol_file);
  symbol_file->clear();

  for (unsigned int path_index = 0; path_index < paths_.size(); ++path_index) {
    SymbolResult result;
    if ((result = GetSymbolFileAtPathFromRoot(module, system_info,
                                              paths_[path_index],
                                              symbol_file)) != NOT_FOUND) {
      return result;
    }
  }
  return NOT_FOUND;
}

SymbolSupplier::SymbolResult CompressedSymbolSupplier::GetSymbolFile(
    const CodeModule *module,
    const SystemInfo *system_info,
    string *symbol_file,
    string *symbol_data) {
  assert(symbol_data);
  symbol_data->clear();

  SymbolSupplier::SymbolResult s = GetSymbolFile(module, system_info,
                                                 symbol_file);
  if (s == FOUND) {
    //std::ifstream in(symbol_file->c_str(), std::ios::binary);
    //std::getline(in, *symbol_data, string::traits_type::to_char_type(
    //                 string::traits_type::eof()));
    //in.close();

    //const unsigned char *c = (const unsigned char *)symbol_data->data();
    //std::cout << *symbol_file << " " << std::hex << (int)c[symbol_data->size() - 1] << std::dec << std::endl;

    /////////////////////////////////////

    //std::ifstream in(symbol_file->c_str(), std::ios::binary);
    //std::vector<char> buffer((std::istreambuf_iterator<char>(in)), (std::istreambuf_iterator<char>()));
    //in.close();

    //size_t uncompressed_length = *(uint32_t *)&buffer[buffer.size() - 4];
    //std::cout << *symbol_file << " " << uncompressed_length;

    //symbol_data->resize(uncompressed_length);
    //size_t actual_length = symbol_data->size();
    //int ret = uncompress((unsigned char *)&(*symbol_data)[0], &actual_length, (unsigned char *)&buffer[0], buffer.size());
    //std::cout << " " << actual_length << " " << ret << std::endl;

    int symbol_fd = open(symbol_file->c_str(), O_RDONLY);

    lseek(symbol_fd, -4, SEEK_END);

    uint32_t uncompressed_length;
    read(symbol_fd, &uncompressed_length, sizeof(uncompressed_length));

    //std::cout << *symbol_file << " " << uncompressed_length;

    lseek(symbol_fd, 0, SEEK_SET);

    auto symbol_gz_file = gzdopen(symbol_fd, "rb");

    symbol_data->resize(uncompressed_length);
    size_t actual_length = gzread(symbol_gz_file, &(*symbol_data)[0], symbol_data->size());

    //std::cout << " " << actual_length << std::endl;

    gzclose_r(symbol_gz_file);

    /////////////////////////////////////
  }
  return s;
}

SymbolSupplier::SymbolResult CompressedSymbolSupplier::GetCStringSymbolData(
    const CodeModule *module,
    const SystemInfo *system_info,
    string *symbol_file,
    char **symbol_data,
    size_t *symbol_data_size) {
  assert(symbol_data);
  assert(symbol_data_size);

  string symbol_data_string;
  SymbolSupplier::SymbolResult s =
      GetSymbolFile(module, system_info, symbol_file, &symbol_data_string);

  if (s == FOUND) {
    *symbol_data_size = symbol_data_string.size() + 1;
    *symbol_data = new char[*symbol_data_size];
    if (*symbol_data == NULL) {
      BPLOG(ERROR) << "Memory allocation for size " << *symbol_data_size
                   << " failed";
      return INTERRUPT;
    }
    memcpy(*symbol_data, symbol_data_string.c_str(), symbol_data_string.size());
    (*symbol_data)[symbol_data_string.size()] = '\0';
    memory_buffers_.insert(make_pair(module->code_file(), *symbol_data));
  }
  return s;
}

void CompressedSymbolSupplier::FreeSymbolData(const CodeModule *module) {
  if (!module) {
    BPLOG(INFO) << "Cannot free symbol data buffer for NULL module";
    return;
  }

  map<string, char *>::iterator it = memory_buffers_.find(module->code_file());
  if (it == memory_buffers_.end()) {
    BPLOG(INFO) << "Cannot find symbol data buffer for module "
                << module->code_file();
    return;
  }
  delete [] it->second;
  memory_buffers_.erase(it);
}

SymbolSupplier::SymbolResult CompressedSymbolSupplier::GetSymbolFileAtPathFromRoot(
    const CodeModule *module, const SystemInfo *system_info,
    const string &root_path, string *symbol_file) {
  BPLOG_IF(ERROR, !symbol_file) << "CompressedSymbolSupplier::GetSymbolFileAtPath "
                                   "requires |symbol_file|";
  assert(symbol_file);
  symbol_file->clear();

  if (!module)
    return NOT_FOUND;

  // Start with the base path.
  string path = root_path;

  // Append the debug (pdb) file name as a directory name.
  path.append("/");
  string debug_file_name = PathnameStripper::File(module->debug_file());
  if (debug_file_name.empty()) {
    BPLOG(ERROR) << "Can't construct symbol file path without debug_file "
                    "(code_file = " <<
                    PathnameStripper::File(module->code_file()) << ")";
    return NOT_FOUND;
  }
  path.append(debug_file_name);

  // Append the identifier as a directory name.
  path.append("/");
  string identifier = module->debug_identifier();
  if (identifier.empty()) {
    BPLOG(ERROR) << "Can't construct symbol file path without debug_identifier "
                    "(code_file = " <<
                    PathnameStripper::File(module->code_file()) <<
                    ", debug_file = " << debug_file_name << ")";
    return NOT_FOUND;
  }
  path.append(identifier);

  // Transform the debug file name into one ending in .sym.  If the existing
  // name ends in .pdb, strip the .pdb.  Otherwise, add .sym to the non-.pdb
  // name.
  path.append("/");
  string debug_file_extension;
  if (debug_file_name.size() > 4)
    debug_file_extension = debug_file_name.substr(debug_file_name.size() - 4);
  std::transform(debug_file_extension.begin(), debug_file_extension.end(),
                 debug_file_extension.begin(), tolower);
  if (debug_file_extension == ".pdb") {
    path.append(debug_file_name.substr(0, debug_file_name.size() - 4));
  } else {
    path.append(debug_file_name);
  }
  path.append(".sym.gz");

  if (!file_exists(path)) {
    BPLOG(INFO) << "No symbol file at " << path;
    return NOT_FOUND;
  }

  *symbol_file = path;
  return FOUND;
}

}  // namespace google_breakpad