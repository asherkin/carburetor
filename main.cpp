#include <iostream>
#include <chrono>

#include <beanstalk.hpp>

#include <json.hpp>

#include <mysql++/mysql++.h>

#include <google_breakpad/processor/minidump.h>
#include <google_breakpad/processor/minidump_processor.h>
#include <google_breakpad/processor/process_state.h>
#include <google_breakpad/processor/call_stack.h>
#include <google_breakpad/processor/stack_frame.h>
#include <processor/logging.h>
#include <processor/pathname_stripper.h>

#include "compressed_symbol_supplier.h"
#include "repo_source_line_resolver.h"

using Beanstalk::Client;
using Beanstalk::Job;

using nlohmann::json;

using mysqlpp::Connection;

using google_breakpad::Minidump;
using google_breakpad::MinidumpProcessor;
using google_breakpad::ProcessState;
using google_breakpad::ProcessResult;
using google_breakpad::CallStack;
using google_breakpad::StackFrame;
using google_breakpad::PathnameStripper;

// This really shouldn't be in the google_breakpad namespace.
using google_breakpad::CompressedSymbolSupplier;
using google_breakpad::RepoSourceLineResolver;

constexpr auto config_beanstalk_host = "127.0.0.1";
constexpr auto config_beanstalk_port = 11300;
constexpr auto config_beanstalk_queue = "carburetor";

constexpr auto config_mysql_host = (const char *)NULL;
constexpr auto config_mysql_port = 0;
constexpr auto config_mysql_user = "carburetor";
constexpr auto config_mysql_password = "carburetor";
constexpr auto config_mysql_db = "carburetor";

enum ProcessMinidumpResult {
  PMR_Ok,
  PMR_NoFile,
  PMR_Failed,
};

ProcessMinidumpResult ProcessMinidump(CompressedSymbolSupplier *symbol_supplier, const std::string &minidump_directory, const std::string &id) {
  ProcessState process_state;
  std::string minidump_file = minidump_directory + "/" + id.substr(0, 2) + "/" + id + ".dmp";

  // Create this inside the loop to avoid keeping a global symbol cache.
  RepoSourceLineResolver resolver;
  MinidumpProcessor minidump_processor(symbol_supplier, &resolver);

  ProcessResult process_result = minidump_processor.Process(minidump_file, &process_state);

  if (process_result == google_breakpad::PROCESS_ERROR_MINIDUMP_NOT_FOUND) {
    return PMR_NoFile;
  }

  if (process_result != google_breakpad::PROCESS_OK) {
    BPLOG(ERROR) << "MinidumpProcessor::Process failed";
    return PMR_Failed;
  }

  int requesting_thread = process_state.requesting_thread();

  // If there is no requesting thread, print the main thread.
  if (requesting_thread == -1) {
    requesting_thread = 0;
  }

  const CallStack *stack = process_state.threads()->at(requesting_thread);
  if (!stack) {
    BPLOG(ERROR) << "Missing stack for thread " << requesting_thread;
    return PMR_Failed;
  }

  int frame_count = stack->frames()->size();
  for (int frame_index = 0; frame_index < frame_count; ++frame_index) {

    const StackFrame *frame = stack->frames()->at(frame_index);

    std::cout << frame_index << ": ";

    std::cout << std::hex;
    if (frame->module) {
      std::cout << PathnameStripper::File(frame->module->code_file());
      if (!frame->function_name.empty()) {
        std::cout << "!" << frame->function_name;
        if (!frame->source_file_name.empty()) {
          std::cout << " [" << PathnameStripper::File(frame->source_file_name) << ":" << std::dec << frame->source_line << std::hex << " + 0x" << frame->ReturnAddress() - frame->source_line_base << "]";
        } else {
          std::cout << " + 0x" << frame->ReturnAddress() - frame->function_base;
        }
      } else {
        std::cout << " + 0x" << frame->ReturnAddress() - frame->module->base_address();
      }
    } else {
      std::cout << "0x" << frame->ReturnAddress();
    }
    std::cout << std::dec;

    std::string repoUrl = resolver.LookupRepoUrl(frame);
    if (!repoUrl.empty()) {
      std::cout << " <" << repoUrl << ">";
    }

    std::cout << std::endl;
  }

  return PMR_Ok;
}

int main(int argc, char *argv[]) {
  BPLOG_INIT(&argc, &argv);

  CompressedSymbolSupplier symbol_supplier({
    "/var/www/breakpad/symbols/sourcemod",
    "/var/www/breakpad/symbols/valve",
    "/var/www/breakpad/symbols/microsoft",
    "/var/www/breakpad/symbols/electron",
    "/var/www/breakpad/symbols/public",
  });

  // b4eespvdg7ib viuyixuiz4yb zqpavxes3hhr

  if (argc > 1) {
    ProcessMinidump(&symbol_supplier, "/var/www/breakpad/dumps", argv[1]);
    return 0;
  }

  Client queue(config_beanstalk_host, config_beanstalk_port);
  queue.watch(config_beanstalk_queue);
  BPLOG(INFO) << "Connected to beanstalkd @ " << config_beanstalk_host << ":" << config_beanstalk_port << " (queue: " << config_beanstalk_queue << ")";

  //Connection mysql(config_mysql_db, config_mysql_host, config_mysql_user, config_mysql_password, config_mysql_port);
  //BPLOG(INFO) << "Connected to MySQL @ " << mysql.ipc_info();

  Job job;
  while (true) {
    if (!queue.reserve(job) || !job) {
      BPLOG(ERROR) << "Failed to reserve job.";
      break;
    }
 
    json body = json::parse(job.body());
    const std::string &id = body["id"];
    BPLOG(INFO) << id << " " << body["ip"] << " " << body["owner"];

    auto start = std::chrono::steady_clock::now();

    ProcessMinidumpResult result = ProcessMinidump(&symbol_supplier, "/var/www/breakpad/dumps", id);
    if (result != PMR_Ok) {
      if (result == PMR_NoFile) {
        queue.del(job);
      } else {
        queue.bury(job);
      }
      continue;
    }

    auto end = std::chrono::steady_clock::now();

    double elapsedSeconds = ((end - start).count()) * std::chrono::steady_clock::period::num / static_cast<double>(std::chrono::steady_clock::period::den);
    std::cout << "Processing Time: " << elapsedSeconds << "s" << std::endl;

    queue.del(job);
  }

  return 0;
}
