#include <iostream>
#include <fstream>
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

int main(int argc, char *argv[]) {
  BPLOG_INIT(&argc, &argv);

  if (argc <= 1) {
    std::cerr << "Usage: " << argv[0] << " <config file path>" << std::endl;
    return 1;
  }

  std::ifstream configFile;
  configFile.open(argv[1]);
  if (!configFile.is_open()) {
    std::cerr << "Failed to open config file for reading: " << argv[1] << std::endl;
    return 1;
  }

  json config;
  configFile >> config;

  configFile.close();

  const auto &beanstalkHost = config["beanstalk"]["host"];
  const auto &beanstalkPort = config["beanstalk"]["port"];
  const auto &beanstalkQueue = config["beanstalk"]["queue"];

  Client queue(beanstalkHost, beanstalkPort);
  queue.watch(beanstalkQueue);

  BPLOG(INFO) << "Connected to beanstalkd @ " << beanstalkHost << ":" << beanstalkPort << " (queue: " << beanstalkQueue << ")";

  const auto &mysqlHost = config["mysql"]["host"];
  const auto &mysqlPort = config["mysql"]["port"];
  const auto &mysqlUser = config["mysql"]["user"];
  const auto &mysqlPassword = config["mysql"]["password"];
  const auto &mysqlDatabase = config["mysql"]["database"];

  Connection mysql(
    mysqlDatabase.get<string>().c_str(),
    mysqlHost.is_null() ? nullptr :mysqlHost.get<string>().c_str(),
    mysqlUser.is_null() ? nullptr :mysqlUser.get<string>().c_str(),
    mysqlPassword.is_null() ? nullptr :mysqlPassword.get<string>().c_str(),
    mysqlPort);

  BPLOG(INFO) << "Connected to MySQL @ " << mysql.ipc_info() << " (database: " << mysqlDatabase << ")";

  const std::vector<string> &symbolPaths = config["breakpad"]["symbols"];
  CompressedSymbolSupplier symbolSupplier(symbolPaths);

  const string &minidumpDirectory = config["breakpad"]["minidumps"];

  Job job;
  while (true) {
    if (!queue.reserve(job) || !job) {
      BPLOG(ERROR) << "Failed to reserve job.";
      break;
    }

    const json body = json::parse(job.body());
    const string &id = body["id"];
    BPLOG(INFO) << id << " " << body["ip"] << " " << body["owner"];

    auto start = std::chrono::steady_clock::now();

    // Create this inside the loop to avoid keeping a global symbol cache.
    RepoSourceLineResolver resolver;
    MinidumpProcessor minidumpProcessor(&symbolSupplier, &resolver);

    std::string minidumpFile = minidumpDirectory + "/" + id.substr(0, 2) + "/" + id + ".dmp";

    ProcessState processState;
    ProcessResult processResult = minidumpProcessor.Process(minidumpFile, &processState);

    if (processResult == google_breakpad::PROCESS_ERROR_MINIDUMP_NOT_FOUND) {
      queue.del(job);
      continue;
    }

    if (processResult != google_breakpad::PROCESS_OK) {
      BPLOG(ERROR) << "MinidumpProcessor::Process failed";
      queue.bury(job);
      continue;
    }

    ////////////////////////////////////////////////////////////////////////

    // If there is no requesting thread, print the main thread.
    int requestingThread = processState.requesting_thread();
    if (requestingThread == -1) {
      requestingThread = 0;
    }

    const CallStack *stack = processState.threads()->at(requestingThread);
    if (!stack) {
      BPLOG(ERROR) << "Missing stack for thread " << requestingThread;
      queue.bury(job);
      continue;
    }

    int frameCount = stack->frames()->size();
    for (int frameIndex = 0; frameIndex < frameCount; ++frameIndex) {
      const StackFrame *frame = stack->frames()->at(frameIndex);

      std::cout << frameIndex << ": ";

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

    ////////////////////////////////////////////////////////////////////////

    //__asm__("int3");

    auto end = std::chrono::steady_clock::now();

    double elapsedSeconds = ((end - start).count()) * std::chrono::steady_clock::period::num / static_cast<double>(std::chrono::steady_clock::period::den);
    std::cout << "Processing Time: " << elapsedSeconds << "s" << std::endl;

    queue.del(job);

    bool processSingleJob = config["processSingleJob"];
    if (processSingleJob) {
      break;
    }
  }

  return 0;
}
