#include <beanstalk.hpp>

#include <json.hpp>

#if defined(MYSQLPP_HEADERS_BURIED)
#  include <mysql++/mysql++.h>
#else
#  include <mysql++.h>
#endif

#include <processor/logging.h>

using Beanstalk::Client;
using Beanstalk::Job;

using nlohmann::json;

using mysqlpp::Connection;

constexpr auto config_beanstalk_host = "127.0.0.1";
constexpr auto config_beanstalk_port = 11300;
constexpr auto config_beanstalk_queue = "carburetor";

constexpr auto config_mysql_host = (const char *)NULL;
constexpr auto config_mysql_port = 0;
constexpr auto config_mysql_user = "carburetor";
constexpr auto config_mysql_password = "carburetor";
constexpr auto config_mysql_db = "carburetor";

int main(int argc, char *argv[]) {
  BPLOG_INIT(&argc, &argv);

  Client queue(config_beanstalk_host, config_beanstalk_port);
  queue.watch(config_beanstalk_queue);
  BPLOG(INFO) << "Connected to beanstalkd @ " << config_beanstalk_host << ":" << config_beanstalk_port << " (queue: " << config_beanstalk_queue << ")";

  Connection mysql(config_mysql_db, config_mysql_host, config_mysql_user, config_mysql_password, config_mysql_port);
  BPLOG(INFO) << "Connected to MySQL @ " << mysql.ipc_info();

  BPLOG(INFO) << json::parse("[1, 2, 3]").dump();

  Job job;

  while (true) {
    queue.reserve(job);

    json body = json::parse(job.body());
    BPLOG(INFO) << body["id"] << " " << body["ip"] << " " << body["owner"];

    queue.del(job);
  }

  return 0;
}
