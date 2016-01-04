#include <beanstalk.hpp>

#if defined(MYSQLPP_HEADERS_BURIED)
#  include <mysql++/mysql++.h>
#else
#  include <mysql++.h>
#endif

#include <processor/logging.h>

using Beanstalk::Client;

using mysqlpp::Connection;

constexpr auto config_beanstalk_host = "127.0.0.1";
constexpr auto config_beanstalk_port = 11300;

constexpr auto config_mysql_host = (const char *)NULL;
constexpr auto config_mysql_port = 0;
constexpr auto config_mysql_user = "root";
constexpr auto config_mysql_password = "";
constexpr auto config_mysql_db = "carburetor";

int main(int argc, char *argv[]) {
  BPLOG_INIT(&argc, &argv);

  Client queue(config_beanstalk_host, config_beanstalk_port);
  BPLOG(INFO) << "Connected to beanstalkd @ " << config_beanstalk_host << ":" << config_beanstalk_port;

  Connection mysql(config_mysql_db, config_mysql_host, config_mysql_user, config_mysql_password, config_mysql_port);
  BPLOG(INFO) << "Connected to MySQL @ " << mysql.ipc_info();

  return 0;
}
