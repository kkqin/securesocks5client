#include <functional>
#include <memory>
#include <glog/logging.h>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#endif

// network
#include "server_factory.h"
#include "server_socks5.h"
#include "mprocess.h"

static std::unique_ptr<network::Server> socks5server;
static void init_log()
{
	google::InitGoogleLogging("");
	FLAGS_log_dir = "../log/"; //指定glog输出文件路径（输出格式为 "<program name>.<hostname>.<user name>.log.<severity level>.<date>.<time>.<pid>"）
	google::SetLogDestination(google::GLOG_INFO, "../log/info_"); //第一个参数为日志级别，第二个参数表示输出目录及日志文件名前缀。
	google::SetLogDestination(google::GLOG_WARNING, "../log/warn_"); //第一个参数为日志级别，第二个参数表示输出目录及日志文件名前缀。
	google::SetLogDestination(google::GLOG_ERROR, "../log/error_"); //第一个参数为日志级别，第二个参数表示输出目录及日志文件名前缀。
	google::SetLogDestination(google::GLOG_FATAL, "../log/fatal_"); //第一个参数为日志级别，第二个参数表示输出目录及日志文件名前缀。
	google::SetLogSymlink(google::GLOG_INFO, "server");
	google::SetLogSymlink(google::GLOG_WARNING, "server");
	google::SetLogSymlink(google::GLOG_ERROR, "server");
	google::SetLogSymlink(google::GLOG_FATAL, "server");
	FLAGS_logbufsecs = 0; //实时输出日志
	FLAGS_alsologtostderr = true; // 日志输出到stderr（终端屏幕），同时输出到日志文件。 FLAGS_logtostderr = true 日志输出到stderr，不输出到日志文件。
	FLAGS_colorlogtostderr = true; //输出彩色日志到stderr
	FLAGS_minloglevel = 0; //将大于等于该级别的日志同时输出到stderr和指定文件。日志级别 INFO, WARNING, ERROR, FATAL 的值分别为0、1、2、3。
	FLAGS_max_log_size=200;
}

int main(int argc, char *argv[])
{
	printf("-----------------------------------------power by: kk\n");

	init_log();

	// Create io_service
	auto io_service = network::IOMgr::instance().netIO();
	auto onClient = std::bind(&network::Process::onRecvGameMsg, std::move(network::Process()), std::placeholders::_1);

	socks5server = network::ServerFactory::createServer(10802, onClient, network::ServerFactory::SType::SCLIENTSOCKSERVER);
	if(socks5server.get() == NULL)
		LOG(FATAL) << "create socks5server failed, target port: 10801";

	asio::signal_set signals(*(io_service.get()), SIGINT, SIGTERM);
	signals.async_wait([&io_service](const network::error_code& error, int signal_number)
	{
		LOG(WARNING) << "received error:" <<error.message().c_str()<<", signal_number:" << signal_number << ", stopping io_service.";
		io_service->stop();
	});

	io_service->run();
	
	LOG(INFO) << "Stopping Server!";
	
	// Deallocate things
	socks5server.reset();
	
	return 0;
}
