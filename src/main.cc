#include <functional>
#include <memory>
#include <glog/logging.h>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include <filesystem>
#endif

// network
#include "server_factory.h"
#include "server_socks5.h"
#include "mprocess.h"
#include "config_parser.h"

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

int ListenPort;
std::string ConnectPort;
std::string ConnectIP;
bool runAsDaemon = false;

void parseFile() {
	auto config = ConfigParser::parseFile("./server.cfg");
	ListenPort = config.getInteger("base", "listen_port", 10801);
	ConnectPort = config.getString("base", "connect_port", "1080");
	ConnectIP = config.getString("base", "connect_ip", "127.0.0.1");
	runAsDaemon = config.getBoolean("base", "runDaemon", false);
}

static int init_daemon()
{
    pid_t pid;
    if ((pid = fork()) < 0)
    {
        fprintf(stderr, "fork err, process exit 1.\n\n\n");
        exit(1);
    }
    else if (pid != 0)
    {
        exit(0);        // parent goes bye-bye
    }
    // child continues
    setsid();           // become session leader
    //chdir("/");       // change working directory
    umask(0);           // clear our file mode creation mask
 	// close file describe, keep live stdin, stdout, stderr
    for (int i = 3; i < 256; i++)
    {
        close(i);
    }
    return 0;
}

static int parent_daemon()
{
	pid_t pid;

	close(0);				  // close stdin
	close(1);				  // close stdout
	fopen("/dev/null", "wb"); // => 0
	fopen("/dev/null", "wb"); // => 1

	while (1)
	{
		// make pipe at parent and child
		int errfd[2];
		if (pipe(errfd) < 0)
		{
			printf("pipe err, process exit 2.\n\n\n");
			exit(2);
		}

		if ((pid = fork()) < 0)
		{
			printf("fork err, process exit 3.\n\n\n");
			exit(3);
		}
		else if (pid != 0)
		{
			// parent process
			int nStatus;
			pid_t childPid;
			int ret = 0;
			char buf[1024];

			// make pipe reader
			int &errfd_read = errfd[0];
			close(errfd[1]);

			while (1)
			{
				if ((childPid = waitpid(pid, &nStatus, WNOHANG)) < 0)
				{
					fprintf(stderr, "waitpid err, process exit 4.\n\n\n");
					exit(4);
				}

				if (childPid == 0)
				{
					// read pipe
					ret = read(errfd_read, buf, 1023);
					if (ret == -1)
					{
						fprintf(stderr, "read pipe err\n");
						continue;
					}
					else
					{
						buf[ret] = '\0';
						fprintf(stderr, "%s", buf);
						usleep(1000 * 10);
					}
				}
				else
				{
					// child process exit
					if (WIFEXITED(nStatus))
					{
						fprintf(stderr, "child exit code is %d\n", WEXITSTATUS(nStatus));
						if (WEXITSTATUS(nStatus) == 0)
						{
							fprintf(stderr, "parent exit\n");
							exit(0);
						}
					}
					else if (WIFSIGNALED(nStatus))
					{
						char szCoreFile[128];
						fprintf(stderr, "child process quited for signal %d\n", WTERMSIG(nStatus));
						if (WTERMSIG(nStatus) == SIGKILL)
						{
							fprintf(stderr, "parent exit\n");
							exit(0);
						}
						sprintf(szCoreFile, "core.%d", pid);
						chmod(szCoreFile, 0644);
					}
					close(errfd_read);
					usleep(10000);
					fprintf(stderr, "parent create another child process\n");
					break;
				}
			}
		}
		else
		{
			// child process
			int errfd_write = errfd[1];
			close(errfd[0]);
			//xcore::sleep(1000);
			if (errfd_write != STDERR_FILENO)
			{
				if (dup2(errfd_write, STDERR_FILENO) != STDERR_FILENO)
				{
					exit(127);
				}
			}
			close(errfd_write);
			break;
		}
	}
	return 0;
}

static void sighandler(int signo)
{
    fprintf(stderr, " recv a signal:%d\n", signo);
    if (signo == SIGUSR1)
    {
				network::IOMgr::instance().netIO()->stop();
        fprintf(stderr, "user send exit signal.\n");
    }
}

static std::string g_pidfile;
static FILE*  g_fdpid = NULL;
static bool save_pidfile()
{
  std::string path = std::filesystem::current_path();
  g_pidfile = path + "/pid";
  g_fdpid = fopen(g_pidfile.c_str(), "wt+");
  if (g_fdpid == NULL)
  {
      printf("open pid file(%s) failed.\n", g_pidfile.c_str());
      return false;
  }
  fprintf(g_fdpid, "%u", getpid());
  fflush(g_fdpid);
  //fclose(g_fdpid); // 不关闭，一直持有到进程关闭
  return true;
}

int main(int argc, char *argv[])
{
	if(runAsDaemon) {
		init_daemon();
		parent_daemon();
	}
	save_pidfile();
	printf("-----------------------------------------power by: kk\n");

	init_log();
	parseFile();

	// Create io_service
	auto io_service = network::IOMgr::instance().netIO();
	auto onClient = std::bind(&network::Process::onRecvGameMsg, std::move(network::Process()), std::placeholders::_1);

	socks5server = network::ServerFactory::createServer(ListenPort, onClient, network::ServerFactory::SType::SCLIENTSOCKSERVER);
	if(socks5server.get() == NULL)
		LOG(FATAL) << "create socks5server failed, target port: " << ListenPort;

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
