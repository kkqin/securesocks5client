#include "global_io.h"

namespace network
{
IOMgr& IOMgr::instance()
{
	static IOMgr _instance;
	return _instance;
}

std::shared_ptr<asio::io_service>& IOMgr::netIO()
{
	return _io;
}

IOMgr::IOMgr()
{
	_io = std::make_shared<asio::io_service>();
}
}
