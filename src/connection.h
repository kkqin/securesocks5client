#ifndef NETWORK_CONNECTION_H_
#define NETWORK_CONNECTION_H_

#include <functional> // new add
#include <unordered_map>
#include <string>
#include <memory>

#include "Configure.h"

#ifdef USE_STANDALONE_ASIO
#include <asio.hpp>
#include <asio/steady_timer.hpp>
#include <asio/ssl.hpp>
namespace network {
	namespace error = asio::error;
	using error_code = std::error_code;
	using errc = std::errc;
	using system_error = std::system_error;
}
#else
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ssl.hpp>
namespace network{
	namespace asio = boost::asio;
	namespace error = asio::error;
	using error_code = boost::system::error_code;
	namespace errc = boost::system::errc;
	using system_error = boost::system::system_error;
}
#endif

namespace network {
class Connection : public std::enable_shared_from_this<Connection>
{
public:
	virtual ~Connection() = default;

	virtual void init() = 0;
	virtual void close(bool force) = 0;
};
}

#include "global_io.h"

#endif  // NETWORK_CONNECTION_H_
