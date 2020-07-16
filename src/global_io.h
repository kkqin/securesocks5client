#ifndef _GLOBAL_IO_H_
#define _GLOBAL_IO_H_

/*#ifdef USE_STANDALONE_ASIO
#include <asio.hpp>
#else
#include <boost/asio.hpp>
namespace asio = boost::asio;
#endif
*/
#include "connection.h"

namespace network
{
	class IOMgr
	{
	public:
		static IOMgr& instance();
		std::shared_ptr<asio::io_context>& netIO();
	private:
		IOMgr();
		std::shared_ptr<asio::io_context> _io;
	};

}

#endif
