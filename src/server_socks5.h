#ifndef NETWORK_SRC_SERVER_SOCK_IMPL_H_
#define NETWORK_SRC_SERVER_SOCK_IMPL_H_

#include "server.h"

#include <memory>
#include <unordered_map>
#include <utility>
#include <list>

#include "acceptor.h"
#include "cnt_socks5.h"
#include <glog/logging.h>

#include "mprocess.h"
#include "global_io.h"

namespace network {
	template <typename Method>
	class Socks5Server : public Server
	{
	public:
		Socks5Server(int port,
			const std::function<void(std::shared_ptr<Connection>&&)>& onClientConnected)
			: index(0), acceptor_(network::IOMgr::instance().netIO().get(),
				port,
				[this, onClientConnected](asio::ip::tcp::socket&& socket) {
					DLOG(INFO) << ("onAccept()");
					asio::ssl::context ctx(asio::ssl::context::sslv23);
					ctx.load_verify_file("ca.pem");

					auto cnt = std::make_shared<Socks5ConnectionImpl<Method>>(std::move(socket), std::move(ctx), index++);
					onClientConnected(cnt);
				})
		{
		}

		// Delete copy constructors
		Socks5Server(const Socks5Server&) = delete;
		Socks5Server& operator=(const Socks5Server&) = delete;

	private:
		int index;
		AcceptorNormal acceptor_;
	};
}

#endif  // NETWORK_SRC_SERVER_IMPL_H_
