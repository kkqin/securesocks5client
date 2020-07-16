#ifndef NETWORK_EXPORT_SERVER_FACTORY_H_
#define NETWORK_EXPORT_SERVER_FACTORY_H_

#include <functional>
#include <memory>

namespace network
{
	class Server;
	class Connection;
	class io_service;

	class ServerFactory
	{
	public:
		using Callback = std::function<void(std::shared_ptr<Connection>&&)>;

		enum class SType
		{
			SSOCKSERVER = 1,
			SCLIENTSOCKSERVER = 2,
		};

		static std::unique_ptr<Server> createServer(int port,
			const Callback& onClientConnected,
			ServerFactory::SType type);
	};
}

#endif  // NETWORK_EXPORT_SERVER_FACTORY_H_
