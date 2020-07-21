#ifndef NETWORK_SRC_ACCEPTOR_H_
#define NETWORK_SRC_ACCEPTOR_H_

#include <functional>
#include <memory>
#include <utility>

#include <glog/logging.h>
#include "connection.h"

namespace network {

class Acceptor : public asio::ip::tcp::acceptor
{
public:
	Acceptor(asio::io_context& io_context, int port)  //NOLINT
		: asio::ip::tcp::acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port))
	{
	}
};

class AcceptorNormal
{
public:
	AcceptorNormal(asio::io_context* io_context,
		int port,
		const std::function<void(asio::ip::tcp::socket&&)>& onAccept)
		: acceptor_(*io_context, port),
		socket_(*io_context),
		onAccept_(onAccept)
	{
		accept();
	}

	virtual ~AcceptorNormal()
	{
		acceptor_.cancel();
	}

	// Delete copy constructors
	AcceptorNormal(const AcceptorNormal&) = delete;
	AcceptorNormal& operator=(const AcceptorNormal&) = delete;

private:
	void accept()
	{
		acceptor_.async_accept(socket_, [this](const error_code& errorCode)
		{
			if (errorCode == asio::error::basic_errors::operation_aborted)
			{
				// This instance might be deleted, so don't touch any instance variables
				return;
			}
			else if (errorCode)
			{
				DLOG(ERROR) << "Could not accept connection: " << errorCode.message();
			}
			else
			{
				//DLOG(INFO) << "Accepted connection";
				onAccept_(std::move(socket_));
			}

			// Continue to accept new connections
			accept();
		});
	}

	Acceptor acceptor_;
	asio::ip::tcp::socket socket_;
	std::function<void(asio::ip::tcp::socket&&)> onAccept_;
};
}
#endif  // NETWORK_SRC_ACCEPTOR_H_
