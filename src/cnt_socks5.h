#ifndef NETWORK_SRC_CNT_SOCKS5_H_
#define NETWORK_SRC_CNT_SOCKS5_H_

#include "connection.h"

#include <deque>
#include <memory>
#include <vector>
#include <utility>
#include <chrono>

#include <glog/logging.h>

extern int ListenPort;
extern std::string ConnectPort;
extern std::string ConnectIP;

namespace network {
	template <typename Method>
	class Socks5ConnectionImpl : public Connection
	{
	public:
		Socks5ConnectionImpl(asio::ip::tcp::socket&& socket,
					asio::ssl::context&& ctx, int index)
			: socket_(std::move(socket)),
			remote_socket_(*IOMgr::instance().netIO().get(), ctx),
			closing_(false),
			is_auth(false),
			resolver(*network::IOMgr::instance().netIO().get()),
			id(index),
			total_upload(0),
			total_download(0)
		{
			method_ = std::make_unique<Method>();
		}

		virtual ~Socks5ConnectionImpl()
		{
			/*DLOG(WARNING) << __func__ << " dead " << "index: "<< id ;
			DLOG(WARNING) << "upload bytes:" << total_upload << " download bytes:" << total_download;
			socket_.close(); 
			remote_socket_.lowest_layer().close();
			method_.reset();
			DLOG(WARNING) << __func__
				<< ": called with closing_:" << (closing_ ? "true" : "false");*/
		}

		// Delete copy constructors
		Socks5ConnectionImpl(const Socks5ConnectionImpl&) = delete;
		Socks5ConnectionImpl& operator=(const Socks5ConnectionImpl&) = delete;

		void set_timeout(long seconds)
		{
			if (seconds == 0) {
				timer_ = nullptr;
				return;
			}

			timer_ = std::unique_ptr<asio::steady_timer>(new asio::steady_timer(socket_.get_executor(), std::chrono::seconds(seconds)));
			std::weak_ptr<Connection> self_weak(this->shared_from_this());
			timer_->async_wait([self_weak](const error_code &ec) {
				if (!ec)
				{
					if (auto self = self_weak.lock()) {
						DLOG(INFO) << "time out";
						self->close(true);
					}
				}
			});
		}

		void cancel_timeout()
		{
			if (timer_) {
				try {
					error_code ec;
					timer_->cancel(ec);
				} catch (...) {
				}
			}
		}

		void init() override
		{
			method_->m_cnt = shared_from_this();
			read_handshake();
		}

		void close(bool force) override
		{
			/*if (closing_)
			{
				DLOG(WARNING) << __func__ << "called with shutdown_: true";
				//return;
			}

			closing_ = true;

			DLOG(WARNING) << __func__
				<< ": force: " << (force ? "true" : "false");*/

			// We can close the socket now if either we should force close,
			// or if there are no send in progress (i.e. no queued packets)
			if (force)
			{
				closeSocket();  // Note that this instance might be deleted during this call
			}
			// Else: we should send all queued packets before closing the connection
		}

	private:

		void read_handshake()
		{
			this->set_timeout(method_->timeout());
			asio::async_read(socket_,
				asio::buffer(in_buf), asio::transfer_exactly(3),
				[this](const error_code& errorCode, std::size_t len) {
					this->cancel_timeout();
					if (errorCode || closing_ || len < 3u) {
						DLOG(ERROR) << __func__
									<< ": errorCode: " << errorCode.message()
									<< " len expect 3u but now: " << len
									<< " closing_: " << (closing_ ? "true" : "false");
						closeSocket(); // Note that this instance might be deleted during this call
						return;
					}

					if (in_buf[0] != 0x05) {
						DLOG(ERROR) << __func__ << " version not support.";
						closeSocket();
						return;
					}

					uint8_t num_methods = in_buf[1];
					in_buf[1] = 0xFF;
					for (uint8_t method = 0; method < num_methods; ++method) {
						if (in_buf[2 + method] == 0x00) {
							in_buf[1] = 0x00;
							break;
						}

						if (in_buf[2 + method] == 0x02) {
							in_buf[1] = 0x02;
							is_auth = true;
							break;
						}
					}

					write_handshake();
			});
		}

		void do_auth() {
			this->set_timeout(method_->timeout());
			socket_.async_receive(
				asio::buffer(in_buf),
				[this](const error_code& errorCode, std::size_t len) {
				this->cancel_timeout();

				if (errorCode) {
					closeSocket();
					return;
				}

				// default no auth
				this->is_auth = false;
				in_buf[1] = 0x00;
				write_handshake();
			});
		}

		void write_handshake()
		{
			this->set_timeout(method_->timeout());
			asio::async_write(socket_,
				asio::buffer(in_buf,2),
				[this](const error_code& errorCode, std::size_t len) {
				this->cancel_timeout();
					if(errorCode) {
						DLOG(ERROR) << __func__
									<< ": errorCode: " << errorCode.message();
						closeSocket();
						return;
					}

					if(in_buf[1] == 0xFF) {
						closeSocket();
						return;
					}

					if (!this->is_auth)
						read_request();
					else
						do_auth();
				});
		}

		void read_request()
		{
			this->set_timeout(method_->timeout());
			socket_.async_receive(
				asio::buffer(in_buf),
				[this](const error_code& errorCode, std::size_t len) {
				this->cancel_timeout();
					if (errorCode || closing_) {
						DLOG(ERROR) << __func__
									<< ": errorCode: " << errorCode.message();
						closeSocket();
						return;
					}

					if (len < 5 || in_buf[0] != 0x05 || in_buf[1] != 0x01) {
						DLOG(ERROR) << __func__
									<< " :socks conect requset invaild.";
						closeSocket();
						return;
					}

					uint8_t addr_type = in_buf[3], host_length;
					trans_len = len;
					switch (addr_type)
					{
					case 0x01: // IP V4 addres
						if (len != 10) { return; }
						remote_host_ = asio::ip::address_v4(ntohl(*((uint32_t*)&in_buf[4]))).to_string();
						remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf[8])));
						break;
					case 0x03: // DOMAINNAME
						host_length = in_buf[4];
						if (len != (size_t)(5 + host_length + 2)) { return; }
						remote_host_ = std::string(&in_buf[5], host_length);
						remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf[5 + host_length])));
						break;
					default:
						break;
					}

					DLOG(INFO) <<"cnt: "<< id <<  " prepare request " << remote_host_ << ":" << remote_port_;

					do_socks_ssl_prepare();
			});
		}

		void do_socks_ssl_prepare() {
			this->set_timeout(method_->timeout());
			//verify
			remote_socket_.set_verify_mode(asio::ssl::verify_peer);
			remote_socket_.set_verify_callback(
				[this](bool p, asio::ssl::verify_context& context)-> bool {
					return true;
				});

			resolver.async_resolve(asio::ip::tcp::resolver::query({ ConnectIP, ConnectPort }),
			[this](const error_code& errorCode, asio::ip::tcp::resolver::iterator it) {
				this->cancel_timeout();
				if (errorCode) {
					DLOG(ERROR) << "resolve "<< remote_host_ << " error. code:" << errorCode.message();
					closeSocket();
					return;
				}

				do_remote_ssl_socks_connect(it);
			});
		}

		void do_remote_ssl_socks_connect(asio::ip::tcp::resolver::iterator& it) {
			this->set_timeout(method_->timeout());
			remote_socket_.lowest_layer().async_connect(*it,
				[this](const error_code& errorCode) {
				this->cancel_timeout();
				if(errorCode) {
					DLOG(ERROR) << "connect ssl error:"<< errorCode.message();
					closeSocket();
					return;
				}

				do_handshake();
				});
		}

		void do_handshake() {
			this->set_timeout(method_->timeout());
			remote_socket_.async_handshake(asio::ssl::stream_base::client,
				[this](const error_code& errorCode) {
				this->cancel_timeout();
				if(errorCode) {
					DLOG(ERROR) << "handshake ssl error:"<< errorCode.message();
					closeSocket();
					return;
				}

				do_client_socks5();
				});
		}

		void do_client_socks5() {
			auto self(shared_from_this());
			// request remote ssl socks
			req[0] = 0x05;
			req[1] = 0x01;
			req[2] = 0x02; //auth

			out_auth = true;
			this->set_timeout(method_->timeout());
			asio::async_write(remote_socket_,
				asio::buffer(req),
				[this, self](const error_code& errorCode, std::size_t len){
				this->cancel_timeout();
				if(errorCode) {
					DLOG(ERROR) << "do client socks5 ssl error:"<< errorCode.message();
					closeSocket();
					return;
				}

				read_response_server();
			});
		}

		void read_response_server() {
			auto self(shared_from_this());
			this->set_timeout(method_->timeout());
			remote_socket_.async_read_some(asio::buffer(req),
				[this, self](const error_code& errorCode, std::size_t len) {
				this->cancel_timeout();
				if(errorCode || req[1] != 0x02) {
					DLOG(ERROR) << errorCode.message() << " req:" << req[1];
					closeSocket();
					return;
				}

				passing_auth();
			});
		}

		void passing_auth() {
			auto self(shared_from_this());
			std::string uname{"letus"};
			std::string pwd{"bebrave"};
			authLength = (1 + 1 + uname.length() + 1 + pwd.length());
			uint8_t* st = (std::uint8_t*)malloc(authLength * sizeof(char));
			st[0] = 0x05;
			st[1] = uname.length();
			memcpy(st + 1 + 1, uname.c_str(), uname.length());
			st[1 + 1 + uname.length()] = pwd.length();
			memcpy(st + 1 + 1 + uname.length() + 1, pwd.c_str(), pwd.length() + 1);
			this->set_timeout(method_->timeout());
			asio::async_write(remote_socket_,
				asio::buffer(st, authLength),
				[this, st, self](const error_code& errorCode, std::size_t len){
				this->cancel_timeout();
				if(errorCode) {
					DLOG(ERROR) << "error:" << errorCode.message();
					closeSocket();
					return;
				}

				this->set_timeout(method_->timeout());
				remote_socket_.async_read_some(asio::buffer(req),
						[this, self](const error_code& errorCode, std::size_t len) {
						this->cancel_timeout();
						if(errorCode || req[1] != 0x00) {
							DLOG(ERROR) << "error:" << errorCode.message()
								<< " req:" << std::to_string(req[1]) ;
							closeSocket();
							return;
						}

						write_remote_socks5();
					});
			});
		}

		void write_remote_socks5() {
			auto self(shared_from_this());
			this->set_timeout(method_->timeout());
			asio::async_write(remote_socket_,
				asio::buffer(in_buf),
				asio::transfer_exactly(trans_len),
				[this, self](const error_code& errorCode, std::size_t len) {
				this->cancel_timeout();
				if(errorCode){
					DLOG(ERROR) << "error:" << errorCode.message();
					closeSocket();
					return;
				}

				read_remote_socks5();
			});
		}

		void read_remote_socks5() {
			auto self(shared_from_this());
			this->set_timeout(method_->timeout());
			remote_socket_.async_read_some(
				asio::buffer(in_buf),
				[this, self](const error_code& errorCode, std::size_t len) {
				this->cancel_timeout();
				if(errorCode) {
					DLOG(ERROR) << "error:" << errorCode.message();
					closeSocket();
					return;
				}

				write_local_socks5();
			});
		}

		void write_local_socks5() {
			auto self(shared_from_this());
			this->set_timeout(method_->timeout());
			asio::async_write(socket_, asio::buffer(in_buf, 10),
				[this, self](const error_code& errorCode, std::size_t len) {
				this->cancel_timeout();
				if(errorCode) {
					closeSocket();
					return;
				}

				do_read(3);
			});
		}

		void do_read(int direction) {
			this->set_timeout(method_->timeout());
			auto self(shared_from_this());
			if (direction & 0x01) {
				asio::async_read(socket_, asio::buffer(in_buf), asio::transfer_at_least(1),
					[this, self](const error_code& errorCode, std::size_t len) {
					this->cancel_timeout();
					if (errorCode) {
						DLOG(ERROR) << "do read up error:" << errorCode.message();
						closeSocket();
						return;
					}

					total_upload += len;
					do_write(1, len);
				});
			}

			if (direction & 0x02) {
				asio::async_read(remote_socket_, asio::buffer(out_buf), asio::transfer_at_least(1),
					[this, self](const error_code& errorCode, std::size_t len) {
					this->cancel_timeout();
					if (errorCode) {
						DLOG(ERROR) << "do read down error:" << errorCode.message();
						closeSocket();
						return;
					}

					total_download += len;
					do_write(2, len);
				});
			}
		}

		void do_write(int direction, std::size_t length) {
			this->set_timeout(method_->timeout());
			auto self(shared_from_this());
			switch (direction) {
			case 1:
				asio::async_write(remote_socket_, asio::buffer(in_buf, length),
					[this, self, direction](const error_code& errorCode, std::size_t len) {
					this->cancel_timeout();
					if (errorCode) {
						closeSocket();
						return;
					}
					do_read(direction);
				});
				break;

			case 2:
				asio::async_write(socket_, asio::buffer(out_buf, length),
					[this, self, direction](const error_code& errorCode, std::size_t len) {
					if (errorCode) {
						closeSocket();
						return;
					}
					do_read(direction);
				});
				break;
			}
		}

		void closeSocket()
		{
			error_code error;
			socket_.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both, error);
			socket_.lowest_layer().close(error);
			remote_socket_.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both, error);
			remote_socket_.lowest_layer().close(error);
			DLOG(WARNING) << "index: " << id << " dying..." ;
			socket_.close();
			remote_socket_.lowest_layer().close();
			// Time to delete this instance
			method_->onDisconnected();
		}

		asio::ip::tcp::socket socket_;
		asio::ssl::stream<asio::ip::tcp::socket> remote_socket_;
		std::unique_ptr<Method> method_;
		std::unique_ptr<asio::steady_timer> timer_;

		bool closing_;
		bool is_auth, out_auth;

		// I/O Buffers
		char* reuse_buf;
		std::array<char, 4096> in_buf;
		std::array<char, 4096> out_buf;
		std::array<char, 3> req;
		std::string remote_host_;
		std::string remote_port_;
		asio::ip::tcp::resolver resolver;
		std::size_t authLength;

		int trans_len;
		int id;
		long long total_upload;
		long long total_download;

		std::mutex mutex_;
	};
}

#endif
