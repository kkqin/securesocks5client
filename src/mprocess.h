#ifndef NETWORK_MY_PROCESS
#define NETWORK_MY_PROCESS

#include <set>
#include "connection.h"

namespace network {
	struct Method
	{
		virtual ~Method() {}
		virtual void onPacketReceivedRaw(std::uint8_t * d_ptr, std::size_t length) = 0;
		virtual void onDisconnected() = 0;
		virtual long timeout() = 0;
	};

	struct MyMethod : public Method
	{
		static long m_timeout;
		std::shared_ptr<network::Connection> m_cnt;
		virtual void onPacketReceivedRaw(std::uint8_t * d_ptr, std::size_t length) override;
		virtual void onDisconnected() override;
		virtual long timeout() override;
	};

	class Process
	{
	public:
		void onRecvGameMsg(std::shared_ptr<network::Connection> cnt);
	private:
		static int m_index;
		std::set<std::shared_ptr<network::Connection>> m_group;
	};
}

#endif
