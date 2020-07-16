#include "mprocess.h"
#include <glog/logging.h>

namespace network {
	int Process::m_index = 0;
	long MyMethod::m_timeout = 5;
	void MyMethod::onPacketReceivedRaw(std::uint8_t * d_ptr, std::size_t length)
	{
	}

	void MyMethod::onDisconnected()
	{
		DLOG(WARNING) << "connect reset";
		m_cnt.reset();
	}

	long MyMethod::timeout()
	{
		return m_timeout;
	}

	void Process::onRecvGameMsg(std::shared_ptr<network::Connection> cnt)
	{
		cnt->init();
		DLOG(INFO) << ("onRecvGameMsg end.");
	}
}
