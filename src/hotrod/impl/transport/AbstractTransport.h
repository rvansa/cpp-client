#ifndef ISPN_HOTROD_TRANSPORT_ABSTRACTTRANSPORT_H
#define ISPN_HOTROD_TRANSPORT_ABSTRACTTRANSPORT_H



#include <sstream>

#include "hotrod/impl/transport/Transport.h"

#include "hotrod/sys/types.h"
#include "hotrod/sys/Socket.h"

namespace infinispan {
namespace hotrod {
namespace transport {

class TransportFactory;

class AbstractTransport : public Transport
{
  public:
	AbstractTransport(TransportFactory& transportFactory);

    void writeArray(const hrbytes& bytes);
    void writeLong(int64_t longValue);
    hrbytes readArray();
    int64_t readLong();
    std::string readString();

  protected:
    virtual void writeBytes(const hrbytes& bytes) = 0;
    virtual void readBytes(hrbytes& bytes, uint32_t size) = 0;

  private:
    TransportFactory& transportFactory;
};

}}} // namespace infinispan::hotrod::transport

#endif  // ISPN_HOTROD_TRANSPORT_ABSTRACTTRANSPORT_H

