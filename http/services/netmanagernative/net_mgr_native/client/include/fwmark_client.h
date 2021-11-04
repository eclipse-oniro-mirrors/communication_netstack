#ifndef __INCLUDE_FWMARK_CLIENT_H__
#define __INCLUDE_FWMARK_CLIENT_H__

#include "fwmark_command.h"

namespace nmd {
class fwmark_client {
private:
    int channel_ = -1;

public:
    fwmark_client();
    ~fwmark_client();

    int send(fwmark_command *data);
};
} // namespace nmd

#endif //!__INCLUDE_FWMARK_CLIENT_H__