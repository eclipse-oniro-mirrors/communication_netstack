#ifndef __INCLUDE_INTERFACE_UTILS_H__
#define __INCLUDE_INTERFACE_UTILS_H__
#include <netinet/in.h>

namespace OHOS {
namespace nmd {
namespace common {
namespace interface_utils {
int ifcGetAddr(const char *name, in_addr_t *addr);
int ifcSetAddr(const char *name, in_addr_t addr);
void ifcClearAddresses(const char *name);
int ifcInit(void);
int getInterfaceIndex(const char *interfaceName);
int ifcAddAddr(const char *ifName, const char *addr, const int prefixLen);
int ifcActOnAddr(uint16_t action, const char *name, const char *address, const int prefixlen, const bool nodad);
int ifcDelAddr(const char *ifName, const char *addr, const int prefixLen);

} // namespace interface_utils
} // namespace common
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_INTERFACE_UTILS_H__