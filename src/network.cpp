/**
 * @file src/network.cpp
 * @brief Definitions for networking related functions.
 */
// standard includes
#include <algorithm>
#include <memory>
#include <sstream>
#include <unordered_map>

// local includes
#include "config.h"
#include "logging.h"
#include "network.h"
#include "utility.h"

#ifdef _WIN32
  // platform includes
  #include <iphlpapi.h>
  #include <ws2tcpip.h>

  // local includes
  #include "platform/windows/utf_utils.h"
#else
  // platform includes
  #include <arpa/inet.h>
  #include <ifaddrs.h>
  #include <net/if.h>
#endif

using namespace std::literals;

namespace ip = boost::asio::ip;

namespace net {
  /**
   * @brief Pc ips v4.
   */
  std::vector<ip::network_v4> pc_ips_v4 {
    ip::make_network_v4("127.0.0.0/8"sv),
  };
  /**
   * @brief Lan ips v4.
   */
  std::vector<ip::network_v4> lan_ips_v4 {
    ip::make_network_v4("192.168.0.0/16"sv),
    ip::make_network_v4("172.16.0.0/12"sv),
    ip::make_network_v4("10.0.0.0/8"sv),
    ip::make_network_v4("100.64.0.0/10"sv),
    ip::make_network_v4("169.254.0.0/16"sv),
  };

  /**
   * @brief Pc ips v6.
   */
  std::vector<ip::network_v6> pc_ips_v6 {
    ip::make_network_v6("::1/128"sv),
  };
  /**
   * @brief Lan ips v6.
   */
  std::vector<ip::network_v6> lan_ips_v6 {
    ip::make_network_v6("fc00::/7"sv),
    ip::make_network_v6("fe80::/64"sv),
  };

  std::vector<network_adapter_t> get_network_adapters() {
    std::vector<network_adapter_t> adapters;

#ifdef _WIN32
    constexpr ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG buffer_size = 0;
    // AF_UNSPEC keeps adapters without IPv4 visible to the Web UI; their eligibility is evaluated below.
    auto result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &buffer_size);
    if (result != ERROR_BUFFER_OVERFLOW || buffer_size == 0) {
      if (result != NO_ERROR && result != ERROR_NO_DATA) {
        BOOST_LOG(warning) << "GetAdaptersAddresses() failed while sizing the adapter buffer: "sv << result;
      }
      return adapters;
    }

    std::vector<unsigned char> buffer(buffer_size);
    auto *addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addresses, &buffer_size);
    if (result != NO_ERROR) {
      BOOST_LOG(warning) << "GetAdaptersAddresses() failed: "sv << result;
      return adapters;
    }

    for (auto *current = addresses; current != nullptr; current = current->Next) {
      network_adapter_t adapter;
      if (current->FriendlyName != nullptr) {
        adapter.name = utf_utils::to_utf8(std::wstring {current->FriendlyName});
      }
      if (current->AdapterName != nullptr) {
        adapter.id = current->AdapterName;
      }
      if (current->Description != nullptr) {
        adapter.description = utf_utils::to_utf8(std::wstring {current->Description});
      }
      if (adapter.name.empty()) {
        adapter.name = adapter.id;
      }

      adapter.is_up = current->OperStatus == IfOperStatusUp;
      adapter.is_loopback = current->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
      adapter.supports_multicast = (current->Flags & IP_ADAPTER_NO_MULTICAST) == 0;

      for (auto *unicast = current->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
        if (unicast->Address.lpSockaddr == nullptr || unicast->Address.lpSockaddr->sa_family != AF_INET) {
          continue;
        }

        // Do not expose addresses that Windows has not completed duplicate-address detection for.
        if (unicast->DadState == IpDadStateInvalid || unicast->DadState == IpDadStateTentative || unicast->DadState == IpDadStateDuplicate) {
          continue;
        }

        const auto *sockaddr = reinterpret_cast<const SOCKADDR_IN *>(unicast->Address.lpSockaddr);
        char address[INET_ADDRSTRLEN] {};
        if (InetNtopA(AF_INET, &sockaddr->sin_addr, address, sizeof(address)) != nullptr) {
          adapter.ipv4_addresses.emplace_back(address);
        }
      }

      adapters.emplace_back(std::move(adapter));
    }
#else
    ifaddrs *raw_addresses = nullptr;
    if (getifaddrs(&raw_addresses) != 0 || raw_addresses == nullptr) {
      BOOST_LOG(warning) << "getifaddrs() failed while enumerating network adapters"sv;
      return adapters;
    }
    std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> addresses {raw_addresses, freeifaddrs};

    std::unordered_map<std::string, std::size_t> adapter_indexes;
    for (auto *current = raw_addresses; current != nullptr; current = current->ifa_next) {
      if (current->ifa_name == nullptr) {
        continue;
      }

      const std::string name {current->ifa_name};
      auto [index_it, inserted] = adapter_indexes.try_emplace(name, adapters.size());
      if (inserted) {
        network_adapter_t adapter;
        adapter.name = name;
        adapter.id = name;
        adapters.emplace_back(std::move(adapter));
      }

      auto &adapter = adapters[index_it->second];
      adapter.is_up = adapter.is_up || ((current->ifa_flags & IFF_UP) != 0);
      adapter.is_loopback = adapter.is_loopback || ((current->ifa_flags & IFF_LOOPBACK) != 0);
      adapter.supports_multicast = adapter.supports_multicast || ((current->ifa_flags & IFF_MULTICAST) != 0);

      if (current->ifa_addr == nullptr || current->ifa_addr->sa_family != AF_INET) {
        continue;
      }

      const auto *sockaddr = reinterpret_cast<const sockaddr_in *>(current->ifa_addr);
      char address[INET_ADDRSTRLEN] {};
      if (inet_ntop(AF_INET, &sockaddr->sin_addr, address, sizeof(address)) != nullptr) {
        adapter.ipv4_addresses.emplace_back(address);
      }
    }
#endif

    return adapters;
  }

  bool is_network_adapter_eligible(const network_adapter_t &adapter) {
    return adapter.is_up &&
           !adapter.is_loopback &&
           adapter.supports_multicast &&
           !adapter.ipv4_addresses.empty();
  }

  /**
   * @brief Convert configuration text to a network enum value.
   */
  net_e from_enum_string(const std::string_view &view) {
    if (view == "wan") {
      return WAN;
    }
    if (view == "lan") {
      return LAN;
    }

    return PC;
  }

  /**
   * @brief Convert a Boost address family to Sunshine network enum value.
   */
  net_e from_address(const std::string_view &view) {
    auto addr = normalize_address(ip::make_address(view));

    if (addr.is_v6()) {
      for (auto &range : pc_ips_v6) {
        if (range.hosts().find(addr.to_v6()) != range.hosts().end()) {
          return PC;
        }
      }

      for (auto &range : lan_ips_v6) {
        if (range.hosts().find(addr.to_v6()) != range.hosts().end()) {
          return LAN;
        }
      }
    } else {
      for (auto &range : pc_ips_v4) {
        if (range.hosts().find(addr.to_v4()) != range.hosts().end()) {
          return PC;
        }
      }

      for (auto &range : lan_ips_v4) {
        if (range.hosts().find(addr.to_v4()) != range.hosts().end()) {
          return LAN;
        }
      }
    }

    return WAN;
  }

  /**
   * @brief Convert a network enum value to configuration text.
   */
  std::string_view to_enum_string(net_e net) {
    switch (net) {
      case PC:
        return "pc"sv;
      case LAN:
        return "lan"sv;
      case WAN:
        return "wan"sv;
    }

    // avoid warning
    return "wan"sv;
  }

  af_e af_from_enum_string(const std::string_view &view) {
    if (view == "ipv4") {
      return IPV4;
    }
    if (view == "both") {
      return BOTH;
    }

    // avoid warning
    return BOTH;
  }

  std::string_view af_to_any_address_string(const af_e af) {
    switch (af) {
      case IPV4:
        return "0.0.0.0"sv;
      case BOTH:
        return "::"sv;
    }

    // avoid warning
    return "::"sv;
  }

  std::string get_bind_address(const af_e af) {
    // If bind_address is configured, use it
    if (!config::sunshine.bind_address.empty()) {
      return config::sunshine.bind_address;
    }

    // Otherwise use the wildcard address for the given address family
    return std::string(af_to_any_address_string(af));
  }

  boost::asio::ip::address normalize_address(boost::asio::ip::address address) {
    // Convert IPv6-mapped IPv4 addresses into regular IPv4 addresses
    if (address.is_v6()) {
      auto v6 = address.to_v6();
      if (v6.is_v4_mapped()) {
        return boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, v6);
      }
    }

    return address;
  }

  std::string addr_to_normalized_string(boost::asio::ip::address address) {
    return normalize_address(address).to_string();
  }

  std::string addr_to_url_escaped_string(boost::asio::ip::address address) {
    address = normalize_address(address);
    if (address.is_v6()) {
      std::stringstream ss;
      ss << '[' << address.to_string() << ']';
      return ss.str();
    } else {
      return address.to_string();
    }
  }

  int encryption_mode_for_address(boost::asio::ip::address address) {
    auto nettype = net::from_address(address.to_string());
    if (nettype == net::net_e::PC || nettype == net::net_e::LAN) {
      return config::stream.lan_encryption_mode;
    } else {
      return config::stream.wan_encryption_mode;
    }
  }

  /**
   * @brief Create an ENet host with the requested address family.
   */
  host_t host_create(af_e af, ENetAddress &addr, std::uint16_t port) {
    static std::once_flag enet_init_flag;
    std::call_once(enet_init_flag, []() {
      enet_initialize();
    });

    const auto bind_addr = net::get_bind_address(af);
    enet_address_set_host(&addr, bind_addr.c_str());
    enet_address_set_port(&addr, port);

    // Maximum of 128 clients, which should be enough for anyone
    auto host = host_t {enet_host_create(af == IPV4 ? AF_INET : AF_INET6, &addr, 128, 0, 0, 0)};

    // Enable opportunistic QoS tagging (automatically disables if the network appears to drop tagged packets)
    enet_socket_set_option(host->socket, ENET_SOCKOPT_QOS, 1);

    return host;
  }

  /**
   * @brief Destroy an ENet host allocated by host_create().
   */
  void free_host(ENetHost *host) {
    std::for_each(host->peers, host->peers + host->peerCount, [](ENetPeer &peer_ref) {
      ENetPeer *peer = &peer_ref;

      if (peer) {
        enet_peer_disconnect_now(peer, 0);
      }
    });

    enet_host_destroy(host);
  }

  std::uint16_t map_port(int port) {
    // calculate the port from the config port
    auto mapped_port = (std::uint16_t) ((int) config::sunshine.port + port);

    // Ensure port is in the range of 1024-65535
    if (mapped_port < 1024 || mapped_port > 65535) {
      BOOST_LOG(warning) << "Port out of range: "sv << mapped_port;
    }

    return mapped_port;
  }

  /**
   * @brief Returns a string for use as the instance name for mDNS.
   * @param hostname The hostname to use for instance name generation.
   * @return Hostname-based instance name or "Sunshine" if hostname is invalid.
   */
  std::string mdns_instance_name(const std::string_view &hostname) {
    // Start with the unmodified hostname
    std::string instancename {hostname.data(), hostname.size()};

    // Truncate to 63 characters per RFC 6763 section 7.2.
    if (instancename.size() > 63) {
      instancename.resize(63);
    }

    for (auto i = 0; i < instancename.size(); i++) {
      // Replace any spaces with dashes
      if (instancename[i] == ' ') {
        instancename[i] = '-';
      } else if (!std::isalnum(instancename[i]) && instancename[i] != '-') {
        // Stop at the first invalid character
        instancename.resize(i);
        break;
      }
    }

    return !instancename.empty() ? instancename : "Sunshine";
  }
}  // namespace net
