/**
 * @file src/upnp.cpp
 * @brief Definitions for UPnP port mapping.
 */
// standard includes
#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <optional>
#include <ranges>
#include <regex>
#include <stddef.h>  // workaround for type_t error in miniupnpc 2.3.3, see https://github.com/miniupnp/miniupnp/commit/e263ab6f56c382e10fed31347ec68095d691a0e8
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

// lib includes
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>

#ifdef _WIN32
  // platform includes
  #include <winsock2.h>
  #include <ws2tcpip.h>
#endif

// local includes
#include "config.h"
#include "confighttp.h"
#include "globals.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "rtsp.h"
#include "stream.h"
#include "upnp.h"
#include "utility.h"

using namespace std::literals;

namespace upnp {

  /**
   * @brief UPnP port mapping description and lease state.
   */
  struct mapping_t {
    struct {
      std::string wan;
      std::string lan;
      std::string proto;
    } port;  ///< WAN/LAN/protocol tuple for the mapped port.

    std::string description;  ///< Human-readable UPnP lease description advertised to the gateway.
  };

  /**
   * @brief Adapter and IPv4 address pair used for one MiniUPnPc discovery attempt.
   */
  struct discovery_target_t {
    std::string adapter_name;  ///< Human-readable adapter name used in diagnostics.
    std::string adapter_id;  ///< Native adapter identifier used in diagnostics.
    std::string address;  ///< IPv4 address passed to MiniUPnPc as the multicast interface.
  };

  /**
   * @brief Format an adapter's IPv4 addresses for diagnostic logging.
   *
   * @param addresses IPv4 addresses assigned to the adapter.
   * @return Comma-separated IPv4 addresses, or `<none>` when no address is assigned.
   */
  static std::string format_ipv4_addresses(const std::vector<std::string> &addresses) {
    if (addresses.empty()) {
      return "<none>";
    }

    std::string result;
    for (const auto &address : addresses) {
      if (!result.empty()) {
        result += ", ";
      }
      result += address;
    }
    return result;
  }

  /**
   * @brief Return the best display label for an enumerated adapter.
   *
   * @param adapter Adapter to label.
   * @return Friendly adapter name, native ID, or `<unnamed>` when neither is available.
   */
  static std::string adapter_display_name(const net::network_adapter_t &adapter) {
    if (!adapter.name.empty()) {
      return adapter.name;
    }
    if (!adapter.id.empty()) {
      return adapter.id;
    }
    return "<unnamed>";
  }

  /**
   * @brief Check whether a configured selector identifies an adapter.
   *
   * @param adapter Enumerated adapter to inspect.
   * @param selector Configured friendly name, native ID, or IPv4 address.
   * @return `true` when the selector exactly identifies the adapter.
   */
  static bool adapter_matches_selector(const net::network_adapter_t &adapter, const std::string_view selector) {
    if (adapter.name == selector || adapter.id == selector) {
      return true;
    }

    return std::ranges::any_of(adapter.ipv4_addresses, [selector](const std::string &address) {
      return address == selector;
    });
  }

  /**
   * @brief Build the ordered IPv4 discovery candidates selected by configuration.
   *
   * @details An explicit allow-list is strict: only adapters matching one of its
   * selectors are considered. An empty allow-list with a non-empty blacklist uses
   * every eligible adapter after blacklist filtering.
   *
   * @return Ordered adapter/address pairs for MiniUPnPc discovery.
   */
  static std::vector<discovery_target_t> get_ipv4_discovery_targets() {
    const auto adapters = net::get_network_adapters();
    std::vector<discovery_target_t> targets;
    std::unordered_set<std::string> seen_targets;

    std::optional<std::regex> blacklist;
    if (!config::sunshine.upnp_adapter_blacklist.empty()) {
      try {
        blacklist.emplace(config::sunshine.upnp_adapter_blacklist, std::regex_constants::ECMAScript | std::regex_constants::icase);
      } catch (const std::regex_error &err) {
        BOOST_LOG(error) << "Invalid UPnP adapter blacklist regex: "sv << err.what();
        return {};
      }
    }

    auto add_adapter = [&](const net::network_adapter_t &adapter) {
      const auto name = adapter_display_name(adapter);
      const auto addresses = format_ipv4_addresses(adapter.ipv4_addresses);

      if (blacklist && (std::regex_search(adapter.name, *blacklist) || std::regex_search(adapter.id, *blacklist) || std::regex_search(adapter.description, *blacklist))) {
        BOOST_LOG(debug) << "UPnP adapter blacklist skip: name ["sv << name
                         << "], IPv4 ["sv << addresses
                         << "], native ID ["sv << adapter.id
                         << "], description ["sv << adapter.description << ']';
        return;
      }

      if (!net::is_network_adapter_eligible(adapter)) {
        BOOST_LOG(debug) << "Skipping ineligible UPnP adapter: name ["sv << name
                         << "], IPv4 ["sv << addresses
                         << "], up ["sv << adapter.is_up
                         << "], loopback ["sv << adapter.is_loopback
                         << "], multicast ["sv << adapter.supports_multicast << ']';
        return;
      }

      for (const auto &address : adapter.ipv4_addresses) {
        std::string key = adapter.id.empty() ? adapter.name : adapter.id;
        key += '\n';
        key += address;
        if (!seen_targets.insert(key).second) {
          continue;
        }

        targets.emplace_back(discovery_target_t {name, adapter.id, address});
      }
    };

    if (!config::sunshine.upnp_adapters.empty()) {
      for (const auto &selector : config::sunshine.upnp_adapters) {
        bool matched = false;
        for (const auto &adapter : adapters) {
          if (!adapter_matches_selector(adapter, selector)) {
            continue;
          }

          matched = true;
          add_adapter(adapter);
        }

        if (!matched) {
          BOOST_LOG(warning) << "Configured UPnP adapter selector was not found: ["sv << selector << ']';
        }
      }
    } else {
      for (const auto &adapter : adapters) {
        add_adapter(adapter);
      }
    }

    return targets;
  }

  static std::string_view status_string(int status) {
    switch (status) {
      case 0:
        return "No IGD device found"sv;
      case 1:
        return "Valid IGD device found"sv;
      case 2:
        return "Valid IGD device found,  but it isn't connected"sv;
      case 3:
        return "A UPnP device has been found,  but it wasn't recognized as an IGD"sv;
    }

    return "Unknown status"sv;
  }

  /**
   * @brief Check whether a port mapping is one of Sunshine's own entries.
   *
   * @details The description is the only ownership marker exposed by the
   * UPnP port-mapping APIs. Require the expected internal port as well so a
   * manually created entry using a Sunshine port but a different destination
   * cannot be removed accidentally.
   *
   * @param mapping Mapping Sunshine is trying to create.
   * @param internal_port Existing mapping's internal port.
   * @param description Existing mapping's description.
   * @return `true` when the existing entry matches Sunshine's mapping.
   */
  static bool is_sunshine_mapping(const mapping_t &mapping, const std::string_view internal_port, const std::string_view description) {
    return internal_port == mapping.port.lan && description == mapping.description;
  }

#ifdef _WIN32
  /**
   * @brief Send a DeletePortMapping request from a specific local IPv4 address.
   *
   * @details A few Windows residential gateways authorize a port-mapping
   * deletion by the source address of the control point. MiniUPnPc does not
   * expose a source-address binding for SOAP requests, so retry the deletion
   * with a small Windows socket client when the old internal client is still
   * assigned to this host.
   *
   * @param urls urls_t from UPNP_GetValidIGD().
   * @param data IGDdatas from UPNP_GetValidIGD().
   * @param mapping Mapping to delete.
   * @param source_address Local IPv4 address used as the SOAP source.
   * @return UPnP error code or MiniUPnPc command error.
   */
  static int delete_port_mapping_from_address(const urls_t &urls, const IGDdatas &data, const mapping_t &mapping, const std::string_view source_address) {
    if (urls->controlURL == nullptr || source_address.empty()) {
      return UPNPCOMMAND_INVALID_ARGS;
    }

    constexpr std::string_view HTTP_PREFIX = "http://";
    const std::string_view control_url {urls->controlURL};
    if (!control_url.starts_with(HTTP_PREFIX)) {
      return UPNPCOMMAND_HTTP_ERROR;
    }

    const auto authority_start = HTTP_PREFIX.size();
    const auto path_start = control_url.find('/', authority_start);
    if (path_start == std::string_view::npos) {
      return UPNPCOMMAND_HTTP_ERROR;
    }

    const auto authority = control_url.substr(authority_start, path_start - authority_start);
    if (authority.empty() || authority.front() == '[') {
      // This fallback intentionally handles IPv4 control URLs only.
      return UPNPCOMMAND_HTTP_ERROR;
    }

    const auto port_separator = authority.rfind(':');
    const auto host = authority.substr(0, port_separator == std::string_view::npos ? authority.size() : port_separator);
    if (host.empty()) {
      return UPNPCOMMAND_HTTP_ERROR;
    }

    std::uint16_t port = 80;
    if (port_separator != std::string_view::npos) {
      const auto port_text = authority.substr(port_separator + 1);
      unsigned int parsed_port = 0;
      const auto [end, error] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), parsed_port);
      if (error != std::errc {} || end != port_text.data() + port_text.size() || parsed_port > UINT16_MAX) {
        return UPNPCOMMAND_HTTP_ERROR;
      }
      port = static_cast<std::uint16_t>(parsed_port);
    }

    std::string host_string {host};
    std::string port_string {std::to_string(port)};
    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo *resolved = nullptr;
    if (getaddrinfo(host_string.c_str(), port_string.c_str(), &hints, &resolved) != 0 || resolved == nullptr) {
      return UPNPCOMMAND_HTTP_ERROR;
    }

    sockaddr_in destination = *reinterpret_cast<const sockaddr_in *>(resolved->ai_addr);
    freeaddrinfo(resolved);

    sockaddr_in local {};
    local.sin_family = AF_INET;
    if (InetPtonA(AF_INET, std::string {source_address}.c_str(), &local.sin_addr) != 1) {
      return UPNPCOMMAND_INVALID_ARGS;
    }

    const auto socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET) {
      return UPNPCOMMAND_HTTP_ERROR;
    }

    struct socket_guard_t {
      SOCKET handle;

      ~socket_guard_t() {
        closesocket(handle);
      }
    } socket_guard {socket_handle};

    if (bind(socket_handle, reinterpret_cast<const sockaddr *>(&local), sizeof(local)) == SOCKET_ERROR || connect(socket_handle, reinterpret_cast<const sockaddr *>(&destination), sizeof(destination)) == SOCKET_ERROR) {
      return UPNPCOMMAND_HTTP_ERROR;
    }

    constexpr DWORD SOCKET_TIMEOUT_MS = 5000;
    (void) setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&SOCKET_TIMEOUT_MS), sizeof(SOCKET_TIMEOUT_MS));
    (void) setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&SOCKET_TIMEOUT_MS), sizeof(SOCKET_TIMEOUT_MS));

    const std::string service_type {data.first.servicetype};
    const std::string soap_body =
      "<?xml version=\"1.0\"?>\r\n"
      "<s:Envelope s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" "
      "xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>"
      "<u:DeletePortMapping xmlns:u=\"" +
      service_type +
      "\">"
      "<NewRemoteHost></NewRemoteHost>"
      "<NewExternalPort>" +
      mapping.port.wan +
      "</NewExternalPort>"
      "<NewProtocol>" +
      mapping.port.proto +
      "</NewProtocol>"
      "</u:DeletePortMapping></s:Body></s:Envelope>\r\n";
    const std::string request =
      "POST " + std::string {control_url.substr(path_start)} +
      " HTTP/1.1\r\n"
      "Host: " +
      host_string + ":" + port_string +
      "\r\n"
      "SOAPACTION: \"" +
      service_type +
      "#DeletePortMapping\"\r\n"
      "Content-Type: text/xml; charset=\"utf-8\"\r\n"
      "Content-Length: " +
      std::to_string(soap_body.size()) +
      "\r\n"
      "Connection: close\r\n\r\n" +
      soap_body;

    std::size_t sent = 0;
    while (sent < request.size()) {
      const auto count = send(socket_handle, request.data() + sent, static_cast<int>(request.size() - sent), 0);
      if (count == SOCKET_ERROR || count == 0) {
        return UPNPCOMMAND_HTTP_ERROR;
      }
      sent += static_cast<std::size_t>(count);
    }

    std::string response;
    std::array<char, 4096> buffer {};
    while (true) {
      const auto count = recv(socket_handle, buffer.data(), static_cast<int>(buffer.size()), 0);
      if (count == 0) {
        break;
      }
      if (count == SOCKET_ERROR) {
        return UPNPCOMMAND_HTTP_ERROR;
      }
      response.append(buffer.data(), static_cast<std::size_t>(count));
      if (response.size() > 65536) {
        return UPNPCOMMAND_HTTP_ERROR;
      }
    }

    if (response.empty()) {
      return UPNPCOMMAND_HTTP_ERROR;
    }

    const auto error_begin = response.find("<errorCode>");
    if (error_begin != std::string::npos) {
      const auto code_begin = error_begin + std::string_view {"<errorCode>"}.size();
      const auto code_end = response.find("</errorCode>", code_begin);
      if (code_end != std::string::npos) {
        int error_code = UPNPCOMMAND_UNKNOWN_ERROR;
        const auto [end, error] = std::from_chars(response.data() + code_begin, response.data() + code_end, error_code);
        if (error == std::errc {} && end == response.data() + code_end) {
          return error_code;
        }
      }
      return UPNPCOMMAND_UNKNOWN_ERROR;
    }

    const auto status_begin = response.find(' ');
    if (status_begin == std::string::npos) {
      return UPNPCOMMAND_HTTP_ERROR;
    }
    const auto status_line_end = response.find('\r', status_begin);
    if (status_line_end == std::string::npos) {
      return UPNPCOMMAND_HTTP_ERROR;
    }
    int status = 0;
    const auto [status_end, error] = std::from_chars(response.data() + status_begin + 1, response.data() + status_line_end, status);
    if (error != std::errc {} || status_end == response.data() + status_line_end || status < 200 || status >= 300) {
      return UPNPCOMMAND_HTTP_ERROR;
    }
    return UPNPCOMMAND_SUCCESS;
  }

  /**
   * @brief Check whether an IPv4 address is currently assigned to this host.
   *
   * @param address IPv4 address to find.
   * @return `true` when the address belongs to one of this host's adapters.
   */
  static bool is_local_ipv4_address(const std::string_view address) {
    return std::ranges::any_of(net::get_network_adapters(), [address](const net::network_adapter_t &adapter) {
      return std::ranges::any_of(adapter.ipv4_addresses, [address](const std::string &ipv4) {
        return ipv4 == address;
      });
    });
  }
#endif

  /**
   * @brief Delete a mapping, retrying from its old local client when required.
   *
   * @param data IGDdatas from UPNP_GetValidIGD().
   * @param urls urls_t from UPNP_GetValidIGD().
   * @param mapping Mapping to delete.
   * @param internal_client Internal client reported by the IGD, if available.
   * @return UPnP error code or MiniUPnPc command error.
   */
  static int delete_upnp_mapping(const IGDdatas &data, const urls_t &urls, const mapping_t &mapping, const std::string_view internal_client) {
    auto err = UPNP_DeletePortMapping(
      urls->controlURL,
      data.first.servicetype,
      mapping.port.wan.c_str(),
      mapping.port.proto.c_str(),
      nullptr
    );

#ifdef _WIN32
    if (err == 714 && is_local_ipv4_address(internal_client)) {  // NoSuchEntryInArray
      BOOST_LOG(debug) << "Retrying UPnP mapping deletion from old local client IPv4 ["sv << internal_client << ']';
      err = delete_port_mapping_from_address(urls, data, mapping, internal_client);
    }
#endif

    return err;
  }

  /**
   * @brief Remove an old Sunshine mapping that a broken IGD hides from the specific-entry query.
   *
   * @details Some IGDs return `NoSuchEntryInArray` for
   * `GetSpecificPortMappingEntry` while `GetGenericPortMappingEntry` still
   * exposes the entry. Enumerate the generic table only after an
   * `AddPortMapping` conflict, and delete an entry only when its port tuple,
   * wildcard remote host, internal port, and Sunshine description all match.
   *
   * @param data IGDdatas from UPNP_GetValidIGD().
   * @param urls urls_t from UPNP_GetValidIGD().
   * @param mapping Mapping Sunshine is trying to create.
   * @return `true` when an owned stale entry was removed.
   */
  static bool remove_stale_sunshine_mapping(const IGDdatas &data, const urls_t &urls, const mapping_t &mapping) {
    // Generic mapping indexes are normally small, but keep a hard limit in
    // case an IGD reports an invalid or maliciously large table.
    constexpr unsigned int MAX_MAPPING_ENTRIES = 65536;

    for (unsigned int index = 0; index < MAX_MAPPING_ENTRIES; ++index) {
      auto index_string = std::to_string(index);
      std::array<char, 6> external_port {};
      std::array<char, 16> internal_client {};
      std::array<char, 6> internal_port {};
      std::array<char, 4> protocol {};
      std::array<char, 80> description {};
      std::array<char, 4> enabled {};
      std::array<char, 64> remote_host {};
      std::array<char, 16> lease_duration {};

      const auto err = UPNP_GetGenericPortMappingEntry(
        urls->controlURL,
        data.first.servicetype,
        index_string.c_str(),
        external_port.data(),
        internal_client.data(),
        internal_port.data(),
        protocol.data(),
        description.data(),
        enabled.data(),
        remote_host.data(),
        lease_duration.data()
      );

      if (err == 713) {  // SpecifiedArrayIndexInvalid
        return false;
      }
      if (err) {
        BOOST_LOG(debug) << "Unable to enumerate UPnP port mappings after conflict: "sv << err;
        return false;
      }

      if (std::strcmp(external_port.data(), mapping.port.wan.c_str()) || std::strcmp(protocol.data(), mapping.port.proto.c_str()) || remote_host[0] != '\0') {
        continue;
      }

      if (!is_sunshine_mapping(mapping, internal_port.data(), description.data())) {
        BOOST_LOG(debug) << "UPnP conflict was not identified as a Sunshine mapping for "sv
                         << mapping.port.proto << ' ' << mapping.port.wan;
        return false;
      }

      const auto delete_err = delete_upnp_mapping(data, urls, mapping, internal_client.data());
      if (delete_err) {
        BOOST_LOG(debug) << "Unable to remove stale Sunshine UPnP mapping for "sv
                         << mapping.port.proto << ' ' << mapping.port.wan << ": "sv << delete_err;
        return false;
      }

      BOOST_LOG(debug) << "Removed stale Sunshine UPnP mapping for "sv
                       << mapping.port.proto << ' ' << mapping.port.wan << " to "sv << internal_client.data();
      return true;
    }

    BOOST_LOG(debug) << "UPnP mapping table exceeded the enumeration limit after conflict"sv;
    return false;
  }

  /**
   * This function is a wrapper around UPNP_GetValidIGD() that returns the status code. There is a pre-processor
   * check to determine which version of the function to call based on the version of the MiniUPnPc library.
   */
  int UPNP_GetValidIGDStatus(device_t &device, urls_t *urls, IGDdatas *data, std::array<char, INET6_ADDRESS_STRLEN> &lan_addr) {
#if (MINIUPNPC_API_VERSION >= 18)
    return UPNP_GetValidIGD(device.get(), &urls->el, data, lan_addr.data(), (int) lan_addr.size(), nullptr, 0);
#else
    return UPNP_GetValidIGD(device.get(), &urls->el, data, lan_addr.data(), (int) lan_addr.size());
#endif
  }

  /**
   * @brief Discover a valid IPv4 IGD through one multicast interface.
   *
   * @param multicast_interface IPv4 address passed to MiniUPnPc, or `nullptr` for its legacy automatic selection.
   * @param adapter_name Adapter label used in diagnostic messages.
   * @param adapter_address Current adapter IPv4 address, when one was selected.
   * @param urls Destination UPnP URLs populated on success.
   * @param data Destination IGD data populated on success.
   * @param lan_addr Destination local address populated on success.
   * @return `true` when a connected or recognized valid IGD was found.
   */
  static bool discover_ipv4_igd(const char *multicast_interface, const std::string_view adapter_name, const std::string_view adapter_address, urls_t &urls, IGDdatas &data, std::array<char, INET6_ADDRESS_STRLEN> &lan_addr) {
    const auto address = adapter_address.empty() ? "automatic"sv : adapter_address;
    int err = 0;
    device_t device {upnpDiscover(2000, multicast_interface, nullptr, 0, IPv4, 2, &err)};
    if (!device || err) {
      BOOST_LOG(debug) << "No IPv4 UPnP device discovered via adapter name ["sv << adapter_name
                       << "], IPv4 ["sv << address << "], error ["sv << err << ']';
      return false;
    }

    for (auto dev = device.get(); dev != nullptr; dev = dev->pNext) {
      BOOST_LOG(debug) << "Found UPnP device via adapter name ["sv << adapter_name
                       << "], IPv4 ["sv << address << "], rootDesc ["sv << dev->descURL << ']';
    }

    urls_t candidate_urls;
    IGDdatas candidate_data {};
    std::array<char, INET6_ADDRESS_STRLEN> candidate_lan_addr {};
    const auto status = upnp::UPNP_GetValidIGDStatus(device, &candidate_urls, &candidate_data, candidate_lan_addr);
    if (status != 1 && status != 2) {
      BOOST_LOG(debug) << "No valid IPv4 IGD via adapter name ["sv << adapter_name
                       << "], IPv4 ["sv << address << "]: "sv << status_string(status);
      return false;
    }

    BOOST_LOG(debug) << "Valid IPv4 IGD via adapter name ["sv << adapter_name
                     << "], IPv4 ["sv << address
                     << "], rootDesc ["sv << candidate_urls->rootdescURL
                     << "], controlURL ["sv << candidate_urls->controlURL << ']';

    urls = std::move(candidate_urls);
    data = candidate_data;
    lan_addr = candidate_lan_addr;
    return true;
  }

  /**
   * @brief RAII helper that runs shutdown cleanup when destroyed.
   */
  class deinit_t: public platf::deinit_t {
  public:
    deinit_t() {
      auto rtsp = std::to_string(net::map_port(rtsp_stream::RTSP_SETUP_PORT));
      auto video = std::to_string(net::map_port(stream::VIDEO_STREAM_PORT));
      auto audio = std::to_string(net::map_port(stream::AUDIO_STREAM_PORT));
      auto control = std::to_string(net::map_port(stream::CONTROL_PORT));
      auto gs_http = std::to_string(net::map_port(nvhttp::PORT_HTTP));
      auto gs_https = std::to_string(net::map_port(nvhttp::PORT_HTTPS));
      auto wm_http = std::to_string(net::map_port(confighttp::PORT_HTTPS));

      mappings.assign({
        {{rtsp, rtsp, "TCP"s}, "Sunshine - RTSP"s},
        {{video, video, "UDP"s}, "Sunshine - Video"s},
        {{audio, audio, "UDP"s}, "Sunshine - Audio"s},
        {{control, control, "UDP"s}, "Sunshine - Control"s},
        {{gs_http, gs_http, "TCP"s}, "Sunshine - Client HTTP"s},
        {{gs_https, gs_https, "TCP"s}, "Sunshine - Client HTTPS"s},
      });

      // Only map port for the Web Manager if it is configured to accept connection from WAN
      if (net::from_enum_string(config::nvhttp.origin_web_ui_allowed) > net::LAN) {
        mappings.emplace_back(mapping_t {{wm_http, wm_http, "TCP"s}, "Sunshine - Web UI"s});
      }

      // Start the mapping thread
      upnp_thread = std::jthread {&deinit_t::upnp_thread_proc, this};
    }

    /**
     * @brief Destroy the UPnP deinitializer.
     */
    ~deinit_t() {
      upnp_thread.join();
    }

    /**
     * @brief Opens pinholes for IPv6 traffic if the IGD is capable.
     * @details Not many IGDs support this feature, so we perform error logging with debug level.
     * @return `true` if the pinholes were opened successfully.
     */
    bool create_ipv6_pinholes() {
      int err;
      device_t device {upnpDiscover(2000, nullptr, nullptr, 0, IPv6, 2, &err)};
      if (!device || err) {
        BOOST_LOG(debug) << "Couldn't discover any IPv6 UPNP devices"sv;
        return false;
      }

      IGDdatas data;
      urls_t urls;
      std::array<char, INET6_ADDRESS_STRLEN> lan_addr;
      auto status = upnp::UPNP_GetValidIGDStatus(device, &urls, &data, lan_addr);
      if (status != 1 && status != 2) {
        BOOST_LOG(debug) << "No valid IPv6 IGD: "sv << status_string(status);
        return false;
      }

      if (data.IPv6FC.controlurl[0] != 0) {
        int firewallEnabled;
        int pinholeAllowed;

        // Check if this firewall supports IPv6 pinholes
        err = UPNP_GetFirewallStatus(urls->controlURL_6FC, data.IPv6FC.servicetype, &firewallEnabled, &pinholeAllowed);
        if (err == UPNPCOMMAND_SUCCESS) {
          BOOST_LOG(debug) << "UPnP IPv6 firewall control available. Firewall is "sv
                           << (firewallEnabled ? "enabled"sv : "disabled"sv)
                           << ", pinhole is "sv
                           << (pinholeAllowed ? "allowed"sv : "disallowed"sv);

          if (pinholeAllowed) {
            // Create pinholes for each port
            auto mapping_period = std::to_string(PORT_MAPPING_LIFETIME.count());
            auto shutdown_event = mail::man->event<bool>(mail::shutdown);

            for (auto it = std::begin(mappings); it != std::end(mappings) && !shutdown_event->peek(); ++it) {
              auto mapping = *it;
              char uniqueId[8];

              // Open a pinhole for the LAN port, since there will be no WAN->LAN port mapping on IPv6
              err = UPNP_AddPinhole(urls->controlURL_6FC, data.IPv6FC.servicetype, "", "0", lan_addr.data(), mapping.port.lan.c_str(), mapping.port.proto.c_str(), mapping_period.c_str(), uniqueId);
              if (err == UPNPCOMMAND_SUCCESS) {
                BOOST_LOG(debug) << "Successfully created pinhole for "sv << mapping.port.proto << ' ' << mapping.port.lan;
              } else {
                BOOST_LOG(debug) << "Failed to create pinhole for "sv << mapping.port.proto << ' ' << mapping.port.lan << ": "sv << err;
              }
            }

            return err == 0;
          } else {
            BOOST_LOG(debug) << "IPv6 pinholes are not allowed by the IGD"sv;
            return false;
          }
        } else {
          BOOST_LOG(debug) << "Failed to get IPv6 firewall status: "sv << err;
          return false;
        }
      } else {
        BOOST_LOG(debug) << "IPv6 Firewall Control is not supported by the IGD"sv;
        return false;
      }
    }

    /**
     * @brief Maps a port via UPnP.
     * @param data IGDdatas from UPNP_GetValidIGD()
     * @param urls urls_t from UPNP_GetValidIGD()
     * @param lan_addr Local IP address to map to
     * @param mapping Information about port to map
     * @return `true` on success.
     */
    bool map_upnp_port(const IGDdatas &data, const urls_t &urls, const std::string &lan_addr, const mapping_t &mapping) {
      char intClient[16];
      char intPort[6];
      char desc[80];
      char enabled[4];
      char leaseDuration[16];
      bool indefinite = false;

      // First check if this port is already mapped successfully
      BOOST_LOG(debug) << "Checking for existing UPnP port mapping for "sv << mapping.port.wan;
      auto err = UPNP_GetSpecificPortMappingEntry(
        urls->controlURL,
        data.first.servicetype,
        // In params
        mapping.port.wan.c_str(),
        mapping.port.proto.c_str(),
        nullptr,
        // Out params
        intClient,
        intPort,
        desc,
        enabled,
        leaseDuration
      );
      if (err == 714) {  // NoSuchEntryInArray
        BOOST_LOG(debug) << "Mapping entry not found for "sv << mapping.port.wan;
      } else if (err == UPNPCOMMAND_SUCCESS) {
        // Some routers change the description, so we can't check that here
        if (!std::strcmp(intClient, lan_addr.c_str())) {
          if (std::atoi(leaseDuration) == 0) {
            BOOST_LOG(debug) << "Static mapping entry found for "sv << mapping.port.wan;

            // It's a static mapping, so we're done here
            return true;
          } else {
            BOOST_LOG(debug) << "Mapping entry found for "sv << mapping.port.wan << " ("sv << leaseDuration << " seconds remaining)"sv;
          }
        } else {
          if (!is_sunshine_mapping(mapping, intPort, desc)) {
            BOOST_LOG(warning) << "UPnP conflict detected with: "sv << intClient;
            return false;
          }

          BOOST_LOG(debug) << "Replacing stale Sunshine UPnP mapping for "sv
                           << mapping.port.proto << ' ' << mapping.port.wan << " to "sv << intClient;

          // Some UPnP IGDs won't let unauthenticated clients delete other conflicting port mappings
          // for security reasons, but we will give it a try anyway.
          err = delete_upnp_mapping(data, urls, mapping, intClient);
          if (err) {
            BOOST_LOG(error) << "Unable to delete conflicting UPnP port mapping: "sv << err;
            return false;
          }
        }
      } else {
        BOOST_LOG(error) << "UPNP_GetSpecificPortMappingEntry() failed: "sv << err;

        // If we get a strange error from the router, we'll assume it's some old broken IGDv1
        // device and only use indefinite lease durations to hopefully avoid confusing it.
        if (err != 606) {  // Unauthorized
          indefinite = true;
        }
      }

      // Add/update the port mapping
      auto mapping_period = std::to_string(indefinite ? 0 : PORT_MAPPING_LIFETIME.count());
      err = UPNP_AddPortMapping(
        urls->controlURL,
        data.first.servicetype,
        mapping.port.wan.c_str(),
        mapping.port.lan.c_str(),
        lan_addr.data(),
        mapping.description.c_str(),
        mapping.port.proto.c_str(),
        nullptr,
        mapping_period.c_str()
      );

      if (err == 718 && remove_stale_sunshine_mapping(data, urls, mapping)) {  // ConflictInMappingEntry
        BOOST_LOG(debug) << "Retrying UPnP mapping after stale-entry cleanup for "sv
                         << mapping.port.proto << ' ' << mapping.port.wan;
        err = UPNP_AddPortMapping(
          urls->controlURL,
          data.first.servicetype,
          mapping.port.wan.c_str(),
          mapping.port.lan.c_str(),
          lan_addr.data(),
          mapping.description.c_str(),
          mapping.port.proto.c_str(),
          nullptr,
          mapping_period.c_str()
        );
      }

      if (err != UPNPCOMMAND_SUCCESS && !indefinite) {
        // This may be an old/broken IGD that doesn't like non-static mappings.
        BOOST_LOG(debug) << "Trying static mapping after failure: "sv << err;
        err = UPNP_AddPortMapping(
          urls->controlURL,
          data.first.servicetype,
          mapping.port.wan.c_str(),
          mapping.port.lan.c_str(),
          lan_addr.data(),
          mapping.description.c_str(),
          mapping.port.proto.c_str(),
          nullptr,
          "0"
        );
      }

      if (err) {
        BOOST_LOG(error) << "Failed to map "sv << mapping.port.proto << ' ' << mapping.port.lan << ": "sv << err;
        return false;
      }

      BOOST_LOG(debug) << "Successfully mapped "sv << mapping.port.proto << ' ' << mapping.port.lan;
      return true;
    }

    /**
     * @brief Unmaps all ports.
     * @param urls urls_t from UPNP_GetValidIGD()
     * @param data IGDdatas from UPNP_GetValidIGD()
     */
    void unmap_all_upnp_ports(const urls_t &urls, const IGDdatas &data) {
      for (auto it = std::begin(mappings); it != std::end(mappings); ++it) {
        auto status = UPNP_DeletePortMapping(
          urls->controlURL,
          data.first.servicetype,
          it->port.wan.c_str(),
          it->port.proto.c_str(),
          nullptr
        );

        if (status && status != 714) {  // NoSuchEntryInArray
          BOOST_LOG(warning) << "Failed to unmap "sv << it->port.proto << ' ' << it->port.lan << ": "sv << status;
        } else if (status == 714) {
          BOOST_LOG(debug) << "UPnP mapping was already absent for "sv << it->port.proto << ' ' << it->port.lan;
        } else {
          BOOST_LOG(debug) << "Successfully unmapped "sv << it->port.proto << ' ' << it->port.lan;
        }
      }
    }

    /**
     * @brief Maintains UPnP port forwarding rules
     */
    void upnp_thread_proc() {
      platf::set_thread_name("upnp");
      auto shutdown_event = mail::man->event<bool>(mail::shutdown);
      bool mapped = false;
      IGDdatas data;
      IGDdatas mapped_data;
      urls_t mapped_urls;
      auto address_family = net::af_from_enum_string(config::sunshine.address_family);
      const bool adapter_filter_enabled =
        !config::sunshine.upnp_adapters.empty() ||
        !config::sunshine.upnp_adapter_blacklist.empty();

      // Refresh UPnP rules every few minutes. They can be lost if the router reboots,
      // WAN IP address changes, or various other conditions.
      do {
        urls_t urls;
        std::array<char, INET6_ADDRESS_STRLEN> lan_addr {};
        bool discovered = false;
        std::string selected_adapter;
        std::string selected_adapter_address;

        if (!adapter_filter_enabled) {
          // Preserve upstream MiniUPnPc automatic interface selection exactly when no filter is configured.
          discovered = discover_ipv4_igd(nullptr, "automatic"sv, {}, urls, data, lan_addr);
        } else {
          const auto targets = get_ipv4_discovery_targets();
          for (const auto &target : targets) {
            BOOST_LOG(debug) << "Trying IPv4 UPnP discovery on adapter name ["sv << target.adapter_name
                             << "], IPv4 ["sv << target.address
                             << "], native ID ["sv << target.adapter_id << ']';

            if (discover_ipv4_igd(target.address.c_str(), target.adapter_name, target.address, urls, data, lan_addr)) {
              selected_adapter = target.adapter_name;
              selected_adapter_address = target.address;
              discovered = true;
              break;
            }
          }
        }

        if (!discovered) {
          BOOST_LOG(warning) << "Couldn't discover any IPv4 UPNP devices"sv;
          continue;
        }

        std::string lan_addr_str {lan_addr.data()};

        BOOST_LOG(debug) << "Using valid IPv4 IGD: rootDesc ["sv << urls->rootdescURL
                         << "], controlURL ["sv << urls->controlURL << ']';

        if (!selected_adapter.empty()) {
          BOOST_LOG(debug) << "Selected UPnP adapter: name ["sv << selected_adapter
                           << "], IPv4 ["sv << selected_adapter_address << ']';
        }

        bool all_mapped = true;
        for (auto it = std::begin(mappings); it != std::end(mappings) && !shutdown_event->peek(); ++it) {
          if (!map_upnp_port(data, urls, lan_addr_str, *it)) {
            all_mapped = false;
          }
        }

        if (!all_mapped) {
          BOOST_LOG(warning) << "Unable to establish all UPnP port mappings to "sv << lan_addr_str;
          continue;
        }

        if (!mapped) {
          BOOST_LOG(info) << "Completed UPnP port mappings to "sv << lan_addr_str
                          << " via rootDesc ["sv << urls->rootdescURL
                          << "], controlURL ["sv << urls->controlURL << ']';
        }

        // If we are listening on IPv6 and the IGD has an IPv6 firewall enabled, try to create IPv6 firewall pinholes
        if (address_family == net::af_e::BOTH) {
          if (create_ipv6_pinholes() && !mapped) {
            // Only log the first time through
            BOOST_LOG(info) << "Successfully opened IPv6 pinholes on the IGD"sv;
          }
        }

        mapped = true;
        mapped_urls = std::move(urls);
        mapped_data = data;
      } while (!shutdown_event->view(REFRESH_INTERVAL));

      if (mapped) {
        // Unmap ports upon termination
        BOOST_LOG(info) << "Unmapping UPNP ports..."sv;
        unmap_all_upnp_ports(mapped_urls, mapped_data);
      }
    }

    std::vector<mapping_t> mappings;  ///< Port mappings Sunshine should keep registered with the gateway.
    std::jthread upnp_thread;  ///< Worker thread that refreshes mappings until shutdown.
  };

  /**
   * @brief Start UPnP port mapping and return its shutdown guard.
   */
  std::unique_ptr<platf::deinit_t> start() {
    if (!config::sunshine.flags[config::flag::UPNP]) {
      return nullptr;
    }

    return std::make_unique<deinit_t>();
  }
}  // namespace upnp
