/**
 * @file tests/unit/test_network.cpp
 * @brief Test src/network.*
 */
#include "../tests_common.h"

#include <src/config.h>
#include <src/network.h>

TEST(NetworkAdapterEligibilityTest, RequiresUsableMulticastIpv4Adapter) {
  net::network_adapter_t adapter;
  adapter.ipv4_addresses = {"192.0.2.10"};
  adapter.is_up = true;
  adapter.supports_multicast = true;

  EXPECT_TRUE(net::is_network_adapter_eligible(adapter));

  adapter.is_up = false;
  EXPECT_FALSE(net::is_network_adapter_eligible(adapter));
  adapter.is_up = true;

  adapter.is_loopback = true;
  EXPECT_FALSE(net::is_network_adapter_eligible(adapter));
  adapter.is_loopback = false;

  adapter.supports_multicast = false;
  EXPECT_FALSE(net::is_network_adapter_eligible(adapter));
  adapter.supports_multicast = true;

  adapter.ipv4_addresses.clear();
  EXPECT_FALSE(net::is_network_adapter_eligible(adapter));
}

struct NetworkAdapterEnumerationTest: BaseTest {};

TEST_F(NetworkAdapterEnumerationTest, ReportsValidIpv4Text) {
  const auto adapters = net::get_network_adapters();

  for (const auto &adapter : adapters) {
    for (const auto &address : adapter.ipv4_addresses) {
      EXPECT_NO_THROW(boost::asio::ip::make_address_v4(address));
    }
  }
}

/**
 * @brief Verifies UPnP adapter settings are parsed without leaking global test state.
 */
struct UpnpAdapterConfigTest: BaseTest {
  void SetUp() override {
    BaseTest::SetUp();
    // The Windows test target uses a writable asset directory, but does not copy apps.json into it.
    // Point the unrelated applications file at a source file before applying these settings.
    config::stream.file_apps = SUNSHINE_SOURCE_DIR "/tests/unit/test_network.cpp";
  }

  void TearDown() override {
    config::video = original_video;
    config::audio = original_audio;
    config::stream = original_stream;
    config::nvhttp = original_nvhttp;
    config::input = original_input;
    config::sunshine = original_sunshine;
    config::modified_config_settings = original_modified_config_settings;
    BaseTest::TearDown();
  }

  config::video_t original_video {config::video};  ///< Video configuration restored after each test.
  config::audio_t original_audio {config::audio};  ///< Audio configuration restored after each test.
  config::stream_t original_stream {config::stream};  ///< Stream configuration restored after each test.
  config::nvhttp_t original_nvhttp {config::nvhttp};  ///< HTTP configuration restored after each test.
  config::input_t original_input {config::input};  ///< Input configuration restored after each test.
  config::sunshine_t original_sunshine {config::sunshine};  ///< Core configuration restored after each test.
  decltype(config::modified_config_settings) original_modified_config_settings {config::modified_config_settings};  ///< Modified settings restored after each test.
};

TEST_F(UpnpAdapterConfigTest, ParsesCommaSeparatedSelectorsAndBlacklist) {
  config::apply_config_for_test("upnp_adapters = Ethernet, native-id, 192.0.2.10\nupnp_adapter_blacklist = mihomo|tun\n");

  EXPECT_EQ((std::vector<std::string> {"Ethernet", "native-id", "192.0.2.10"}), config::sunshine.upnp_adapters);
  EXPECT_EQ("mihomo|tun", config::sunshine.upnp_adapter_blacklist);
}

TEST_F(UpnpAdapterConfigTest, ExplicitEmptyBlacklistDisablesLocalDefault) {
  config::sunshine.upnp_adapter_blacklist = "host-default";
  config::apply_config_for_test("upnp_adapter_blacklist =\n");

  EXPECT_TRUE(config::sunshine.upnp_adapter_blacklist.empty());
}

struct MdnsInstanceNameTest: BaseTest, testing::WithParamInterface<std::tuple<std::string, std::string>> {};

TEST_P(MdnsInstanceNameTest, Run) {
  auto [input, expected] = GetParam();
  ASSERT_EQ(net::mdns_instance_name(input), expected);
}

INSTANTIATE_TEST_SUITE_P(
  MdnsInstanceNameTests,
  MdnsInstanceNameTest,
  testing::Values(
    std::make_tuple("shortname-123", "shortname-123"),
    std::make_tuple("space 123", "space-123"),
    std::make_tuple("hostname.domain.test", "hostname"),
    std::make_tuple("&", "Sunshine"),
    std::make_tuple("", "Sunshine"),
    std::make_tuple("😁", "Sunshine"),
    std::make_tuple(std::string(128, 'a'), std::string(63, 'a'))
  )
);

/**
 * @brief Test fixture for bind_address tests with setup/teardown
 */
class BindAddressTest: public BaseTest {
protected:
  std::string original_bind_address;

  void SetUp() override {
    BaseTest::SetUp();
    // Save the original bind_address config
    original_bind_address = config::sunshine.bind_address;
  }

  void TearDown() override {
    // Restore the original bind_address config
    config::sunshine.bind_address = original_bind_address;
    BaseTest::TearDown();
  }
};

/**
 * @brief Test that get_bind_address returns wildcard when bind_address is not configured
 */
TEST_F(BindAddressTest, DefaultBehaviorIPv4) {
  // Clear bind_address to test the default behavior
  config::sunshine.bind_address = "";

  const auto bind_addr = net::get_bind_address(net::af_e::IPV4);
  ASSERT_EQ(bind_addr, "0.0.0.0");
}

/**
 * @brief Test that get_bind_address returns wildcard when bind_address is not configured (IPv6)
 */
TEST_F(BindAddressTest, DefaultBehaviorIPv6) {
  // Clear bind_address to test the default behavior
  config::sunshine.bind_address = "";

  const auto bind_addr = net::get_bind_address(net::af_e::BOTH);
  ASSERT_EQ(bind_addr, "::");
}

/**
 * @brief Test that get_bind_address returns configured IPv4 address
 */
TEST_F(BindAddressTest, ConfiguredIPv4Address) {
  // Set a specific IPv4 address
  config::sunshine.bind_address = "192.168.1.100";

  const auto bind_addr = net::get_bind_address(net::af_e::IPV4);
  ASSERT_EQ(bind_addr, "192.168.1.100");
}

/**
 * @brief Test that get_bind_address returns configured IPv6 address
 */
TEST_F(BindAddressTest, ConfiguredIPv6Address) {
  // Set a specific IPv6 address
  config::sunshine.bind_address = "::1";

  const auto bind_addr = net::get_bind_address(net::af_e::BOTH);
  ASSERT_EQ(bind_addr, "::1");
}

/**
 * @brief Test that get_bind_address returns configured address regardless of address family
 */
TEST_F(BindAddressTest, ConfiguredAddressOverridesFamily) {
  // Set a specific IPv6 address but request IPv4 family
  // The configured address should still be returned
  config::sunshine.bind_address = "2001:db8::1";

  const auto bind_addr = net::get_bind_address(net::af_e::IPV4);
  ASSERT_EQ(bind_addr, "2001:db8::1");
}

/**
 * @brief Test with loopback addresses
 */
TEST_F(BindAddressTest, LoopbackAddresses) {
  // Test IPv4 loopback
  config::sunshine.bind_address = "127.0.0.1";
  const auto bind_addr_v4 = net::get_bind_address(net::af_e::IPV4);
  ASSERT_EQ(bind_addr_v4, "127.0.0.1");

  // Test IPv6 loopback
  config::sunshine.bind_address = "::1";
  const auto bind_addr_v6 = net::get_bind_address(net::af_e::BOTH);
  ASSERT_EQ(bind_addr_v6, "::1");
}

/**
 * @brief Test with link-local addresses
 */
TEST_F(BindAddressTest, LinkLocalAddresses) {
  // Test IPv4 link-local
  config::sunshine.bind_address = "169.254.1.1";
  const auto bind_addr_v4 = net::get_bind_address(net::af_e::IPV4);
  ASSERT_EQ(bind_addr_v4, "169.254.1.1");

  // Test IPv6 link-local
  config::sunshine.bind_address = "fe80::1";
  const auto bind_addr_v6 = net::get_bind_address(net::af_e::BOTH);
  ASSERT_EQ(bind_addr_v6, "fe80::1");
}

/**
 * @brief Test that af_to_any_address_string still works correctly
 */
TEST_F(BindAddressTest, WildcardAddressFunction) {
  ASSERT_EQ(net::af_to_any_address_string(net::af_e::IPV4), "0.0.0.0");
  ASSERT_EQ(net::af_to_any_address_string(net::af_e::BOTH), "::");
}
