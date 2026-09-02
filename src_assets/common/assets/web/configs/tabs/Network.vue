<script setup>
import { computed, onMounted, ref } from 'vue'
import {
  Info,
  TriangleAlert,
} from '@lucide/vue'
import Checkbox from "../../Checkbox.vue";

const props = defineProps([
  'platform',
  'config'
])

const defaultMoonlightPort = 47989

const config = ref(props.config)
const effectivePort = computed(() => +config.value?.port ?? defaultMoonlightPort)
const networkAdapters = ref([])

const parseUpnpAdapters = () => {
  const value = config.value?.upnp_adapters
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean)
  }

  return String(value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
}

const adapterAliases = (adapter) => [
  adapter.name,
  adapter.id,
  ...(Array.isArray(adapter.ipv4) ? adapter.ipv4 : []),
].filter(Boolean)

const isUpnpAdapterSelected = (adapter) => {
  const values = parseUpnpAdapters()
  return adapterAliases(adapter).some((alias) => values.includes(alias))
}

const setUpnpAdapterSelected = (adapter, selected) => {
  const aliases = new Set(adapterAliases(adapter))
  const values = parseUpnpAdapters().filter((value) => !aliases.has(value))

  if (selected) {
    const value = adapter.name || adapter.id || adapter.ipv4?.[0]
    if (value) {
      values.push(value)
    }
  }

  config.value.upnp_adapters = [...new Set(values)].join(',')
}

onMounted(async () => {
  try {
    const response = await fetch('./api/network-adapters')
    if (!response.ok) {
      return
    }

    const body = await response.json()
    networkAdapters.value = Array.isArray(body.adapters) ? body.adapters : []
  } catch {
    networkAdapters.value = []
  }
})
</script>

<template>
  <div id="network" class="config-page">
    <!-- UPnP -->
    <Checkbox class="mb-3"
              id="upnp"
              locale-prefix="config"
              v-model="config.upnp"
              default="false"
    ></Checkbox>

    <!-- UPnP adapter filter -->
    <div class="mb-3">
      <label for="upnp_adapters" class="form-label">{{ $t('config.upnp_adapters') }}</label>

      <div class="border rounded p-2 mb-2" v-if="networkAdapters.length">
        <div class="form-check mb-2"
             v-for="(adapter, index) in networkAdapters"
             :key="adapter.id || adapter.name || index">
          <input class="form-check-input"
                 type="checkbox"
                 :id="`upnp_adapter_${index}`"
                 :checked="isUpnpAdapterSelected(adapter)"
                 @change="setUpnpAdapterSelected(adapter, $event.target.checked)" />
          <label class="form-check-label" :for="`upnp_adapter_${index}`">
            <span :class="{ 'text-muted': !adapter.eligible }">
              {{ adapter.name || adapter.id }}
              <span class="ms-1" v-if="adapter.ipv4?.length">({{ adapter.ipv4.join(', ') }})</span>
              <span class="ms-1" v-if="!adapter.eligible">— {{ $t('config.upnp_adapters_ineligible') }}</span>
            </span>
          </label>
          <div class="form-text mt-0" v-if="adapter.id && adapter.id !== adapter.name">
            {{ $t('config.upnp_adapter_native_id') }}: <code>{{ adapter.id }}</code>
          </div>
          <div class="form-text mt-0"
               v-if="adapter.description && adapter.description !== adapter.name">
            {{ adapter.description }}
          </div>
        </div>
      </div>
      <div class="form-text mb-2" v-else>{{ $t('config.upnp_adapters_none') }}</div>

      <input type="text"
             class="form-control"
             id="upnp_adapters"
             v-model="config.upnp_adapters"
             placeholder="Wi-Fi,Ethernet,IPv4-address" />
      <div class="form-text">{{ $t('config.upnp_adapters_desc') }}</div>
    </div>

    <div class="mb-3">
      <label for="upnp_adapter_blacklist" class="form-label">{{ $t('config.upnp_adapter_blacklist') }}</label>
      <input type="text"
             class="form-control"
             id="upnp_adapter_blacklist"
             v-model="config.upnp_adapter_blacklist"
             placeholder="Mihomo|Clash|TUN|TAP" />
      <div class="form-text">{{ $t('config.upnp_adapter_blacklist_desc') }}</div>
    </div>

    <!-- Address family -->
    <div class="mb-3">
      <label for="address_family" class="form-label">{{ $t('config.address_family') }}</label>
      <select id="address_family" class="form-select" v-model="config.address_family">
        <option value="ipv4">{{ $t('config.address_family_ipv4') }}</option>
        <option value="both">{{ $t('config.address_family_both') }}</option>
      </select>
      <div class="form-text">{{ $t('config.address_family_desc') }}</div>
    </div>

    <!-- Bind address -->
    <div class="mb-3">
      <label for="bind_address" class="form-label">{{ $t('config.bind_address') }}</label>
      <input type="text" class="form-control" id="bind_address" v-model="config.bind_address" />
      <div class="form-text">{{ $t('config.bind_address_desc') }}</div>
    </div>

    <!-- Port family -->
    <div class="mb-3">
      <label for="port" class="form-label">{{ $t('config.port') }}</label>
      <input type="number" min="1029" max="65514" class="form-control" id="port" :placeholder="defaultMoonlightPort"
             v-model="config.port" />
      <div class="form-text">{{ $t('config.port_desc') }}</div>
      <!-- Add warning if any port is less than 1024 -->
      <div class="alert alert-danger" v-if="(+effectivePort - 5) < 1024">
        <TriangleAlert :size="20" /> {{ $t('config.port_alert_1') }}
      </div>
      <!-- Add warning if any port is above 65535 -->
      <div class="alert alert-danger" v-if="(+effectivePort + 21) > 65535">
        <TriangleAlert :size="20" /> {{ $t('config.port_alert_2') }}
      </div>
      <!-- Create a port table for the various ports needed by Sunshine -->
      <table class="table">
        <thead>
        <tr>
          <th scope="col">{{ $t('config.port_protocol') }}</th>
          <th scope="col">{{ $t('config.port_port') }}</th>
          <th scope="col">{{ $t('config.port_note') }}</th>
        </tr>
        </thead>
        <tbody>
        <tr>
          <!-- HTTPS -->
          <td>{{ $t('config.port_tcp') }}</td>
          <td>{{+effectivePort - 5}}</td>
          <td></td>
        </tr>
        <tr>
          <!-- HTTP -->
          <td>{{ $t('config.port_tcp') }}</td>
          <td>{{+effectivePort}}</td>
          <td>
            <div class="alert alert-primary" role="alert" v-if="+effectivePort !== defaultMoonlightPort">
              <Info :size="20" /> {{ $t('config.port_http_port_note') }}
            </div>
          </td>
        </tr>
        <tr>
          <!-- Web UI -->
          <td>{{ $t('config.port_tcp') }}</td>
          <td>{{+effectivePort + 1}}</td>
          <td>{{ $t('config.port_web_ui') }}</td>
        </tr>
        <tr>
          <!-- RTSP -->
          <td>{{ $t('config.port_tcp') }}</td>
          <td>{{+effectivePort + 21}}</td>
          <td></td>
        </tr>
        <tr>
          <!-- Video, Control, Audio -->
          <td>{{ $t('config.port_udp') }}</td>
          <td>{{+effectivePort + 9}} - {{+effectivePort + 11}}</td>
          <td></td>
        </tr>
        <!--            <tr>-->
        <!--              &lt;!&ndash; Mic &ndash;&gt;-->
        <!--              <td>UDP</td>-->
        <!--              <td>{{+effectivePort + 13}}</td>-->
        <!--              <td></td>-->
        <!--            </tr>-->
        </tbody>
      </table>
      <!-- add warning about exposing web ui to the internet -->
      <div class="alert alert-warning" v-if="config.origin_web_ui_allowed === 'wan'">
        <TriangleAlert :size="20" /> {{ $t('config.port_warning') }}
      </div>
    </div>

    <!-- Origin Web UI Allowed -->
    <div class="mb-3">
      <label for="origin_web_ui_allowed" class="form-label">{{ $t('config.origin_web_ui_allowed') }}</label>
      <select id="origin_web_ui_allowed" class="form-select" v-model="config.origin_web_ui_allowed">
        <option value="pc">{{ $t('config.origin_web_ui_allowed_pc') }}</option>
        <option value="lan">{{ $t('config.origin_web_ui_allowed_lan') }}</option>
        <option value="wan">{{ $t('config.origin_web_ui_allowed_wan') }}</option>
      </select>
      <div class="form-text">{{ $t('config.origin_web_ui_allowed_desc') }}</div>
    </div>

    <!-- CSRF Allowed Origins -->
    <div class="mb-3">
      <label for="csrf_allowed_origins" class="form-label">{{ $t('config.csrf_allowed_origins') }}</label>
      <input type="text"
             class="form-control"
             id="csrf_allowed_origins"
             v-model="config.csrf_allowed_origins" />
      <div class="form-text">{{ $t('config.csrf_allowed_origins_desc') }}</div>
    </div>

    <!-- External IP -->
    <div class="mb-3">
      <label for="external_ip" class="form-label">{{ $t('config.external_ip') }}</label>
      <input type="text" class="form-control" id="external_ip" placeholder="123.456.789.12" v-model="config.external_ip" />
      <div class="form-text">{{ $t('config.external_ip_desc') }}</div>
    </div>

    <!-- LAN Encryption Mode -->
    <div class="mb-3">
      <label for="lan_encryption_mode" class="form-label">{{ $t('config.lan_encryption_mode') }}</label>
      <select id="lan_encryption_mode" class="form-select" v-model="config.lan_encryption_mode">
        <option value="0">{{ $t('_common.disabled_def') }}</option>
        <option value="1">{{ $t('config.lan_encryption_mode_1') }}</option>
        <option value="2">{{ $t('config.lan_encryption_mode_2') }}</option>
      </select>
      <div class="form-text">{{ $t('config.lan_encryption_mode_desc') }}</div>
    </div>

    <!-- WAN Encryption Mode -->
    <div class="mb-3">
      <label for="wan_encryption_mode" class="form-label">{{ $t('config.wan_encryption_mode') }}</label>
      <select id="wan_encryption_mode" class="form-select" v-model="config.wan_encryption_mode">
        <option value="0">{{ $t('_common.disabled') }}</option>
        <option value="1">{{ $t('config.wan_encryption_mode_1') }}</option>
        <option value="2">{{ $t('config.wan_encryption_mode_2') }}</option>
      </select>
      <div class="form-text">{{ $t('config.wan_encryption_mode_desc') }}</div>
    </div>

    <!-- Ping Timeout -->
    <div class="mb-3">
      <label for="ping_timeout" class="form-label">{{ $t('config.ping_timeout') }}</label>
      <input type="text" class="form-control" id="ping_timeout" placeholder="10000" v-model="config.ping_timeout" />
      <div class="form-text">{{ $t('config.ping_timeout_desc') }}</div>
    </div>

    <!-- Packet Size Limit -->
    <div class="mb-3">
      <label for="packetsize" class="form-label">{{ $t('config.packetsize') }}</label>
      <input type="number" min="0" max="65535" class="form-control" id="packetsize" placeholder="0" v-model="config.packetsize" />
      <div class="form-text">{{ $t('config.packetsize_desc') }}</div>
    </div>

  </div>
</template>

<style scoped>

</style>
