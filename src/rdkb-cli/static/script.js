/*
 
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
 
  Copyright 2023 RDK Management
 
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
 
  http://www.apache.org/licenses/LICENSE-2.0
 
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/**
 * EasyMesh R6 Pro Controller - Advanced JavaScript Application
 * Professional mesh network management interface
 * Supports Wi-Fi 7, Multi-AP R6, real-time monitoring
 */

class EasyMeshController {
  constructor() {
    this.apiBase = '/api/v1';
    this.wsConnection = null;
    this.currentTab = 'dashboard';
    this.devices = [];
    this.clients = [];
    this.topology = {};
    this.charts = {};
    this.refreshIntervals = {};
    this.policyByDeviceId = {};
    this.updatedPolicySettings = [];
    this.isConnected = false;

    // Chart.js configuration
    this.chartDefaults = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { usePointStyle: true, padding: 20 }
        }
      },
      scales: {
        x: { grid: { color: 'rgba(0,0,0,0.05)' } },
        y: { grid: { color: 'rgba(0,0,0,0.05)' }, beginAtZero: true }
      }
    };

    // Notification system
    this.notifications = [];
    this.maxNotifications = 50;

    // Performance monitoring
    this.performanceMetrics = {
      throughput: [],
      latency: [],
      utilization: [],
      clients: []
    };

    // Security monitoring
    this.securityEvents = [];
    this.threatLevel = 'low';

    // Settings cache
    this.systemConfig = {};
  }

  /**
   * Initialize the application
   */
  async init() {
    console.log('🚀 Initializing EasyMesh R6 Pro Controller');

    try {
      // Setup event handlers
      this.setupEventHandlers();

      // Initialize WebSocket connection
      this.initializeWebSocket();

      // Load initial data
      await this.loadInitialData();

      // Start refresh timers
      this.startRefreshTimers();

      // Initialize charts
      this.initializeCharts();

      // Show dashboard by default
      this.showTab('dashboard');

      console.log('✅ EasyMesh Controller initialized successfully');
    } catch (error) {
      console.error('❌ Failed to initialize controller:', error);
      this.showNotification('Failed to initialize controller', 'error');
    }
  }

  /**
   * Setup all event handlers
   */
  setupEventHandlers() {
    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const tab = e.currentTarget.dataset.tab;
        this.showTab(tab);
      });
    });

    // Global search
    const globalSearch = document.getElementById('global-search');
    if (globalSearch) {
      globalSearch.addEventListener('input', (e) => {
        this.handleGlobalSearch?.(e.target.value);
      });
    }

    // Notifications
    const notificationsBtn = document.getElementById('notifications-btn');
    if (notificationsBtn) {
      notificationsBtn.addEventListener('click', () => {
        this.toggleNotificationPanel?.();
      });
    }

    const closeNotifications = document.getElementById('close-notifications');
    if (closeNotifications) {
      closeNotifications.addEventListener('click', () => {
        this.closeNotificationPanel?.();
      });
    }

    // user-avatar
    const avatar = document.getElementById('user-avatar');
    const dialog = document.getElementById('ipPortDialog');
    const ipInput = document.getElementById('ip');
    const portInput = document.getElementById('port');
    avatar.addEventListener('click', () => {
      // Fetch existing configuration from backend
      fetch('/api/v1/controllerIPConfig', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      })
      .then(response => {
        if (!response.ok) {
          throw new Error('Failed to fetch current configuration');
        }
        return response.json();
      })
      .then(data => {
        // Populate fields with existing values
        ipInput.value = data.ip || '';
        portInput.value = data.port || '';
        dialog.style.display = 'flex';
      })
      .catch(error => {
        alert(`Error fetching configuration: ${error.message}`);
        dialog.style.display = 'flex'; // Still show dialog even if fetch fails
      });
    });

    const closeBtn = document.getElementById('closeBtn');
    closeBtn.addEventListener('click', () => {
      dialog.style.display = 'none';
    });

    const saveBtn = document.getElementById('saveBtn');
    saveBtn.addEventListener('click', () => {
      const ip = ipInput.value;
      const port = portInput.value;

      if (!ip || !port) {
        alert('Please enter both IP and Port.');
        return;
      }

      // Send data to Go backend
      fetch('/api/v1/controllerIPConfig', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ip, port })
      })
      .then(response => {
        if (!response.ok) {
          throw new Error('Failed to configure IP and Port');
        }
        return response.json();
      })
      .then(data => {
        alert(`Configuration successful: ${data.message}`);
        dialog.style.display = 'none';
      })
      .catch(error => {
        alert(`Error: ${error.message}`);
      });
    });

    // Dashboard actions
    document.getElementById('refresh-dashboard')?.addEventListener('click', () => {
      this.refreshDashboard();
    });

    document.getElementById('optimize-network')?.addEventListener('click', () => {
      this.optimizeNetwork();
    });
     
    // Performance tab refresh
    document.getElementById('refresh-performance')?.addEventListener('click', () => {
      this.loadPerformanceData();
      this.showNotification('Performance data refreshed', 'success');
    });

    // Time range selectors
    document.querySelectorAll('[data-range]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.setTimeRange(e.target.dataset.range);
      });
    });

    // Band selectors for RF analysis
    document.querySelectorAll('.band-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.setBand(e.target.dataset.band);
      });
    });

    // Settings navigation
    document.querySelectorAll('.settings-nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        this.showSettingsSection(e.target.getAttribute('href').substring(1));
      });
    });

    // Modal handlers
    window.addEventListener('click', (e) => {
      if (e.target.classList.contains('modal-overlay')) {
        this.closeAllModals();
      }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      this.handleKeyboardShortcuts(e);
    });

    // Wifi reset
    document.getElementById('reset-btn')?.addEventListener('click', () => {
      this.handleWifiResetApply();
    });

    document.addEventListener("change", (e) => {
      if (e.target && e.target.id === "device-selector") {
        const deviceId = e.target.value;
        const policy = this.policyByDeviceId[deviceId];
        populatePolicyUI(policy);
      }
    });

    document.addEventListener("click", (e) => {
      const btn = e.target.closest(".apply-section");
      if (!btn) return;

      // Section key from the Save button
      const sectionKey = btn.getAttribute("data-section");
      if (!sectionKey) return;

      // Resolve the radio name (scope group) for this section
      const scopeName = sectionMap(sectionKey);
      const scope = document.querySelector(`input[name="${scopeName}"]:checked`)?.value || "selected";

      // Collect the section's values from the form/table
      this.savePolicySettings(sectionKey, scope);

    });

    const applyPolicyBtn = document.getElementById('apply-policy-settings');
    if (applyPolicyBtn) {
      applyPolicyBtn.addEventListener('click', () => this.handlePolicySettingApply());
    }

    // Local Steering disallowed mac: + / - buttons
    (() => {
      const localBody = document.querySelector("#localMacBody");
      const localAdd  = document.getElementById("add-mac-inline");
      const localRem  = document.getElementById("remove-selected-inline");
      const localAll  = document.getElementById("select-all-local");

      // Select-all behavior
      if (localAll && localBody) {
        localAll.addEventListener("change", () => {
          localBody.querySelectorAll('input.row-select').forEach(cb => cb.checked = localAll.checked);
          this.updateSelectAllState(localBody, localAll);
        });
        localBody.addEventListener("change", (e) => {
          if (e.target && e.target.matches('input.row-select')) {
            this.updateSelectAllState(localBody, localAll);
          }
        });
      }
      // + button: Add inline row for user to type MAC
      localAdd?.addEventListener("click", () =>
        this.addDisallowedMacRow(localBody, localAll)
      );

      // - button: Remove selected rows
      localRem?.addEventListener("click", () => {
        const removed = this.removeSelectedRows(localBody, localAll);
        if (removed > 0) this.showNotification?.(`${removed} MAC${removed > 1 ? "s" : ""} removed`, "success");
      });

      // Refresh select-all state afterward.
      document.addEventListener("change", (e) => {
        if (e.target && e.target.id === "device-selector") {
          setTimeout(() => {
            this.updateSelectAllState(localBody, localAll);
          }, 0);
        }
      });
    })();

    // BTM Steering disallowed mac: + / - buttons
    (() => {
      const tbody = document.querySelector("#btmMacBody");
      const addBtn = document.getElementById("add-btm-inline");
      const remBtn = document.getElementById("remove-btm-inline");
      const selectAll = document.getElementById("select-all-btm");

      if (tbody && selectAll) {
        selectAll.addEventListener("change", () => {
          tbody.querySelectorAll('input.row-select').forEach(cb => cb.checked = selectAll.checked);
          this.updateSelectAllState(tbody, selectAll);
        });
        tbody.addEventListener("change", (e) => {
          if (e.target && e.target.matches('input.row-select')) {
            this.updateSelectAllState(tbody, selectAll);
          }
        });
      }
      addBtn?.addEventListener("click", () => this.addDisallowedMacRow(tbody, selectAll));
      remBtn?.addEventListener("click", () => {
        const removed = this.removeSelectedRows(tbody, selectAll);
        if (removed > 0) this.showNotification?.(`${removed} MAC${removed > 1 ? "s" : ""} removed`, "success");
      });
    })();

    // Window resize handler for charts
    window.addEventListener('resize', () => {
      this.resizeCharts();
    });
  }

  /**
   * Initialize WebSocket connection for real-time updates
   */
  initializeWebSocket() {
  // prevent duplicate connections
  if (this.wsConnection && (this.wsConnection.readyState === WebSocket.OPEN || this.wsConnection.readyState === WebSocket.CONNECTING)) {
    return;
  }

  const scheme = (location.protocol === 'https:') ? 'wss' : 'ws';
  const wsUrl = `${scheme}://${location.host}${this.apiBase}/ws`;
  console.log('🔌 Connecting to WebSocket:', wsUrl);

  try {
    this.wsConnection = new WebSocket(wsUrl);

    this.wsConnection.onopen = () => {
      console.log('✅ WebSocket connected');
      this.isConnected = true;
      this.updateConnectionStatus(true);
    };

    this.wsConnection.onmessage = async (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch { return; }
      await this.handleWebSocketMessage(data);
    };

    this.wsConnection.onerror = (err) => {
      console.warn('WebSocket error:', err);
      this.updateConnectionStatus(false);
    };

    this.wsConnection.onclose = () => {
      console.log('🔌 WebSocket disconnected');
      this.isConnected = false;
      this.updateConnectionStatus(false);
      // small backoff
      setTimeout(() => this.initializeWebSocket(), 2000);
    };
  } catch (e) {
    console.error('Failed to initialize WebSocket:', e);
    this.updateConnectionStatus(false);
  }
}

async handleWifiResetApply() {
  // Prevent re-entry
  if (this._wifiResetInProgress) return;
  this._wifiResetInProgress = true;

  const resetBtn = document.getElementById('reset-btn');
  const originalBtnText = resetBtn?.textContent;

  // Confirmation dialog box
  const confirmed = window.confirm(
    "Resetting the Wi-Fi configuration may require the controller to restart.\nDo you want to continue?"
  );
  if (!confirmed) {
    this._wifiResetInProgress = false;
    return;
  }

  // Prepare UI state
  try {
    // payload
    const payload = collectResetPayload();
    // Disable button and show progress state
    if (resetBtn) {
      resetBtn.disabled = true;
      resetBtn.textContent = "Applying reset...";
      resetBtn.classList.add("is-loading");
      resetBtn.setAttribute("aria-busy", "true");
    }

    // block navigation or keyboard shortcuts while in progress
    this._blockShortcutsDuringReset?.(true);

    // Send payload
    const response = await sendResetPayload(payload);

    // Success case
    if (handleResetSuccess) {
      try { await handleResetSuccess(response); } catch (noop) {}
    }

    if (typeof this.loadWifiResetConfig === 'function') {
      console.log("Reloading Wi-Fi Reset config after reset");
      await this.loadWifiResetConfig();
    }
  } catch (error) {
    // Call custom error handler if provided
    if (handleResetError) {
      try { await handleResetError(error); } catch (noop) {}
    }
  } finally {
    // Restore UI state
    if (resetBtn) {
      resetBtn.disabled = false;
      resetBtn.textContent = originalBtnText ?? "Apply Reset";
      resetBtn.classList.remove("is-loading");
      resetBtn.removeAttribute("aria-busy");
    }
    this._blockShortcutsDuringReset?.(false);
    this._wifiResetInProgress = false;
  }
}

savePolicySettings(sectionKey, scope = "selected") {
  if (!Array.isArray(this.updatedPolicySettings)) {
    console.warn("updatedPolicySettings is not initialized or not an array.");
    return;
  }
  const deviceSelect = document.querySelector("#device-selector");
  const selectedDeviceId = deviceSelect?.value || null;

  let indicesToUpdate = [];
  if (scope === "all") {
    indicesToUpdate = this.updatedPolicySettings.map((_, i) => i);
  } else {
    if (!selectedDeviceId) {
      console.warn("No device selected in #device-selector.");
      return;
    }
    const idx = this.updatedPolicySettings.findIndex(p => p.id === selectedDeviceId);
    if (idx === -1) {
      console.warn("Selected device not found in updatedPolicySettings:", selectedDeviceId);
      return;
    }
    indicesToUpdate = [idx];
  }

  // Read DOM values per section
  switch (sectionKey) {
    case "ap-metrics": {
      const intervalVal = document.querySelector("#ap-interval")?.value ?? "";
      const managedClientMarker = document.querySelector("#managed-client-marker")?.value ?? "";

      let interval = intervalVal;
      if (intervalVal !== "" && !Number.isNaN(Number(intervalVal))) {
        interval = Number(intervalVal);
      }

      // Apply to the chosen indices
      indicesToUpdate.forEach(i => {
        const policy = this.updatedPolicySettings[i];
        policy.apMetricReportingPolicy ||= {};
        policy.apMetricReportingPolicy.interval = interval;
        policy.apMetricReportingPolicy.managedClientMarker = managedClientMarker;
      });

      this.showNotification('AP metrics policy saved successfully', 'success');
      break;
    }
    case "local-disallowed": {
      const list = getMacList("#localMacBody") || [];
      indicesToUpdate.forEach(i => {
        const d = this.updatedPolicySettings[i];
        d.localSteeringDisallowed = Array.isArray(list) ? [...list] : [];
      });
      this.showNotification('Local Steering Disallowed Policy saved successfully', 'success');
      break;
    }
    case "btm-disallowed": {
      const list = getMacList("#btmMacBody") || [];
      indicesToUpdate.forEach(i => {
        const d = this.updatedPolicySettings[i];
        d.btmSteeringDisallowed = Array.isArray(list) ? [...list] : [];
      });
      this.showNotification('BTM Steering Disallowed Policy saved successfully', 'success');
      break;
    }
    case "channel-scan": {
      const val = document.querySelector("#report-independent-scans")?.value ?? "0";
      const num = Number(val);
      indicesToUpdate.forEach(i => {
        const d = this.updatedPolicySettings[i];
        d.reportIndependentChannelScans = Number.isNaN(num) ? 0 : num;
      });
      this.showNotification('Channel Scan Reporting Policy saved successfully', 'success');
      break;
    }
    case "dot1q-defaults": {
      const vlan = document.querySelector("#primary-vlan-id")?.value ?? "";
      const pcp  = document.querySelector("#default-pcp")?.value ?? "";

      const vlanNum = Number(vlan);
      const pcpNum  = Number(pcp);

      indicesToUpdate.forEach(i => {
        const d = this.updatedPolicySettings[i];
        d.default802_1Q_SettingsPolicy ||= {};

        if (!Number.isNaN(vlanNum)) d.default802_1Q_SettingsPolicy.primaryVLANID = vlanNum;
        if (!Number.isNaN(pcpNum))  d.default802_1Q_SettingsPolicy.defaultPCP   = pcpNum;
      });
      this.showNotification('Default 802.1Q Settings Policy saved successfully', 'success');
      break;
    }
    case "radio-metrics": {
      const rows = RMP.getAll();
      if (!Array.isArray(rows) || rows.length === 0) {
        this.showNotification('At least one Radio specific Matrics row with a valid ID (Station MAC") is required.', 'error');
        return;
      }
      indicesToUpdate.forEach(i => {
        const d = this.updatedPolicySettings[i];
        d.radioSpecificMetricsPolicy = rows;
      });
      this.showNotification('Radio Specific Metrics Policy saved successfully', 'success');
      break;
    }
    case "radio-steering": {
      const rows = RSP.getAll();

      if (!Array.isArray(rows) || rows.length === 0) {
        this.showNotification('At least one Radio Steering row with a valid ID (Station MAC") is required.', 'error');
        return;
      }
      indicesToUpdate.forEach(i => {
        const d = this.updatedPolicySettings[i];
        d.radioSteeringParametersPolicy = rows;
      });
      this.showNotification('Radio Steering Parameters saved successfully', 'success');
      break;
    }

    default:
      console.warn("Unknown sectionKey:", sectionKey);
  }
}


async handlePolicySettingApply() {
  const saveBtn = document.getElementById('apply-policy-settings');

  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
  }

  try {
    const settings = this.updatedPolicySettings;
    console.log('updated policy on apply: ', settings);
    const res = await fetch("api/v1/wifipolicy", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(settings)
    });

    if (res.ok) {
      this.showNotification('Wireless Policy saved successfully', 'success');
      await this.loadWifiPolicyConfig();
      this.updateAllDisplays();
    } else {
      const errorText = await res.text();
      throw new Error(errorText);
    }

  } catch (error) {
    console.error('Failed to save network Policy settings:', error);
    this.showNotification('Failed to save network Policy settings', 'error');
  } finally {
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.innerHTML = '<i class="fas fa-save"></i> Apply Policy Settings';
    }
  }
}

async addDisallowedMacRow(tbody, selectAll) {
  if (!tbody) return;

  const existing = tbody.querySelector("tr.inline-input-row");
  if (existing) {
    existing.querySelector('input[type="text"]')?.focus();
    return;
  }

  const tr = document.createElement("tr");
  tr.className = "inline-input-row";

  const td1 = document.createElement("td");
  td1.innerHTML = "&nbsp;";

  const td2 = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.className = "mac-input-wrapper";

  const input = document.createElement("input");
  input.type = "text";
  input.placeholder = "xx:xx:xx:xx:xx:xx";
  input.className = "mac-inline-input";
  input.pattern = this.MAC_REGEX.source;
  input.setAttribute("aria-label", "Enter MAC address");

  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.className = "mac-add-btn";
  addBtn.textContent = "Add";

  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "mac-cancel-btn";
  cancelBtn.textContent = "Cancel";

  const err = document.createElement("div");
  err.className = "mac-inline-error";
  err.role = "alert";
  err.style.display = "none";

  const showError = (msg) => {
    err.textContent = msg;
    err.style.display = "block";
  };
  const clearError = () => {
    err.textContent = "";
    err.style.display = "none";
  };

  const submit = () => {
    clearError();
    const mac = this.normalizeMac(input.value);

    if (!this.isValidMac(mac)) {
      showError("Invalid MAC address format");
      input.focus();
      return;
    }
    // Check for duplicate entries
    const exists = !!tbody.querySelector(`tr[data-mac="${mac}"]`);
    if (exists) {
      showError("MAC address is already present.");
      input.focus();
      return;
    }

    // Create and replace inline row with a normal data row
    const row = this.createMacRow(mac);
    tbody.replaceChild(row, tr);
    this.updateSelectAllState(tbody, selectAll);
  };

  addBtn.addEventListener("click", submit);
  cancelBtn.addEventListener("click", () => {
    tr.remove();
    this.updateSelectAllState(tbody, selectAll);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      submit();
    } else if (e.key === "Escape") {
      tr.remove();
      this.updateSelectAllState(tbody, selectAll);
    }
  });

  wrap.appendChild(input);
  wrap.appendChild(addBtn);
  wrap.appendChild(cancelBtn);
  td2.appendChild(wrap);
  td2.appendChild(err);

  tr.appendChild(td1);
  tr.appendChild(td2);
  tbody.appendChild(tr);

  setTimeout(() => input.focus(), 0);
}

updateSelectAllState(tbody, selectAll) {
  if (!tbody || !selectAll) return;
  const checks = tbody.querySelectorAll('input.row-select');
  const total = checks.length;
  const checked = [...checks].filter(cb => cb.checked).length;
  selectAll.indeterminate = checked > 0 && checked < total;
  selectAll.checked = total > 0 && checked === total;
}

createMacRow(mac) {
  const tr = document.createElement("tr");
  tr.dataset.mac = mac;

  const tdCheckbox = document.createElement("td");
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.className = "row-select";
  cb.setAttribute("aria-label", `Select ${mac}`);
  tdCheckbox.appendChild(cb);

  const tdMac = document.createElement("td");
  tdMac.textContent = mac;

  tr.appendChild(tdCheckbox);
  tr.appendChild(tdMac);
  return tr;
}

// Remove all selected rows from a table. Returns count removed.
removeSelectedRows(tbody, selectAll) {
  if (!tbody) return 0;
  let removed = 0;
  [...tbody.querySelectorAll("tr")].forEach(tr => {
    const cb = tr.querySelector('input.row-select');
    if (cb && cb.checked) {
      tr.remove();
      removed++;
    }
  });
  // Remove any inline row, if present
  tbody.querySelector("tr.inline-input-row")?.remove();
  this.updateSelectAllState(tbody, selectAll);
  return removed;
}

/** Minimal MAC helpers (as methods or move to module scope if you prefer) */
MAC_REGEX = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;

normalizeMac(v) {
  return (v ?? "").trim().toLowerCase();
}
isValidMac(v) {
  return this.MAC_REGEX.test(v);
}

async handleWebSocketMessage(data) {
  switch (data.type) {
    case 'initial':
      this.devices = data.devices || [];
      this.clients = data.clients || [];
      this.updateAllDisplays();
      break;
    case 'metrics_update':
      this.updateMetrics(data.metrics || {});
      break;
    case 'device_update':
      this.updateDevice(data.device);
      break;
    case 'client_update':
      this.updateClient(data.client);
      break;
    case 'topology_change':
      const freshTopology = await this.apiCall('/topology');
      await this.updateTopology(freshTopology);
      break;
    case 'security_event':
      this.handleSecurityEvent(data.event);
      break;
    case 'notification':
      this.showNotification(data.message, data.level);
      break;
    case 'heartbeat':                              // ✅ handle it
      // optionally track connected_clients or update a “last seen”
      // console.debug('WS heartbeat', data.connected_clients);
      break;
    default:
      // noop
      break;
  }
}

  /**
   * Load initial data from API
   */
  async loadInitialData() {
    this.showLoading(true);

    try {
      // Load devices
      const devicesResponse = await this.apiCall('/devices');
      this.devices = devicesResponse.devices || [];

      // Load clients
      const clientsResponse = await this.apiCall('/clients');
      this.clients = clientsResponse.clients || [];

      // Load system config
      this.systemConfig = await this.apiCall('/config');

      // Update displays
      this.updateAllDisplays();
    } catch (error) {
      console.error('Failed to load initial data:', error);
      this.showNotification('Failed to load initial data', 'error');
    } finally {
      this.showLoading(false);
    }
  }

  /**
   * Make API calls with error handling
   */
  async apiCall(endpoint, options = {}) {
    const url = `${this.apiBase}${endpoint}`;

    try {
      const response = await fetch(url, {
        method: options.method || 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        body: options.body ? JSON.stringify(options.body) : null
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error(`API call failed for ${endpoint}:`, error);
      throw error;
    }
  }

  /**
   * Update all displays with current data
   */
  updateAllDisplays() {
    this.updateDashboard();
    this.updateDevicesList();
    this.updateClientsList();
    this.updateTopologyVisualization();
    this.updatePerformanceCharts();
    this.updateSecurityCenter();
    this.updateCountBadges();
  }

  /**
   * Update dashboard metrics and displays
   */
  updateDashboard() {
    // Update key metrics
    const totalNodes = this.devices.length;
    const onlineNodes = this.devices.filter(d => d.status === 'Online').length;
    const activeClients = this.clients.filter(c => this.isClientActive(c)).length;

    this.updateElement('total-nodes', totalNodes);
    this.updateElement('active-clients', activeClients);

    // Calculate network health score
    const healthScore = this.calculateNetworkHealth();
    this.updateElement('health-score-display', Math.round(healthScore));

    // Update health indicators
    this.updateHealthIndicators();

    // Update optimization suggestions
    this.updateOptimizationSuggestions();

    // Update quick status cards
    this.updateQuickStatusCards();

    // Update traffic chart
    if (this.charts.traffic) this.updateTrafficChart();
  }

  /**
   * Calculate network health score
   */
  calculateNetworkHealth() {
    let score = 100;
    const totalDevices = this.devices.length;
    const onlineDevices = this.devices.filter(d => d.status === 'Online').length;

    if (totalDevices === 0) return 0;

    // Device availability (40% weight)
    const deviceHealth = (onlineDevices / totalDevices) * 40;

    // Performance metrics (30% weight)
    const avgThroughput = this.getAverageThroughput();
    const performanceHealth = Math.min((avgThroughput / 1000) * 30, 30);

    // Interference levels (20% weight)
    const interferenceLevel = this.getAverageInterference();
    const interferenceHealth = Math.max(0, (1 - interferenceLevel) * 20);

    // Security status (10% weight)
    const securityHealth = this.getSecurityHealth();

    return deviceHealth + performanceHealth + interferenceHealth + securityHealth;
  }

  /**
   * Update devices list display
   */
  updateDevicesList() {
    const devicesGrid = document.getElementById('devices-grid');
    if (!devicesGrid) return;

    devicesGrid.innerHTML = '';

    this.devices.forEach(device => {
      const deviceCard = this.createDeviceCard(device);
      devicesGrid.appendChild(deviceCard);
    });
  }

  /**
   * Create device card element
   */
   /**
   * Update devices list (for Mesh Devices tab - keep original)
   */
  updateDevicesList() {
    const devicesGrid = document.getElementById('devices-grid');
    if (!devicesGrid) return;

    devicesGrid.innerHTML = '';

    if (this.devices.length === 0) {
      devicesGrid.innerHTML = '<div class="loading-message">No devices found</div>';
      return;
    }

    this.devices.forEach(device => {
      const card = this.createDeviceCard(device);
      devicesGrid.appendChild(card);
    });
  }

  /**
   * Update performance devices section (P2/P3 design in Performance tab)
   */
  updatePerformanceDevices() {
    const devicesContainer = document.getElementById('performance-devices-list');
    if (!devicesContainer) return;

    devicesContainer.innerHTML = '';

    if (this.devices.length === 0) {
      devicesContainer.innerHTML = '<div class="loading-message">No devices found</div>';
      return;
    }

    this.devices.forEach(device => {
      const deviceSection = this.createDeviceSection(device);
      devicesContainer.appendChild(deviceSection);
    });
  }

  /**
   * Create expandable device section (like P2/P3 design)
   */
  createDeviceSection(device) {
    const section = document.createElement('div');
    section.className = 'device-section';
    section.id = `device-section-${device.mac.replace(/:/g, '')}`;

    const statusClass = device.status === 'Online' ? 'online' : 'offline';
    const clientCount = this.getDeviceClientCount(device.mac);

    section.innerHTML = `
      <div class="device-section-header">
        <div class="device-section-info">
          <i class="fas fa-network-wired"></i>
          <h3>${device.vendor} ${device.model}</h3>
        </div>
        <div class="device-section-badges">
          <span class="badge badge-${device.role.toLowerCase()}">${device.role}</span>
          <span class="badge badge-${statusClass}">${device.status}</span>
          <span class="badge badge-clients"><i class="fas fa-users"></i> ${clientCount} clients</span>
        </div>
        <button class="device-toggle-btn" onclick="window.EasyMeshController.toggleDeviceSection('${device.mac}')">
          <i class="fas fa-chevron-down"></i>
        </button>
      </div>

      <div class="device-section-content" id="device-content-${device.mac.replace(/:/g, '')}">
        <!-- Individual charts will be populated here for each client -->
        <div class="individual-client-charts" id="client-charts-${device.mac.replace(/:/g, '')}">
          ${clientCount > 0 ? '<div class="loading-message">Loading client charts...</div>' : '<p class="no-clients">No clients connected</p>'}
        </div>

        <!-- Connected Clients Section -->
        <div class="device-clients-section">
          <h4><i class="fas fa-users"></i> Connected Clients</h4>
          <div class="device-clients-list" id="device-clients-${device.mac.replace(/:/g, '')}">
            ${clientCount > 0 ? 'Loading clients...' : 'No clients connected'}
          </div>
        </div>
      </div>
    `;

    return section;
  }

  /**
   * Toggle device section expand/collapse
   */
  toggleDeviceSection(deviceMAC) {
    const contentId = `device-content-${deviceMAC.replace(/:/g, '')}`;
    const content = document.getElementById(contentId);
    const section = document.getElementById(`device-section-${deviceMAC.replace(/:/g, '')}`);
    
    if (!content || !section) return;

    const isExpanded = content.style.display === 'block';
    content.style.display = isExpanded ? 'none' : 'block';
    
    const toggleBtn = section.querySelector('.device-toggle-btn i');
    if (toggleBtn) {
      toggleBtn.className = isExpanded ? 'fas fa-chevron-down' : 'fas fa-chevron-up';
    }

    // Load client list and individual charts if expanding for the first time
    if (!isExpanded) {
      this.loadDeviceClients(deviceMAC);
      this.createIndividualClientCharts(deviceMAC);
    }
  }

  /**
   * Load and display clients for a device
   */
  loadDeviceClients(deviceMAC) {
    const clientsContainer = document.getElementById(`device-clients-${deviceMAC.replace(/:/g, '')}`);
    if (!clientsContainer) return;

    const connectedClients = this.clients.filter(c => c.connected_ap_mac === deviceMAC);

    if (connectedClients.length === 0) {
      clientsContainer.innerHTML = '<p class="no-clients">No clients connected</p>';
      return;
    }

    clientsContainer.innerHTML = connectedClients.map(client => {
      const metrics = client.client_metrics || {};
      const performance = this.calculateClientPerformanceMetrics(metrics);
      
      return `
        <div class="device-client-item">
          <div class="client-item-icon">
            <i class="fas fa-${this.getDeviceTypeIcon(client.device_type)}"></i>
          </div>
          <div class="client-item-info">
            <h5>${client.hostname}</h5>
            <span class="client-mac">${client.mac.substring(0, 17)}</span>
          </div>
          <div class="client-item-status">
            <span class="status-badge ${this.getPerformanceClass(performance.score)}">${this.getPerformanceRating(performance.score)}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  /**
   * Handle client selection for device chart
   */
  /**
   * Create individual performance charts for each client on a device
   */
  createIndividualClientCharts(deviceMAC) {
    const chartsContainer = document.getElementById(`client-charts-${deviceMAC.replace(/:/g, '')}`);
    if (!chartsContainer) return;

    const connectedClients = this.clients.filter(c => c.connected_ap_mac === deviceMAC);
    
    if (connectedClients.length === 0) {
      chartsContainer.innerHTML = '<p class="no-clients">No clients connected</p>';
      return;
    }

    // Clear container
    chartsContainer.innerHTML = '';

    // Create individual chart for each client
    connectedClients.forEach((client, index) => {
      const clientId = client.mac.replace(/:/g, '');
      const chartDiv = document.createElement('div');
      chartDiv.className = 'individual-client-chart-card';
      chartDiv.innerHTML = `
        <div class="client-chart-header">
          <h4>${client.hostname} - Performance Metrics</h4>
          <span class="client-mac-label">${client.mac.substring(0, 17)}</span>
        </div>
        <div class="client-chart-canvas-wrapper">
          <canvas id="client-individual-chart-${clientId}"></canvas>
        </div>
      `;
      chartsContainer.appendChild(chartDiv);

      // Create the chart
      this.createSingleClientChart(client, `client-individual-chart-${clientId}`, deviceMAC);
    });
  }

  /**
   * Create chart for a single client showing all 5 metrics
   */
  createSingleClientChart(client, canvasId, deviceMAC) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const metrics = client.client_metrics || {};
    const performance = this.calculateClientPerformanceMetrics(metrics);

    // Destroy existing chart if any
    const chartKey = `${deviceMAC}-${client.mac}`;
    if (this.charts[chartKey]) {
      this.charts[chartKey].destroy();
    }

    // Generate time series data
    const timeLabels = this.generateTimeLabels(13);
    
    // Create datasets for all 5 metrics
    const datasets = [
      {
        label: 'Score',
        data: this.generateVariedData(performance.score, 13, 8),
        borderColor: '#6366f1',
        backgroundColor: '#6366f1' + '30',
        borderWidth: 3,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'SNR (dB)',
        data: this.generateVariedData(performance.snr, 13, 4),
        borderColor: '#10b981',
        backgroundColor: '#10b981' + '30',
        borderWidth: 3,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'PR (Mbps/10)',
        data: this.generateVariedData(performance.pr / 10, 13, 20),
        borderColor: '#f59e0b',
        backgroundColor: '#f59e0b' + '30',
        borderWidth: 3,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'PER (% × 20)',
        data: this.generateVariedData(performance.per * 20, 13, 2),
        borderColor: '#ef4444',
        backgroundColor: '#ef4444' + '30',
        borderWidth: 3,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'PSY',
        data: this.generateVariedData(performance.psy, 13, 6),
        borderColor: '#8b5cf6',
        backgroundColor: '#8b5cf6' + '30',
        borderWidth: 3,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      }
    ];

    this.charts[chartKey] = new Chart(ctx, {
      type: 'line',
      data: {
        labels: timeLabels,
        datasets: datasets
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: 'index',
          intersect: false,
        },
        plugins: {
          legend: {
            display: true,
            position: 'bottom',
            labels: {
              usePointStyle: true,
              padding: 15,
              font: { size: 11 }
            }
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                let label = context.dataset.label || '';
                let value = context.parsed.y;
                
                // Denormalize for display
                if (label.includes('PR')) {
                  value = value * 10;
                  label = 'PR (Mbps)';
                } else if (label.includes('PER')) {
                  value = value / 20;
                  label = 'PER (%)';
                }
                
                return label + ': ' + value.toFixed(2);
              }
            }
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(0, 0, 0, 0.05)' },
            ticks: { font: { size: 10 } }
          },
          y: {
            beginAtZero: true,
            min: 0,
            max: 100,
            grid: { color: 'rgba(0, 0, 0, 0.05)' },
            title: {
              display: true,
              text: 'Normalized Values (0-100)',
              font: { size: 12, weight: 'bold' }
            }
          }
        }
      }
    });
  }

  // Deprecated functions - kept for compatibility
  createAllClientsChart(deviceMAC) {
    const canvasId = `client-chart-${deviceMAC.replace(/:/g, '')}`;
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const connectedClients = this.clients.filter(c => c.connected_ap_mac === deviceMAC);
    
    if (connectedClients.length === 0) {
      return;
    }

    // Destroy existing chart if any
    const chartKey = `device-chart-${deviceMAC}`;
    if (this.charts[chartKey]) {
      this.charts[chartKey].destroy();
    }

    // Generate time series data
    const timeLabels = this.generateTimeLabels(13);
    
    // Define colors for the 5 metrics
    const metricColors = {
      score: '#6366f1',
      snr: '#10b981',
      pr: '#f59e0b',
      per: '#ef4444',
      psy: '#8b5cf6'
    };
    
    // Create datasets for each client - all 5 metrics per client
    const datasets = [];
    
    connectedClients.forEach((client, clientIndex) => {
      const metrics = client.client_metrics || {};
      const performance = this.calculateClientPerformanceMetrics(metrics);
      
      // For each metric, create a dataset with client name
      const clientLabel = client.hostname || `Client ${clientIndex + 1}`;
      
      // Score
      datasets.push({
        label: `${clientLabel} - Score`,
        data: this.generateVariedData(performance.score, 13, 8),
        borderColor: metricColors.score,
        backgroundColor: metricColors.score + '30',
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 2,
        pointHoverRadius: 5,
        borderDash: clientIndex === 0 ? [] : [5, 5]
      });
      
      // SNR
      datasets.push({
        label: `${clientLabel} - SNR`,
        data: this.generateVariedData(performance.snr, 13, 4),
        borderColor: metricColors.snr,
        backgroundColor: metricColors.snr + '30',
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 2,
        pointHoverRadius: 5,
        borderDash: clientIndex === 0 ? [] : [5, 5]
      });
      
      // PR (normalized)
      datasets.push({
        label: `${clientLabel} - PR`,
        data: this.generateVariedData(performance.pr / 10, 13, 20),
        borderColor: metricColors.pr,
        backgroundColor: metricColors.pr + '30',
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 2,
        pointHoverRadius: 5,
        borderDash: clientIndex === 0 ? [] : [5, 5]
      });
      
      // PER (normalized)
      datasets.push({
        label: `${clientLabel} - PER`,
        data: this.generateVariedData(performance.per * 20, 13, 2),
        borderColor: metricColors.per,
        backgroundColor: metricColors.per + '30',
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 2,
        pointHoverRadius: 5,
        borderDash: clientIndex === 0 ? [] : [5, 5]
      });
      
      // PSY
      datasets.push({
        label: `${clientLabel} - PSY`,
        data: this.generateVariedData(performance.psy, 13, 6),
        borderColor: metricColors.psy,
        backgroundColor: metricColors.psy + '30',
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 2,
        pointHoverRadius: 5,
        borderDash: clientIndex === 0 ? [] : [5, 5]
      });
    });

    this.charts[chartKey] = new Chart(ctx, {
      type: 'line',
      data: {
        labels: timeLabels,
        datasets: datasets
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: 'index',
          intersect: false,
        },
        plugins: {
          legend: {
            display: true,
            position: 'bottom',
            labels: {
              usePointStyle: true,
              padding: 8,
              font: { size: 10 },
              boxWidth: 20,
              boxHeight: 2
            }
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                let label = context.dataset.label || '';
                let value = context.parsed.y;
                
                // Denormalize for display
                if (label.includes('PR')) {
                  value = value * 10;
                } else if (label.includes('PER')) {
                  value = value / 20;
                }
                
                return label + ': ' + value.toFixed(2);
              }
            }
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(0, 0, 0, 0.05)' },
            ticks: { font: { size: 10 } }
          },
          y: {
            beginAtZero: true,
            min: 0,
            max: 100,
            grid: { color: 'rgba(0, 0, 0, 0.05)' },
            title: {
              display: true,
              text: 'Normalized Values (0-100)',
              font: { size: 12, weight: 'bold' }
            }
          }
        }
      }
    });
  }

  // Keep old function for compatibility (not used anymore)
  onClientSelect(deviceMAC, clientMAC) {
    // Deprecated - now showing all clients automatically
  }

  /**
   * Create combined performance chart for selected client (deprecated)
   */
  createDeviceClientChart(deviceMAC, client) {
    const canvasId = `client-chart-${deviceMAC.replace(/:/g, '')}`;
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const metrics = client.client_metrics || {};
    const performance = this.calculateClientPerformanceMetrics(metrics);

    // Destroy existing chart if any
    const chartKey = `device-chart-${deviceMAC}`;
    if (this.charts[chartKey]) {
      this.charts[chartKey].destroy();
    }

    // Generate time series data
    const timeLabels = this.generateTimeLabels(13);
    
    // Create datasets for all 5 metrics (normalized to 0-100)
    const datasets = [
      {
        label: 'Score',
        data: this.generateVariedData(performance.score, 13, 8),
        borderColor: '#6366f1',
        backgroundColor: '#6366f1' + '30',
        borderWidth: 3,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'SNR (dB)',
        data: this.generateVariedData(performance.snr, 13, 4),
        borderColor: '#10b981',
        backgroundColor: '#10b981' + '30',
        borderWidth: 3,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'PR (Mbps/10)',
        data: this.generateVariedData(performance.pr / 10, 13, 20),
        borderColor: '#f59e0b',
        backgroundColor: '#f59e0b' + '30',
        borderWidth: 3,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'PER (% × 20)',
        data: this.generateVariedData(performance.per * 20, 13, 2),
        borderColor: '#ef4444',
        backgroundColor: '#ef4444' + '30',
        borderWidth: 3,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'PSY',
        data: this.generateVariedData(performance.psy, 13, 6),
        borderColor: '#8b5cf6',
        backgroundColor: '#8b5cf6' + '30',
        borderWidth: 3,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      }
    ];

    this.charts[chartKey] = new Chart(ctx, {
      type: 'line',
      data: {
        labels: timeLabels,
        datasets: datasets
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: 'index',
          intersect: false,
        },
        plugins: {
          legend: {
            display: true,
            position: 'bottom',
            labels: {
              usePointStyle: true,
              padding: 15,
              font: { size: 12 }
            }
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                let label = context.dataset.label || '';
                let value = context.parsed.y;
                
                // Denormalize for display
                if (label.includes('PR')) {
                  value = value * 10;
                  label = 'PR (Mbps)';
                } else if (label.includes('PER')) {
                  value = value / 20;
                  label = 'PER (%)';
                }
                
                return label + ': ' + value.toFixed(2);
              }
            }
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(0, 0, 0, 0.05)' },
            ticks: { font: { size: 10 } }
          },
          y: {
            beginAtZero: true,
            min: 0,
            max: 100,
            grid: { color: 'rgba(0, 0, 0, 0.05)' },
            title: {
              display: true,
              text: 'Normalized Values (0-100)',
              font: { size: 12, weight: 'bold' }
            }
          }
        }
      }
    });
  }

  /**
   * Calculate performance metrics from client metrics
   */
  calculateClientPerformanceMetrics(metrics) {
    // Score
    const rssiScore = this.normalizeRSSI(metrics.rssi_dbm || -70);
    const snrScore = (metrics.snr_db || 0) / 60 * 100;
    const rateScore = Math.min((Math.max(metrics.tx_rate_mbps || 0, metrics.rx_rate_mbps || 0)) / 2000 * 100, 100);
    const lossScore = Math.max(100 - (metrics.packet_loss_percent || 0) * 100, 0);
    const score = Math.round(rssiScore * 0.3 + snrScore * 0.3 + rateScore * 0.2 + lossScore * 0.2);
    
    // SNR
    const snr = metrics.snr_db || 0;
    
    // Physical Rate
    const pr = Math.max(metrics.tx_rate_mbps || 0, metrics.rx_rate_mbps || 0);
    
    // Packet Error Rate
    const per = metrics.packet_loss_percent || 0;
    
    // PSY
    const snrComponent = (metrics.snr_db || 0) / 60 * 50;
    const spatialStreams = (metrics.spatial_streams || 1) / 2 * 25;
    const channelWidth = (metrics.channel_width_mhz || 20) / 160 * 25;
    const psy = Math.round(Math.min(snrComponent + spatialStreams + channelWidth, 100));
    
    return { score, snr, pr, per, psy };
  }

  normalizeRSSI(rssi) {
    const min = -90;
    const max = -30;
    return Math.max(0, Math.min(100, ((rssi - min) / (max - min)) * 100));
  }

  /**
   * Generate varied time series data
   */
  generateVariedData(baseValue, points, variation) {
    const data = [];
    for (let i = 0; i < points; i++) {
      const vary = (Math.random() - 0.5) * variation;
      data.push(Math.max(0, Math.min(100, baseValue + vary)));
    }
    return data;
  }

  /**
   * Generate time labels
   */
  generateTimeLabels(count) {
    const labels = [];
    const now = new Date();
    const interval = 60 / count;
    
    for (let i = count - 1; i >= 0; i--) {
      const time = new Date(now.getTime() - i * interval * 60000);
      labels.push(time.toLocaleTimeString('en-US', { 
        hour: 'numeric', 
        minute: '2-digit',
        hour12: true 
      }));
    }
    
    return labels;
  }

  getPerformanceClass(score) {
    if (score >= 80) return 'excellent';
    if (score >= 60) return 'good';
    if (score >= 40) return 'fair';
    return 'poor';
  }

  getPerformanceRating(score) {
    if (score >= 80) return 'EXCELLENT';
    if (score >= 60) return 'GOOD';
    if (score >= 40) return 'FAIR';
    return 'POOR';
  }

  createDeviceCard(device) {
    const card = document.createElement('div');
    card.className = 'device-card';
    card.onclick = () => this.showDeviceDetails(device);

    const statusClass = device.status === 'Online' ? 'online' : 'offline';
    const signalStrength = this.getSignalStrengthIcon(device.signal || -50);
    const uptime = device.uptime || 'Unknown';

    card.innerHTML = `
      <div class="device-header">
        <div class="device-info">
          <h3>${device.vendor} ${device.model}</h3>
          <div class="device-model">${device.mac}</div>
        </div>
        <div class="device-status ${statusClass}">
          <i class="fas fa-circle"></i>
          ${device.status}
        </div>
      </div>

      <div class="device-metrics">
        <div class="metric-item">
          <div class="label">Role</div>
          <div class="value">${device.role}</div>
        </div>
        <div class="metric-item">
          <div class="label">Signal</div>
          <div class="value">${signalStrength}</div>
        </div>
        <div class="metric-item">
          <div class="label">Uptime</div>
          <div class="value">${uptime}</div>
        </div>
        <div class="metric-item">
          <div class="label">Clients</div>
          <div class="value">${this.getDeviceClientCount(device.mac)}</div>
        </div>
      </div>

      <div class="device-actions">
        <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); window.EasyMeshController.rebootDevice('${device.mac}')">
          <i class="fas fa-power-off"></i> Reboot
        </button>
        <button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); window.EasyMeshController.configureDevice('${device.mac}')">
          <i class="fas fa-cog"></i> Configure
        </button>
      </div>
    `;

    return card;
  }

  /**
   * Update clients list
   */
  updateClientsList() {
    const clientsTable = document.getElementById('clients-tbody');
    if (!clientsTable) return;

    clientsTable.innerHTML = '';

    this.clients.forEach(client => {
      const row = this.createClientRow(client);
      clientsTable.appendChild(row);
    });
  }

  /**
   * Create client table row
   */
  createClientRow(client) {
    const row = document.createElement('tr');

    const deviceIcon = this.getDeviceTypeIcon(client.device_type);
    const signalBars = this.createSignalBars(client.client_metrics?.rssi || -70);
    const connectionInfo = this.getClientConnectionInfo(client);

    row.innerHTML = `
      <td>
        <div class="client-info">
          <div class="client-icon">
            <i class="fas fa-${deviceIcon}"></i>
          </div>
          <div class="client-details">
            <h4>${client.hostname || 'Unknown Device'}</h4>
            <div class="client-mac">${client.mac}</div>
          </div>
        </div>
      </td>
      <td>
        <div class="connection-info">
          <div class="connection-ap">${connectionInfo.ap}</div>
          <div class="connection-band">${connectionInfo.band}</div>
        </div>
      </td>
      <td>
        <div class="signal-strength">
          ${signalBars}
          <span>${client.client_metrics?.rssi || 'N/A'} dBm</span>
        </div>
      </td>
      <td>
        <div class="speed-info">
          ↑${this.formatSpeed(client.client_metrics?.tx_rate || 0)}<br>
          ↓${this.formatSpeed(client.client_metrics?.rx_rate || 0)}
        </div>
      </td>
      <td>
        <div class="usage-info">
          ${this.formatBytes(client.client_metrics?.data_usage || 0)}
        </div>
      </td>
      <td>
        <div class="client-actions">
          <button class="action-btn" onclick="window.EasyMeshController.showClientDetails('${client.mac}')" title="Details">
            <i class="fas fa-info"></i>
          </button>
          <button class="action-btn" onclick="window.EasyMeshController.disconnectClient('${client.mac}')" title="Disconnect">
            <i class="fas fa-unlink"></i>
          </button>
          <button class="action-btn" onclick="window.EasyMeshController.blockClient('${client.mac}')" title="Block">
            <i class="fas fa-ban"></i>
          </button>
        </div>
      </td>
    `;

    return row;
  }

  /**
   * Initialize all charts
   */
  initializeCharts() {
    // Check if Chart.js is loaded
    if (typeof Chart === 'undefined') {
      console.warn('Chart.js not loaded, loading from CDN...');
      this.loadChartJS().then(() => {
        this.createCharts();
      }).catch(() => console.error('Failed to load Chart.js'));
    } else {
      this.createCharts();
    }
  }

  /**
   * Load Chart.js dynamically
   */
  async loadChartJS() {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js';
      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });
  }

  /**
   * Create all charts
   */
  createCharts() {
    try {
      this.createTrafficChart();
      this.createThroughputChart();
      this.createUtilizationChart();
      this.createClientDistributionChart();
      this.createLatencyChart?.();
      this.createSpectrumChart();
    } catch (error) {
      console.error('Error creating charts:', error);
    }
  }

  /**
   * Create traffic chart
   */
  createTrafficChart() {
    const canvas = document.getElementById('traffic-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    this.charts.traffic = new Chart(ctx, {
      type: 'line',
      data: {
        labels: this.generateTimeLabels(12),
        datasets: [
          {
            label: 'Upload',
            data: this.generateTrafficData(12),
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            fill: true,
            tension: 0.4
          },
          {
            label: 'Download',
            data: this.generateTrafficData(12, 2),
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            fill: true,
            tension: 0.4
          }
        ]
      },
      options: {
        ...this.chartDefaults,
        scales: {
          ...this.chartDefaults.scales,
          y: {
            ...this.chartDefaults.scales.y,
            title: { display: true, text: 'Mbps' }
          }
        },
        plugins: {
          ...this.chartDefaults.plugins,
          tooltip: {
            callbacks: {
              label: (context) => `${context.dataset.label}: ${context.parsed.y} Mbps`
            }
          }
        }
      }
    });
  }

  /**
   * Create throughput chart
   */
  createThroughputChart() {
    const canvas = document.getElementById('throughput-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    this.charts.throughput = new Chart(ctx, {
      type: 'line',
      data: {
        labels: this.generateTimeLabels(24),
        datasets: [
          {
            label: '2.4GHz',
            data: this.generateRandomData(24, 50, 200),
            borderColor: '#f59e0b',
            backgroundColor: 'rgba(245, 158, 11, 0.1)',
            fill: false
          },
          {
            label: '5GHz',
            data: this.generateRandomData(24, 200, 800),
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            fill: false
          },
          {
            label: '6GHz',
            data: this.generateRandomData(24, 500, 1200),
            borderColor: '#8b5cf6',
            backgroundColor: 'rgba(139, 92, 246, 0.1)',
            fill: false
          }
        ]
      },
      options: {
        ...this.chartDefaults,
        scales: {
          ...this.chartDefaults.scales,
          y: {
            ...this.chartDefaults.scales.y,
            title: { display: true, text: 'Throughput (Mbps)' }
          }
        }
      }
    });
  }

  /**
   * Create utilization chart
   */
  createUtilizationChart() {
    const canvas = document.getElementById('utilization-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    this.charts.utilization = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['2.4GHz', '5GHz', '6GHz', 'Available'],
        datasets: [{
          data: [35, 45, 15, 5],
          backgroundColor: ['#f59e0b', '#3b82f6', '#8b5cf6', '#e5e7eb'],
          borderWidth: 0
        }]
      },
      options: {
        ...this.chartDefaults,
        cutout: '60%',
        plugins: {
          ...this.chartDefaults.plugins,
          tooltip: {
            callbacks: { label: (context) => `${context.label}: ${context.parsed}%` }
          }
        }
      }
    });
  }

  /**
   * Create client distribution chart
   */
  createClientDistributionChart() {
    const canvas = document.getElementById('client-distribution-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    const deviceData = this.devices.map(device => ({
      label: device.model,
      clients: this.getDeviceClientCount(device.mac)
    }));

    this.charts.clientDistribution = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: deviceData.map(d => d.label),
        datasets: [{
          label: 'Connected Clients',
          data: deviceData.map(d => d.clients),
          backgroundColor: '#3b82f6',
          borderColor: '#2563eb',
          borderWidth: 1
        }]
      },
      options: {
        ...this.chartDefaults,
        scales: {
          ...this.chartDefaults.scales,
          y: {
            ...this.chartDefaults.scales.y,
            title: { display: true, text: 'Number of Clients' },
            ticks: { stepSize: 1 }
          }
        }
      }
    });
  }

  /**
   * Create spectrum analyzer chart
   */
  createSpectrumChart() {
    const canvas = document.getElementById('spectrum-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    this.charts.spectrum = new Chart(ctx, {
      type: 'line',
      data: {
        labels: this.generate24GHzChannels(),
        datasets: [{
          label: 'Signal Strength (dBm)',
          data: this.generateSpectrumData(),
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          fill: true,
          pointRadius: 0,
          tension: 0.1
        }]
      },
      options: {
        ...this.chartDefaults,
        scales: {
          x: { title: { display: true, text: 'Frequency (MHz)' } },
          y: { title: { display: true, text: 'Signal Strength (dBm)' }, min: -100, max: -20 }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  /**
   * Update topology visualization
   */
  updateTopologyVisualization() {
    const container = d3.select('#topology-visualization');
    const tooltip = d3.select('#custom-tooltip');
    const width = container.node().clientWidth;
    const height = container.node().clientHeight;
    const self = this;

    // Return if container is not ready
    if (width === 0 || height === 0) {
      setTimeout(() => this.updateTopologyVisualization(), 100);
      return;
    }

    // Return if container is empty
    if (!this.topology?.nodes?.length) return;

    // Clear previous content
    container.selectAll('*').remove();

    // Create SVG and zoom behavior
    const svg = container.append('svg')
    .attr('width', width)
    .attr('height', height)
    .call(d3.zoom().on('zoom', (event) => {
      svgGroup.attr('transform', event.transform);
    }));

    const svgGroup = svg.append('g');

    // Normalize node and edge IDs to strings
    this.topology.nodes.forEach(n => n.id = String(n.id));
    this.topology.edges.forEach(e => {
      e.from = String(e.from);
      e.to = String(e.to);
    });

    // Validate edges
    const nodeIds = new Set(this.topology.nodes.map(n => n.id));
    const invalidEdges = this.topology.edges.filter(e => !nodeIds.has(e.from) || !nodeIds.has(e.to));

    if (invalidEdges.length > 0) {
      console.error('Invalid edges found:', invalidEdges);
      throw new Error('Topology contains edges with undefined nodes.');
    }

    // Transform edges to use source/target for D3
    const edges = this.topology.edges.map(e => ({
      ...e,
      source: e.from,
      target: e.to
    }));

    // Define haulType colors
    const haulColors = {
      Fronthaul: '#c3cbf8ff',
      Backhaul: '#e68b8bff',
      Iot: '#d3ced3ff'
    };

    const circleOffsets = [
      { x: -65, y: 50 },
      { x: 65, y: 50 },
      { x: 0, y: -65 }
    ];

    const bandColors = {
      '-1': '#0bd476ff',
      '0': '#8B4513',
      '1': '#5a82c2ff',
      '2': '#d83131ff',
    };

    const bandWavelengths = {
      '-1': 0,
      '0': 25,
      '1': 15,
      '2': 10,
      'default': 20
    };

    const minX = d3.min(this.topology.nodes, d => d.x);
    const maxX = d3.max(this.topology.nodes, d => d.x);
    const minY = d3.min(this.topology.nodes, d => d.y);
    const maxY = d3.max(this.topology.nodes, d => d.y);
    const graphWidth = maxX - minX;
    const graphHeight = maxY - minY;
    const offsetX = (width - graphWidth) / 2 - minX -250;
    const offsetY = (height - graphHeight) / 2 - minY;

    this.topology.nodes.forEach(node => {
      node.fx = node.x + offsetX;
      node.fy = node.y + offsetY;
    });

    // Create simulation
    const simulation = d3.forceSimulation(this.topology.nodes)
    .force('link', d3.forceLink(edges).id(d => d.id))
    .force('charge', d3.forceManyBody().strength(-500))
    .force('center', d3.forceCenter(width / 2, height / 2));

    const nodeGroup = svgGroup.append('g').attr('class', 'nodes');
    const edgeGroup = svgGroup.append('g').attr('class', 'edges');
    const staGroup  = svgGroup.append('g').attr('class', 'sta-nodes');

    const node = nodeGroup.selectAll('g')
    .data(this.topology.nodes)
    .enter()
    .append('g')
    .attr('class', 'node')
    .call(d3.drag()
      .on('start', dragstarted)
      .on('drag', dragged)
      .on('end', dragended));

    // Draw overlapping haulType circles and icon
    node.each(function(d) {
      const g = d3.select(this);
      const haulTypes = d.haulTypes?.map(ht => ht.name) || [];

      haulTypes.forEach((type, i) => {
        const offset = circleOffsets[i] || { x: 0, y: 0 };
        const verticalShift = offset.x < 0 ? -8 : offset.x > 0 ? 8 : 0;

        // SSID heading inside the each circle
        const haul = d.haulTypes?.[i];
        const ssid = haul?.ssid || 'SSID N/A';
        const vlanId = haul?.VlanId || 'N/A';
        const mldMap = new Map();

        // Extract BSS-band details
        const bssDetails = haul.BSSList
        .filter(bss => bss.vapMode !== 1)
        .map(bss => {
          const bandLabel = bss.Band === 0 ? '2.4GHz' :
            bss.Band === 1 ? '5GHz' :
            bss.Band === 2 ? '6GHz' : 'Unknown';

            if (bss.MLDAddr && bss.MLDAddr !== "") {
              if (!mldMap.has(bss.MLDAddr)) {
                mldMap.set(bss.MLDAddr, new Set());
              }
              mldMap.get(bss.MLDAddr).add(bandLabel);
            }

            if (bss.IEEE == "" ) {
              if (bss.Band == 0 || bss.Band == 1) {
                bss.IEEE= "802.11ax"
              } else {
                bss.IEEE= "802.11be"
              }
            }

            return `${bss.BSSID} - (${bandLabel}) - ${bss.IEEE}`;
          });

          const mldSummary = Array.from(mldMap.entries()).map(([addr, bands]) => {
            return `${addr} - ${bands.size} - ${Array.from(bands).join(', ')}`;
          });

        const hasMLD = haul.BSSList.some(bss => bss.MLDAddr && bss.MLDAddr !== "");

        // Draw haultype overlapping circle
        g.append('circle')
          .attr('r', 80)
          .attr('cx', offset.x)
          .attr('cy', offset.y)
          .attr('fill', haulColors[type] || '#ccc')
          .attr('opacity', 0.6)
          .attr('stroke', hasMLD ? '#45f88aff': 'none')
          .attr('stroke-width', hasMLD ? 3: 0)
          .style('pointer-events', 'visiblePainted')
          .on('mouseover', function(event) {
            let mldInfo = '';
            if (mldSummary.length > 0) {
              mldInfo = `<br><b>MLD Summary:</b><br>${mldSummary.join('<br>')}`;
            }
            tooltip.style('display', 'block')
           .html(`<b>SSID: ${ssid}</b><br>${bssDetails.join('<br>')}<br>VLAN ID: ${vlanId}<br>${mldInfo}`);
          })
          .on('mousemove', function(event) {
            self.positionTooltip(event, tooltip);
          })
          .on('mouseout', function() {
            tooltip.style('display', 'none');
          });

        g.append('text')
          .attr('x', offset.x)
          .attr('y', offset.y + verticalShift)
          .attr('text-anchor', 'middle')
          .attr('dominant-baseline', 'middle')
          .attr('font-size', '12px')
          .attr('fill', '#9b9a9aff')
          .attr('font-weight', 'bold')
          .text(ssid);
      });

      // STA Placement
      if (Array.isArray(d.STAList) && d.STAList.length > 0) {
        const staList = d.STAList;
        const baseRadius = 80;
        const angleStep = (2 * Math.PI) / staList.length;
        const nodeRadius = 20;
        const maxSize = 30;
        const minSize = 15;

        staList.forEach((sta, i) => {
          const staElement = staGroup
          .append('g')
          .attr('class', 'sta-node')
          .datum(() => {
            const seed = i + sta.staMAC.length;
            let angle = angleStep * i;
            // small jitter for few STAs (computed once)
            if (staList.length < 5) {
              angle += (self.seededRandom(seed) * 2 - 0.5) * 0.5;
            }

            const radius = baseRadius + self.seededRandom(seed + 2) * 40;
            const iconSize = Math.max(minSize, maxSize - staList.length);
            return {
              nodeRef: d,
              sta,
              angle,
              radius,
              iconSize,
              nodeRadius
            };
          });

          const data = staElement.datum();

          // Compute local positions (relative to the node center)
          const angleFromCenter = data.angle;
          const from = {
            x: data.nodeRadius * Math.cos(angleFromCenter),
            y: data.nodeRadius * Math.sin(angleFromCenter)
          };
          const to = {
            x: data.radius * Math.cos(angleFromCenter),
            y: data.radius * Math.sin(angleFromCenter)
          };
          const staWaveLength = bandWavelengths[sta.band] || bandWavelengths['default'];
          const sinePathData = self.generateSineWavePath(from, to, {
            amplitude: 5,
            wavelength: staWaveLength
          });

          staElement.append('path')
            .attr('d', sinePathData.path)
            .attr('fill', 'none')
            .attr('stroke', '#141313ff')
            .attr('stroke-width', 1)
            .attr('stroke', d => bandColors[sta.band] || '#000');

          // Draw STA node
          const iconUrl = self.getClientIcon(sta.clientType);

          staElement.append('image')
           .attr('xlink:href', iconUrl)
           .attr('x', to.x - data.iconSize / 2)
           .attr('y', to.y - data.iconSize / 2)
           .attr('width', data.iconSize)
           .attr('height', data.iconSize)
           .on('mouseover', function(event) {
              let mldInfo = '';
              if (sta.MLDAddr && sta.MLDAddr !== '') {
                mldInfo = `<br>MLD Address: ${sta.MLDAddr}`;
              }
              tooltip.style('display', 'block')
              .html(`<b>STA:</b> ${sta.clientType || 'Unknown'}<br>MAC: ${sta.staMAC}${mldInfo}<br>SSID: ${sta.ssid}`);
            })
           .on('mousemove', function(event) {
              self.positionTooltip(event, tooltip);
            })
            .on('mouseout', function() {
              tooltip.style('display', 'none');
            });
        });

      }

      const nodeIconUrl = self.getNodeIcon(d.name);
      let isController = false;
      if (d.name?.toLowerCase().includes('controller')) {
        isController = true;
      }

      g.append('image')
        .attr('xlink:href', nodeIconUrl)
        .attr('x', isController ? -25 : -20)
        .attr('y', isController ? -25 : -20)
        .attr('width', isController ? 50 : 35)
        .attr('height', isController ? 50 : 35)
        .on('mouseover', function(event) {
          tooltip.style('display', 'block')
          .html(`<b>${d.name || d.id}</b><br>MAC Address: ${d.id}`);
        })
        .on('mousemove', function(event) {
          self.positionTooltip(event, tooltip);
        })
        .on('mouseout', function() {
          tooltip.style('display', 'none');
        });

      g.append('text')
        .attr('x', 0)
        .attr('y', isController ? 30: 25)
        .attr('text-anchor', 'middle')
        .attr('font-size', '9px')
        .attr('fill', '#333')
        .attr('font-weight', 'bold')
        .text(d.name);
    });

    const edge = edgeGroup.selectAll('path')
    .data(edges)
    .enter()
    .append('path')
    .attr('fill', 'none')
    .attr('stroke-width', 2)
    .attr('stroke', d => bandColors[d.band] || '#000');

    const channelLabels = edgeGroup.selectAll('g.channel-label')
    .data(edges.filter(d => String(d.band) !== '-1')) // Only for non -1 bands
    .enter()
    .append('g')
    .attr('class', 'channel-label');

    channelLabels.append('circle')
    .attr('r', 13)
    .attr('fill', '#fff')
    .attr('stroke-width', 2)
    .attr('stroke', d => bandColors[d.band] || '#000');

    channelLabels.append('text')
    .attr('text-anchor', 'middle')
    .attr('dominant-baseline', 'middle')
    .attr('font-size', '10px')
    .attr('font-weight', 'bold')
    .text(d => d.channel);

    simulation.on('tick', () => {
      node.attr('transform', d => `translate(${d.x},${d.y})`);

      edge.attr('d', d => {
        const from = d.source;
        const to = d.target;
        const dx = to.x - from.x;
        const dy = to.y - from.y;
        const length = Math.sqrt(dx * dx + dy * dy);
        const ux = dx / length;
        const uy = dy / length;

        const edgeOffset = 25;
        const adjustedFrom = {
          x: from.x + ux * edgeOffset,
          y: from.y + uy * edgeOffset
        };
        const adjustedTo = {
          x: to.x - ux * edgeOffset,
          y: to.y - uy * edgeOffset
        };

        const band = String(d.band);
        if (band === '-1') {
          d._midpoint = [(adjustedFrom.x + adjustedTo.x) / 2, (adjustedFrom.y + adjustedTo.y) / 2];
          return `M${adjustedFrom.x},${adjustedFrom.y} L${adjustedTo.x},${adjustedTo.y}`;
        }

        const wavelength = bandWavelengths[band] || bandWavelengths['default'];
        const amplitude = 7;
        const { path, midpoint } = self.generateSineWavePath(adjustedFrom, adjustedTo, { amplitude, wavelength });
        d._midpoint = midpoint;
        return path;
      });

      channelLabels
      .attr('transform', d => {
        const mid = d._midpoint || [(d.source.x + d.target.x) / 2, (d.source.y + d.target.y) / 2];
        return `translate(${mid[0]},${mid[1]})`;
      });

      staGroup.selectAll('.sta-node')
       .attr('transform', d => `translate(${d.nodeRef.fx ?? d.nodeRef.x}, ${d.nodeRef.fy ?? d.nodeRef.y})`);
    });

    function dragstarted(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event, d) {
      if (!event.active) simulation.alphaTarget(0);

      // Only release if not originally fixed
      if (!(d.fixed?.x === true && d.fixed?.y === true)) {
        d.fx = null;
        d.fy = null;
      }
    }
  }

  /**
   * generate the sign wave connecting to node and STA
   */
  generateSineWavePath(from, to, options = {}) {
    const amplitude = options.amplitude || 7;
    const wavelength = options.wavelength || 20;
    const edgeOffset = options.edgeOffset || 0;
    const minSteps = 100;

    const dx = to.x - from.x;
    const dy = to.y - from.y;
    const length = Math.sqrt(dx * dx + dy * dy);
    if (length === 0) return { path: '', midpoint: [from.x, from.y], points: [] };

    const ux = dx / length;
    const uy = dy / length;

    const adjustedFrom = {
      x: from.x + ux * edgeOffset,
      y: from.y + uy * edgeOffset
    };
    const adjustedTo = {
      x: to.x - ux * edgeOffset,
      y: to.y - uy * edgeOffset
    };

    const newDx = adjustedTo.x - adjustedFrom.x;
    const newDy = adjustedTo.y - adjustedFrom.y;
    const newLength = Math.sqrt(newDx * newDx + newDy * newDy);

    const cycles = Math.max(1, Math.floor(newLength / wavelength));
    const steps = Math.max(minSteps, cycles * 50);
    const angle = Math.atan2(newDy, newDx);
    const perpendicularAngle = angle + Math.PI / 2;

    const points = [];
    for (let i = 0; i <= steps; i++) {
      const t = i / steps;
      const x = adjustedFrom.x + newDx * t;
      const y = adjustedFrom.y + newDy * t;
      const sineOffset = Math.sin(t * cycles * 2 * Math.PI) * amplitude;
      const offsetX = Math.cos(perpendicularAngle) * sineOffset;
      const offsetY = Math.sin(perpendicularAngle) * sineOffset;
      points.push([x + offsetX, y + offsetY]);
    }

    const midpoint = points[Math.floor(points.length / 2)];

    const lineGenerator = d3.line()
      .x(d => d[0])
      .y(d => d[1])
      .curve(d3.curveLinear);

    const path = lineGenerator(points);

    return { path, midpoint, points };
  }

  /**
   * tooltip position for hoover
   */
  positionTooltip(event, tooltip) {
    const tooltipWidth = tooltip.node().offsetWidth;
    const tooltipHeight = tooltip.node().offsetHeight;
    const pageWidth = window.innerWidth;
    const pageHeight = window.innerHeight;

    let left = event.pageX + 10;
    let top = event.pageY + 10;

    // Prevent overflow on the right
    if (left + tooltipWidth > pageWidth) {
      left = event.pageX - tooltipWidth - 10;
    }

    // Prevent overflow at the bottom
    if (top + tooltipHeight > pageHeight) {
      top = event.pageY - tooltipHeight - 10;
    }

    tooltip.style('left', `${left}px`)
      .style('top', `${top}px`);
  }

  /**
   * get the icon for STA based on STA types
   */
  getClientIcon(clientType) {
    const type = clientType?.toLowerCase() || '';

    if (type.includes('ipad')) return'static/icons/ipad.png';
    if (type.includes('iphone')) return 'static/icons/iphone.png';
    if (type.includes('android')) return 'static/icons/android.png';
    if (type.includes('laptop')) return 'static/icons/laptop.png';
    return 'static/icons/android.png';
  }

  /**
   * get the icon for nodes based on node name
   */
  getNodeIcon(nodeName) {
    const type = nodeName?.toLowerCase() || '';

    if (type.includes('controller') || type.includes('agent')) return'static/icons/controller.png';
    return 'static/icons/extender.png';
  }

  seededRandom(seed) {
    let x = Math.sin(seed) * 10000;
    return x - Math.floor(x);
  }

  /**
   * Show tab content
   */
  showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));

    // Remove active class from nav links
    document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));

    // Show selected tab
    const targetTab = document.getElementById(tabName);
    if (targetTab) targetTab.classList.add('active');

    // Add active class to nav link
    const navLink = document.querySelector(`[data-tab="${tabName}"]`);
    if (navLink) navLink.classList.add('active');

    this.currentTab = tabName;

    // Load tab-specific data
    this.loadTabData(tabName);
  }

  /**
   * Load data specific to each tab
   */
  async loadTabData(tabName) {
    switch (tabName) {
      case 'topology':
        const freshTopology = await this.apiCall('/topology');
        await this.updateTopology(freshTopology);
        break;
      case 'performance':
        await this.loadPerformanceData();
        break;
      case 'interference':
        await this.loadInterferenceData();
        break;
      case 'security':
        await this.loadSecurityData();
        break;
      case 'firmware':
        await this.loadFirmwareStatus();
        break;
      case 'reports':
        await this.loadReportsData();
        break;
      case 'settings':
        await this.loadSystemSettings();
        break;
      case 'wireless':
        // hydrate wireless tab when it’s opened
        if (window.WirelessSettings) {
          try {
            await window.WirelessSettings.loadWirelessSettings();
            window.WirelessSettings.updateAllDisplays();
          } catch (e) {
            this.showNotification('Failed to load wireless settings', 'error');
          }
        }
        break;
      case 'policy':
        await this.loadPolicySettings();
        break;
      case 'coverage':
  	if (!window.CoverageMapInstance) {
    	// First time: create the map
    	window.CoverageMapInstance = new CoverageMap();
  	} else {
    	// Next times: refresh data/analysis
    	window.CoverageMapInstance.refreshCoverage();
  	}
  	break;
      default:
        break;
    }
  }

  /**
   * Show device details modal
   */
  showDeviceDetails(device) {
    const modal = document.getElementById('device-modal');
    const title = document.getElementById('device-modal-title');
    const content = document.getElementById('device-modal-content');

    if (!modal || !title || !content) return;

    title.textContent = `${device.vendor} ${device.model}`;
    content.innerHTML = this.generateDeviceDetailsHTML(device);
    modal.classList.add('active');
  }

  /**
   * Generate device details HTML
   */
  generateDeviceDetailsHTML(device) {
    const capabilities = device.capabilities || {};
    const metrics = device.metrics || {};

    return `
      <div class="device-details">
        <div class="detail-section">
          <h3>Basic Information</h3>
          <div class="detail-grid">
            <div class="detail-item"><label>MAC Address:</label><span>${device.mac}</span></div>
            <div class="detail-item"><label>IP Address:</label><span>${device.ip_address}</span></div>
            <div class="detail-item"><label>Role:</label><span>${device.role}</span></div>
            <div class="detail-item"><label>Status:</label><span class="status ${device.status?.toLowerCase?.() || ''}">${device.status}</span></div>
            <div class="detail-item"><label>Uptime:</label><span>${device.uptime}</span></div>
            <div class="detail-item"><label>Firmware:</label><span>${capabilities.firmware || 'Unknown'}</span></div>
          </div>
        </div>

        <div class="detail-section">
          <h3>Performance Metrics</h3>
          <div class="metrics-grid">
            <div class="metric-box"><label>CPU Usage</label><span>${metrics.cpu_usage_percent || 0}%</span></div>
            <div class="metric-box"><label>Memory Usage</label><span>${metrics.memory_usage_percent || 0}%</span></div>
            <div class="metric-box"><label>Temperature</label><span>${metrics.temperature_celsius || 0}°C</span></div>
            <div class="metric-box"><label>Power Usage</label><span>${metrics.power_consumption_watts || 0}W</span></div>
          </div>
        </div>

        <div class="detail-section">
          <h3>Radio Information</h3>
          <div class="radios-list">
            ${this.generateRadioInfoHTML(capabilities.radios || [])}
          </div>
        </div>

        <div class="detail-section">
          <h3>Capabilities</h3>
          <div class="capabilities-grid">
            <div class="capability-item">
              <label>Wi-Fi 7 Support:</label>
              <span class="capability ${capabilities.wifi7_support ? 'supported' : 'not-supported'}">${capabilities.wifi7_support ? 'Yes' : 'No'}</span>
            </div>
            <div class="capability-item">
              <label>Max Mesh Links:</label>
              <span>${capabilities.max_mesh_links || 'Unknown'}</span>
            </div>
            <div class="capability-item">
              <label>Band Steering:</label>
              <span class="capability ${capabilities.steering_capability?.band_steering ? 'supported' : 'not-supported'}">
                ${capabilities.steering_capability?.band_steering ? 'Supported' : 'Not Supported'}
              </span>
            </div>
            <div class="capability-item">
              <label>WPA3 Support:</label>
              <span class="capability ${capabilities.security_capability?.wpa3_sae ? 'supported' : 'not-supported'}">
                ${capabilities.security_capability?.wpa3_sae ? 'Supported' : 'Not Supported'}
              </span>
            </div>
          </div>
        </div>

        <div class="modal-actions">
          <button class="btn btn-secondary" onclick="closeModal('device-modal')">
            <i class="fas fa-times"></i> Close
          </button>
          <button class="btn btn-warning" onclick="window.EasyMeshController.rebootDevice('${device.mac}')">
            <i class="fas fa-power-off"></i> Reboot Device
          </button>
          <button class="btn btn-primary" onclick="window.EasyMeshController.configureDevice('${device.mac}')">
            <i class="fas fa-cog"></i> Configure
          </button>
        </div>
      </div>
    `;
  }

  /**
   * Generate radio information HTML
   */
  generateRadioInfoHTML(radios) {
    return radios.map(radio => `
      <div class="radio-info">
        <div class="radio-header">
          <h4>${radio.band} - ${radio.standard}</h4>
          <span class="channel-info">Ch ${radio.current_channel} (${radio.channel_width}MHz)</span>
        </div>
        <div class="radio-metrics">
          <div class="radio-metric"><label>Max PHY Rate:</label><span>${radio.max_phy_rate_mbps} Mbps</span></div>
          <div class="radio-metric"><label>Spatial Streams:</label><span>${radio.max_spatial_streams}</span></div>
          <div class="radio-metric"><label>TX Power:</label><span>${radio.power_settings?.tx_power_dbm || 0} dBm</span></div>
          <div class="radio-metric"><label>Connected Clients:</label><span>${radio.radio_metrics?.connected_clients || 0}</span></div>
        </div>
      </div>
    `).join('');
  }

  /**
   * Update count badges in navigation
   */
  updateCountBadges() {
    const deviceCount = document.getElementById('device-count');
    const clientCount = document.getElementById('client-count');

    if (deviceCount) deviceCount.textContent = this.devices.length;
    if (clientCount) clientCount.textContent = this.clients.length;
  }

  /**
   * Show/hide loading overlay
   */
  showLoading(show) {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) overlay.classList.toggle('active', show);
  }

  /**
   * Update connection status indicator
   */
  updateConnectionStatus(connected) {
    const indicator = document.getElementById('connection-status');
    if (indicator) {
      const statusText = indicator.querySelector('.status-text');
      if (connected) {
        indicator.className = 'indicator connected';
        if (statusText) statusText.textContent = 'Connected';
      } else {
        indicator.className = 'indicator disconnected';
        if (statusText) statusText.textContent = 'Disconnected';
      }
    }
  }

  /**
   * Show notification
   */
  showNotification(message, type = 'info', duration = 5000) {
    const notification = {
      id: Date.now(),
      message,
      type,
      timestamp: new Date(),
      read: false
    };

    this.notifications.unshift(notification);

    // Limit notifications
    if (this.notifications.length > this.maxNotifications) {
      this.notifications = this.notifications.slice(0, this.maxNotifications);
    }

    this.updateNotificationBadge();
    this.updateNotificationList();

    // Show toast notification
    this.showToastNotification(notification, duration);
  }

  /**
   * Show toast notification
   */
  showToastNotification(notification, duration) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${notification.type}`;
    toast.innerHTML = `
      <div class="toast-content">
        <i class="fas fa-${this.getNotificationIcon(notification.type)}"></i>
        <span>${notification.message}</span>
      </div>
      <button class="toast-close" onclick="window.EasyMeshController.removeToast(this)">
        <i class="fas fa-times"></i>
      </button>
    `;

    // Add to DOM
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
      toastContainer = document.createElement('div');
      toastContainer.id = 'toast-container';
      toastContainer.className = 'toast-container';
      document.body.appendChild(toastContainer);
    }

    toastContainer.appendChild(toast);

    // Auto remove
    setTimeout(() => { if (toast.parentNode) toast.remove(); }, duration);
  }

  /**
   * Get notification icon based on type
   */
  getNotificationIcon(type) {
    const icons = {
      success: 'check-circle',
      warning: 'exclamation-triangle',
      error: 'exclamation-circle',
      info: 'info-circle'
    };
    return icons[type] || icons.info;
  }

  /**
   * Update notification badge
   */
  updateNotificationBadge() {
    const badge = document.querySelector('.notification-badge');
    const unreadCount = this.notifications.filter(n => !n.read).length;

    if (badge) {
      badge.textContent = unreadCount;
      badge.style.display = unreadCount > 0 ? 'flex' : 'none';
    }
  }

  /**
   * Update notification list
   */
  updateNotificationList() {
    const list = document.getElementById('notification-list');
    if (!list) return;

    list.innerHTML = '';

    this.notifications.forEach(notification => {
      const item = document.createElement('div');
      item.className = `notification-item ${notification.type} ${notification.read ? 'read' : 'unread'}`;
      item.innerHTML = `
        <div class="notification-icon">
          <i class="fas fa-${this.getNotificationIcon(notification.type)}"></i>
        </div>
        <div class="notification-content">
          <div class="notification-message">${notification.message}</div>
          <div class="notification-time">${this.formatTimestamp(notification.timestamp)}</div>
        </div>
        <button class="notification-close" onclick="window.EasyMeshController.removeNotification(${notification.id})">
          <i class="fas fa-times"></i>
        </button>
      `;

      item.addEventListener('click', () => {
        this.markNotificationAsRead(notification.id);
      });

      list.appendChild(item);
    });
  }

  // ---------- Utility functions ----------

  updateElement(id, content) {
    const element = document.getElementById(id);
    if (element) element.textContent = content;
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  formatSpeed(mbps) {
    if (mbps >= 1000) return (mbps / 1000).toFixed(1) + ' Gbps';
    return mbps + ' Mbps';
  }

  formatTimestamp(timestamp) {
    const now = new Date();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;

    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;

    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }

  generateTimeLabels(count) {
    const labels = [];
    const now = new Date();

    for (let i = count - 1; i >= 0; i--) {
      const time = new Date(now - i * 5 * 60 * 1000); // 5 minute intervals
      labels.push(time.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }));
    }
    return labels;
  }

  generateRandomData(count, min = 0, max = 100) {
    return Array.from({ length: count }, () =>
      Math.floor(Math.random() * (max - min + 1)) + min
    );
  }

  generateTrafficData(count, multiplier = 1) {
    const baseData = this.generateRandomData(count, 100, 500);
    return baseData.map(value => value * multiplier);
  }

  generateSpectrumData() {
    // Simulate spectrum data for 2.4GHz band
    return Array.from({ length: 83 }, (_, i) => {
      const frequency = 2400 + i;
      let signal = -90 + Math.random() * 20;

      // Simulate peaks at common channels
      if ([2412, 2437, 2462].includes(frequency)) {
        signal += 20 + Math.random() * 15;
      }
      return Math.max(-100, Math.min(-20, signal));
    });
  }

  generate24GHzChannels() {
    const channels = [];
    for (let i = 2400; i <= 2483; i++) channels.push(i);
    return channels;
  }

  getDeviceClientCount(deviceMac) {
    return this.clients.filter(client =>
      client.connected_ap_mac === deviceMac
    ).length;
  }

  isClientActive(client) {
    if (!client.last_activity) return false;
    const lastActivity = new Date(client.last_activity);
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    return lastActivity > fiveMinutesAgo;
  }

  getSignalStrengthIcon(rssi) {
    if (rssi >= -50) return '📶📶📶📶';
    if (rssi >= -60) return '📶📶📶';
    if (rssi >= -70) return '📶📶';
    return '📶';
  }

  createSignalBars(rssi) {
    const bars = [];
    const strength = Math.max(0, Math.min(4, Math.floor((rssi + 100) / 12.5)));
    for (let i = 0; i < 4; i++) {
      bars.push(`<div class="signal-bar ${i < strength ? 'active' : ''}"></div>`);
    }
    return `<div class="signal-bars">${bars.join('')}</div>`;
  }

  getDeviceTypeIcon(deviceType) {
    const icons = {
      smartphone: 'mobile-alt',
      laptop: 'laptop',
      tablet: 'tablet-alt',
      'smart-tv': 'tv',
      'gaming-console': 'gamepad',
      'iot-device': 'home',
      default: 'device'
    };
    return icons[deviceType] || icons.default;
  }

  getClientConnectionInfo(client) {
    // Standardize on connected_ap_mac
    const device = this.devices.find(d => d.mac === client.connected_ap_mac);
    return {
      ap: device ? device.model : 'Unknown AP',
      band: client.connected_bssid ? this.getBandFromBSSID(client.connected_bssid) : 'Unknown'
    };
  }

  getBandFromBSSID(bssid) {
    // Simple heuristic; replace with real mapping as needed
    const lastOctet = parseInt(bssid.split(':').pop(), 16);
    if (Number.isNaN(lastOctet)) return 'Unknown';
    if (lastOctet % 3 === 0) return '2.4GHz';
    if (lastOctet % 3 === 1) return '5GHz';
    return '6GHz';
  }

  // ---------- Timers & lifecycle ----------

  startRefreshTimers() {
    // Refresh dashboard every 10 seconds
    this.refreshIntervals.dashboard = setInterval(() => {
      if (this.currentTab === 'dashboard') this.updateDashboard();
    }, 10000);

    // Refresh charts every 30 seconds
    this.refreshIntervals.charts = setInterval(() => {
      this.updateAllCharts();
    }, 30000);

    // Refresh topology every 60 seconds
    this.refreshIntervals.topology = setInterval(async () => {
      if (this.currentTab === 'topology') {
        try {
          const response = await this.apiCall('/topology');
          this.topology = response;
          this.updateTopologyVisualization();
        } catch (error) {
          console.error('Failed to refresh topology:', error);
          this.showNotification('Failed to refresh topology', 'error');
        }
      }
    }, 60000);
  }

  cleanup() {
    // Clear intervals
    Object.values(this.refreshIntervals).forEach(interval => clearInterval(interval));

    // Close WebSocket
    if (this.wsConnection) this.wsConnection.close();

    // Destroy charts
    Object.values(this.charts).forEach(chart => {
      if (chart && typeof chart.destroy === 'function') chart.destroy();
    });
  }

  // ---------- SAFETY STUBS & CORE HELPERS (added) ----------

  // Keyboard shortcuts example
  handleKeyboardShortcuts(e) {
    const isMac = navigator.platform.toUpperCase().includes('MAC');
    const mod = isMac ? e.metaKey : e.ctrlKey;
    if (mod && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      document.getElementById('global-search')?.focus();
    }
  }

  // WebSocket metrics handler: store & refresh charts/dashboard
  updateMetrics(metrics = {}) {
    const m = this.performanceMetrics;
    const push = (arr, v, max = 200) => { arr.push(v); if (arr.length > max) arr.shift(); };

    if (typeof metrics.throughput === 'number') push(m.throughput, metrics.throughput);
    if (typeof metrics.latency === 'number') push(m.latency, metrics.latency);
    if (typeof metrics.utilization === 'number') push(m.utilization, metrics.utilization);
    if (typeof metrics.clients === 'number') push(m.clients, metrics.clients);

    this.updatePerformanceCharts?.();
    if (this.currentTab === 'dashboard') this.updateDashboard();
  }

  // Network health helpers
  getAverageThroughput() {
    const t = this.performanceMetrics.throughput;
    if (!t.length) return 0;
    return t.reduce((a, b) => a + b, 0) / t.length; // Mbps
  }

  getAverageInterference() {
    const u = this.performanceMetrics.utilization;
    if (!u.length) return 0.2; // mild default
    const avgU = u.reduce((a, b) => a + b, 0) / u.length; // 0-100
    return Math.max(0, Math.min(1, avgU / 100)); // normalize
  }

  getSecurityHealth() {
    const recent = this.securityEvents.slice(0, 5);
    const penalty = recent.length * 1.5; // 1.5 points per recent event
    return Math.max(0, 10 - penalty);
  }

  // Dashboard helpers
  updateHealthIndicators() {
    const scoreEl = document.getElementById('health-score-display');
    const ring = document.getElementById('health-score-ring'); // optional ring element
    if (!scoreEl) return;
    const score = parseInt(scoreEl.textContent || '0', 10);
    const cls = score >= 80 ? 'good' : score >= 60 ? 'fair' : 'poor';
    scoreEl.parentElement?.classList?.remove('good', 'fair', 'poor');
    scoreEl.parentElement?.classList?.add(cls);
    if (ring) ring.style.setProperty('--progress', `${score}`);
  }

  updateOptimizationSuggestions() {
    const box = document.getElementById('optimization-suggestions');
    if (!box) return;
    const suggestions = [];
    if (this.getAverageThroughput() < 200) suggestions.push('Enable band steering for congested APs.');
    if (this.getAverageInterference() > 0.6) suggestions.push('High interference — try auto channel optimization.');
    if (!suggestions.length) suggestions.push('Network looks good. No action needed.');
    box.innerHTML = suggestions.map(s => `<li>${s}</li>`).join('');
  }

  updateQuickStatusCards() {
    // implement as needed
  }

  updateTrafficChart() {
    const chart = this.charts?.traffic;
    if (!chart) return;
    chart.data.labels = this.generateTimeLabels(12);
    chart.data.datasets[0].data = this.generateTrafficData(12);
    chart.data.datasets[1].data = this.generateTrafficData(12, 2);
    chart.update();
  }

  resizeCharts() {
    Object.values(this.charts).forEach(ch => ch?.resize?.());
  }

  updateAllCharts() {
    this.updateTrafficChart();
    Object.entries(this.charts).forEach(([k, ch]) => { if (k !== 'traffic') ch?.update?.(); });
  }

  refreshDashboard() { this.updateAllDisplays(); }
  optimizeNetwork() {
    this.showNotification('Running optimization…', 'info');
    setTimeout(() => this.showNotification('Optimization complete', 'success'), 1000);
  }

  setTimeRange(_range) { /* hook up filtering if needed */ }
  setBand(_band) { /* hook up band switch if needed */ }
  showSettingsSection(_id) { /* show a sub-section in settings */ }
  closeAllModals() { document.querySelectorAll('.modal.active').forEach(m => m.classList.remove('active')); }

  updateDevice(device) {
    if (!device?.mac) return;
    const i = this.devices.findIndex(d => d.mac === device.mac);
    if (i >= 0) this.devices[i] = { ...this.devices[i], ...device };
    else this.devices.push(device);
    this.updateAllDisplays();
  }

  updateClient(client) {
    if (!client?.mac) return;
    const i = this.clients.findIndex(c => c.mac === client.mac);
    if (i >= 0) this.clients[i] = { ...this.clients[i], ...client };
    else this.clients.push(client);
    this.updateAllDisplays();
  }

  handleSecurityEvent(event) {
    this.securityEvents.unshift(event);
    this.showNotification(event?.message || 'Security event', 'warning');
    this.updateSecurityCenter?.();
  }

  async updateTopology(newTopo) {
    console.log('Fetching fresh topology from backend...');
    this.topology = newTopo || {};
    if (this.currentTab === 'topology') this.updateTopologyVisualization();
  }

  markNotificationAsRead(id) {
    const n = this.notifications.find(n => n.id === id);
    if (n) n.read = true;
    this.updateNotificationBadge();
    this.updateNotificationList();
  }

  removeNotification(id) {
    this.notifications = this.notifications.filter(n => n.id !== id);
    this.updateNotificationBadge();
    this.updateNotificationList();
  }

  removeToast(btnEl) {
    const toast = btnEl?.closest?.('.toast');
    toast?.remove();
  }

  updateSecurityCenter() { /* fill UI if present */ }
  updatePerformanceCharts() { /* optionally refresh specific charts */ }

  rebootDevice(mac) {
    this.showNotification(`Reboot command sent to ${mac}`, 'info');
    // Optionally: return this.apiCall(`/devices/${mac}/reboot`, { method: 'POST' })
  }
  configureDevice(mac) {
    this.showNotification(`Open configuration for ${mac}`, 'info');
  }
  showClientDetails(mac) {
    const client = this.clients.find(c => c.mac === mac);
    if (!client) {
      this.showNotification(`Client not found: ${mac}`, 'error');
      return;
    }
    
    if (!this.clientDetailsViewer) {
      this.clientDetailsViewer = new ClientDetailsViewer();
    }
    
    this.clientDetailsViewer.show(client);
  }
  disconnectClient(mac) {
    this.showNotification(`Disconnect requested for ${mac}`, 'warning');
  }
  blockClient(mac) {
    this.showNotification(`Block requested for ${mac}`, 'warning');
  }

  /**
   * Load wifi reset default config
   */
  async loadWifiResetConfig() {
    try {
      const res = await fetch("/api/v1/wifireset");

      if (!res.ok) {
        throw new Error(`HTTP error! Status: ${res.status}`);
      }

      const data = await res.json();
      if (!Array.isArray(data?.options) || !Array.isArray(data?.ssidHaulConfig)) {
        this.showNotification("Could not received the wifi reset tree from controller, \nPlease check the controller or try again after sometime.");
        return;
      }

      const select = document.getElementById("almac-select");
      select.innerHTML = '<option value="">Choose AL MAC Address</option>';

      data.options.forEach(mac => {
        const option = document.createElement("option");
        option.value = mac;
        option.textContent = mac;
        // parse only the AL MAC
        const alMac = mac.split(" ")[0];
        if (alMac === data.selectedOption) {
          option.selected = true;
        }
        select.appendChild(option);
      });

      // Add "Other" option
      const otherOption = document.createElement("option");
      otherOption.value = "Other";
      otherOption.textContent = "Other (Enter manually)";
      select.appendChild(otherOption);

      // Manual MAC input toggle
      const manualMacContainer = document.getElementById("manual-almac-container");
      if (select && manualMacContainer) {
        select.addEventListener("change", function () {
          const isOtherSelected = this.value === "Other";
          manualMacContainer.style.display = isOtherSelected ? "block" : "none";

          const manualInput = document.getElementById("manual-almac");
          if (!isOtherSelected && manualInput) {
            manualInput.value = "";
          }
        });

        // Trigger change event in case "Other" is pre-selected
        const event = new Event("change");
        select.dispatchEvent(event);
      }

      // Populate HaulType dropdown
      const haulContainer = document.getElementById("haultype-options");
      haulContainer.innerHTML = ""; // Clear previous content

      const haulTypes = new Set();
      data.ssidHaulConfig.forEach(config => {
        const haul = config.HaulType;
        if (typeof haul === "string") {
          haulTypes.add(haul);
        }
      });

      haulTypes.forEach(ht => {
        const match = data.ssidHaulConfig.find(config => config.HaulType === ht);

        // Create a grid container for each HaulType block
        const gridWrapper = document.createElement("div");
        gridWrapper.className = "haul-block";

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.id = `haul-${ht}`;
        checkbox.name = "haulType";
        checkbox.value = ht;

        const label = document.createElement("label");
        label.htmlFor = checkbox.id;
        label.textContent = ht;

        const checkboxWrapper = document.createElement("div");
        checkboxWrapper.className = "haul-checkbox"
        checkboxWrapper.appendChild(checkbox);
        checkboxWrapper.appendChild(label);

        gridWrapper.appendChild(checkboxWrapper);
        haulContainer.appendChild(gridWrapper);

        // Add event listener to show SSID and password fields
        checkbox.addEventListener("change", () => {
          const existingFields = document.getElementById(`ssid-fields-${ht}`);

          if (checkbox.checked) {
            if (match && !existingFields) {
              const fieldWrapper = document.createElement("div");
              fieldWrapper.id = `ssid-fields-${ht}`;
              fieldWrapper.className = "haul-fields";

              // SSID row
              const ssidRow = document.createElement("div");
              ssidRow.className = "ssid-password-row";

              const ssidLabel = document.createElement("label");
              ssidLabel.textContent = "SSID:";
              ssidLabel.setAttribute("for", `ssid-${ht}`);

              const ssidInput = document.createElement("input");
              ssidInput.type = "text";
              ssidInput.id = `ssid-${ht}`;
              ssidInput.value = match.SSID || "";
              ssidInput.placeholder = "Enter SSID";

              ssidRow.appendChild(ssidLabel);
              ssidRow.appendChild(ssidInput);

              // Password row
              const passRow = document.createElement("div");
              passRow.className = "ssid-password-row";

              const passLabel = document.createElement("label");
              passLabel.textContent = "Password:";
              passLabel.setAttribute("for", `password-${ht}`);

              const passInput = document.createElement("input");
              passInput.type = "text";
              passInput.id = `password-${ht}`;
              passInput.value = match.PassPhrase || "";
              passInput.placeholder = "Enter Password";

              passRow.appendChild(passLabel);
              passRow.appendChild(passInput);

              // Append rows to wrapper
              fieldWrapper.appendChild(ssidRow);
              fieldWrapper.appendChild(passRow);
              gridWrapper.appendChild(fieldWrapper);
            }
          } else {
            // Remove SSID/password fields if unchecked
            if (existingFields) {
              gridWrapper.removeChild(existingFields);
            }
          }
        });
      });
    } catch (err) {
      console.error("Failed to load Wi-Fi interfaces:", err);
      this.showNotification("Failed to load Wi-Fi interfaces", "error");
    }
  }

  /**
   * Load wifi policy config
   */
  async loadWifiPolicyConfig() {
    try {
      const res = await fetch("/api/v1/wifipolicy");
      if (!res.ok) {
        throw new Error(`HTTP error! Status: ${res.status}`);
      }

      const data = await res.json();
      this.policyByDeviceId = {};
      this.updatedPolicySettings = Array.isArray(data?.policyConfig) ? data.policyConfig : [];
      this.updatedPolicySettings.forEach(d => {
        if (d?.id) this.policyByDeviceId[d.id] = d;
      });

      // Populate selector UI
      populateDeviceSelectorFromPolicy(data);

      // Auto-select first device and populate
      const sel = document.querySelector("#device-selector");
      if (sel && sel.options.length > 0) {
        sel.selectedIndex = 0;
        const firstId = sel.value;
        const policy = this.policyByDeviceId[firstId];
        populatePolicyUI(policy);
      }

    } catch (err) {
      console.error("Failed to load Wi-Fi policy settings:", err);
      this.showNotification("Failed to load policy settings", "error");
    }
  }

  // ---- Tab-specific loaders (safe stubs) ----
  async loadPerformanceData() { 
    // Update statistics cards
    this.updatePerformanceStats();
    
    // Initialize client performance monitor when performance tab is shown
    if (!this.clientPerformanceMonitor) {
      this.clientPerformanceMonitor = new ClientPerformanceMonitor(this.clients, this.devices);
      await this.clientPerformanceMonitor.init();
    } else {
      this.clientPerformanceMonitor.updateClients(this.clients, this.devices);
    }
    
    // Populate device sections for client selection (P2/P3 design)
    this.updatePerformanceDevices();
  }

  /**
   * Update performance statistics cards
   */
  updatePerformanceStats() {
    // Active Devices
    const activeDevices = this.devices.filter(d => d.status === 'Online').length;
    const totalDevices = this.devices.length;
    this.updateElement('perf-active-devices', `${activeDevices}/${totalDevices}`);
    
    // Connected Clients
    const connectedClients = this.clients.length;
    this.updateElement('perf-connected-clients', connectedClients);
    
    // Active Alarms (placeholder - would need real alarm data)
    this.updateElement('perf-active-alarms', '0');
    
    // Network Health
    const healthScore = this.calculateNetworkHealth();
    this.updateElement('perf-network-health', `${Math.round(healthScore)}%`);
  }
  async loadInterferenceData() { /* fetch & update interference tab */ }
  async loadSecurityData() { /* fetch & update security tab */ }
  async loadFirmwareStatus() { /* fetch & update firmware tab */ }
  async loadReportsData() { /* fetch & update reports tab */ }
  async loadSystemSettings() {
      try {
        // Fetch and update system settings here
        console.log("🔧 Loading system settings...");

        // Load Wi-Fi AL MAC interfaces when settings tab is opened
        if (typeof this.loadWifiResetConfig === 'function') {
          console.log("Loading Wi-Fi Reset config");
          await this.loadWifiResetConfig();
        }
      } catch (err) {
        console.error("Failed to load system settings:", err);
        this.showNotification("Failed to load system settings", "error");
      }
  }
  async loadPolicySettings() {
    try {
        // Fetch and update Policy settings here
        console.log("🔧 Loading Policy settings...");

        // Load Wi-Fi AL MAC interfaces when settings tab is opened
        if (typeof this.loadWifiPolicyConfig === 'function') {
          console.log("Loading Wi-Fi policy config");
          await this.loadWifiPolicyConfig();
        }
      } catch (err) {
        console.error("Failed to load system settings:", err);
        this.showNotification("Failed to load system settings", "error");
    }

  }
}

/**
  * show all the available device list for wifi policy config
  */
function populateDeviceSelectorFromPolicy(data) {
  const sel = document.querySelector("#device-selector");
  if (!sel) return;

  // clear existing
  sel.innerHTML = "";

  const items = Array.isArray(data?.policyConfig) ? data.policyConfig : [];

  if (items.length === 0) {
    // Add a disabled placeholder when nothing returned
    const opt = document.createElement("option");
    opt.textContent = "No devices";
    opt.disabled = true;
    opt.selected = true;
    sel.appendChild(opt);
    return;
  }

  items.forEach(({ id, mediaType }) => {
    if (!id) return;
    const opt = document.createElement("option");
    opt.value = id;
    opt.textContent = mediaType ? `${id} (${mediaType})` : id;
    sel.appendChild(opt);
  });
}

/**
 * Load wifi policy config for seected device
 */
function populatePolicyUI(policy) {
  if (!policy) return;

  // AP Metrics Reporting Policy
  const ap = policy.apMetricReportingPolicy || {};
  setInputValue("#ap-interval", ap.interval);
  setInputValue("#managed-client-marker", ap.managedClientMarker);

  // Local / BTM Disallowed
  fillMacTable("#localMacBody", policy.localSteeringDisallowed);
  fillMacTable("#btmMacBody",   policy.btmSteeringDisallowed);

  // Channel Scan Reporting
  setInputValue("#report-independent-scans", policy.reportIndependentChannelScans);

  // Default 802.1Q Settings
  const dot1q = policy.default802_1Q_SettingsPolicy || {};
  setInputValue("#primary-vlan-id", dot1q.primaryVLANID);
  setInputValue("#default-pcp", dot1q.defaultPCP);

  // Radio Specific Metrics (table)
  const rmpEntries = getRadioMetricsEntries(policy);
  RMP.render(rmpEntries);
  RMP.bind();

  // Radio Steering Parameters (table)
  const rspEntries = getRadioSteeringEntries(policy);
  RSP.render(rspEntries);
  RSP.bind();
}

// RMP entries (array or single legacy object)
function getRadioMetricsEntries(policy) {
  const radioMetricList = policy?.radioSpecificMetricsPolicy;
  if (Array.isArray(radioMetricList) && radioMetricList.length) {
    const norm = (RMP?.normalizeRow) || (x => x);
    return radioMetricList.map(norm).filter(Boolean);
  }
  return [];
}

// RSP entries (existing logic kept)
function getRadioSteeringEntries(policy) {
  const radioSteeringlist = policy?.radioSteeringParametersPolicy;
  if (Array.isArray(radioSteeringlist) && radioSteeringlist.length) {
    const norm = (RSP?.normalizeRow) || (x => x);
    return radioSteeringlist.map(norm).filter(Boolean);
  }
  return [];
}

// utilities for policy tables
const PolicyUtil = (() => {
  const MAC_ALL = "ff:ff:ff:ff:ff:ff";

  const qs  = (s, r = document) => r.querySelector(s);
  const qsa = (s, r = document) => Array.from(r.querySelectorAll(s));

  // Validators
  const hasText = v => typeof v === "string" && v.trim() !== "";
  const hasNumber = v => Number.isFinite(Number(v));
  const clamp = (n, min, max) => Math.max(min, Math.min(max, n));
  const numOrNull = (v, min, max) => {
    const n = Number(v);
    return Number.isFinite(n) ? clamp(n, min, max) : null;
  };

  // MAC helpers
  const normalizeId = (idLike) => {
    const raw = String(idLike || "").trim().toLowerCase();
    return raw === "all stations" ? MAC_ALL : raw;
  };
  const displayId = (id) => normalizeId(id) === MAC_ALL ? "All Stations" : String(id || "").trim().toLowerCase();

  // Presence gate (for legacy single-object policy)
  function hasAnyRadioMetrics(r) {
    if (!r) return false;
    return (
      hasText(r.id) || hasNumber(r.starCPIThreshold) ||hasNumber(r.starCPIHysteresis) ||
      hasNumber(r.apUtilizationThreshold) || hasNumber(r.apUtilization) ||
      hasNumber(r.staTrafficStats) || hasNumber(r.staLinkMetrics) || hasNumber(r.staStatus)
    );
  }

  // Binary toggle normalize
  const toBin = (v) =>
    (v === true || v === 1 || v === "1" || v === "enabled" || v === "Enabled") ? "1" : "0";

  return {
    MAC_ALL, qs, qsa, hasText, hasNumber, clamp, numOrNull,
    normalizeId, displayId, hasAnyRadioMetrics, toBin
  };
})();

// create Policy Table
function createPolicyTable({
  tbodySel,
  addBtnSel,
  maxRows = 15,
  specialId = { enabled: false,
                macAll: PolicyUtil.MAC_ALL },
  columns,
  normalizeRow,
  readonlyExistingId = true
}) {
  const { qs, qsa, displayId, normalizeId } = PolicyUtil;

  function getCurrentIds() {
    return qsa(`${tbodySel} tr`).map(tr => {
      const input = tr.querySelector('input[name="id"]');
      if (!input) return "";
      let v = (input.value || "").trim().toLowerCase();
      if (v === "all stations") v = PolicyUtil.MAC_ALL;
      return v;
    }).filter(Boolean);
  }

  function hasAllRow() {
    return specialId.enabled && getCurrentIds().includes(specialId.macAll);
  }

  function rowCount() {
    return qsa(`${tbodySel} tr`).length;
  }

  function canAddRow() {
    if (maxRows != null && rowCount() >= maxRows) return false;
    if (specialId.enabled && hasAllRow()) return false;
    return true;
  }

  function updateAddButtonState() {
    const addBtn = qs(addBtnSel);
    if (!addBtn) return;
    const allowed = canAddRow();
    addBtn.disabled = !allowed;
    addBtn.title = allowed ? "" :
      (hasAllRow()
        ? 'Cannot add more rows while "All Stations" row exists. Delete it to add new rows.'
        : `Maximum ${maxRows} rows allowed.`);
  }

  function createIdInput(value, editable) {
    const raw = normalizeId(value);
    const shown = displayId(raw);
    const attrs = [
      'type="text"',
      'name="id"',
      'inputmode="text"',
      'placeholder="MAC or All Stations"',
      // Keep pattern; since readonly for existing rows, it won't block submit
      'pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"',
      'title="Format: 6 octets, colon-separated (e.g., AA:BB:CC:DD:EE:FF)"',
      `value="${shown}"`,
      `data-raw-id="${raw}"`,
      editable ? '' : 'readonly'
    ].filter(Boolean).join(' ');
    return `<input ${attrs} />`;
  }

  function createRow(entry, { editableId = false } = {}) {
    const e = normalizeRow(entry || {});
    const idCell = createIdInput(e.id, editableId);
    const tds = [`<td>${idCell}</td>`];

    for (const col of columns) {
      if (col.type === "number") {
        const v = (e[col.field ?? col.key] == null ? "" : String(e[col.field ?? col.key]));
        tds.push(
          `<td><input type="number" name="${col.name}" min="${col.min}" max="${col.max}" step="${col.step || 1}" placeholder="${col.min}-${col.max}" value="${v}" /></td>`
        );
      } else if (col.type === "select") {
        const v = String(e[col.field ?? col.key] ?? (col.default ?? "0"));
        const opts = col.options.map(([val, label]) =>
          `<option value="${val}" ${v === String(val) ? "selected" : ""}>${label}</option>`
        ).join("");
        tds.push(`<td><select name="${col.name}">${opts}</select></td>`);
      }
    }

    tds.push(`<td style="text-align:right;"><button type="button" class="btn btn-outline btn-sm remove-row">Delete</button></td>`);
    const tr = document.createElement("tr");
    tr.innerHTML = tds.join("");
    return tr;
  }

  // --- Ephemeral scope chooser shown only for newly added rows ---
  function attachNewEntryScopeChooser(tr) {
    const idCell = tr.querySelector('td');
    const idInput = tr.querySelector('input[name="id"]');
    if (!idCell || !idInput) return;

    // Hide the ID input until user chooses scope
    idInput.style.display = 'none';

    // Build a one-time <select>
    const sel = document.createElement('select');
    sel.className = 'new-entry-scope';
    sel.innerHTML = `
      <option value="" selected disabled>Select scope…</option>
      <option value="specific">Specific Station</option>
      <option value="all">All Stations</option>
    `;

    // Insert before the input
    idCell.insertBefore(sel, idInput);

    const finalize = (scope) => {
      if (scope === 'all') {
        // Set ALL MAC and lock field
        idInput.value = displayId(specialId.macAll);
        idInput.setAttribute('data-raw-id', specialId.macAll);
        idInput.readOnly = true;
      } else {
        // Allow editing specific MAC
        idInput.readOnly = false;
        idInput.value = '';
        idInput.setAttribute('data-raw-id', '');
        // Focus for convenience
        queueMicrotask(() => { idInput.focus(); idInput.select?.(); });
      }
      // Remove chooser and show input
      sel.remove();
      idInput.style.display = '';
      // Update add button state (ALL disables further adds)
      updateAddButtonState();
    };

    sel.addEventListener('change', () => {
      const v = sel.value;
      if (v === 'all' || v === 'specific') {
        finalize(v);
      }
    });
  }
  // --- End ephemeral chooser ---

  function render(entries = []) {
    const tbody = qs(tbodySel);
    if (!tbody) return;

    // Dedup special 'All Stations' (first wins)
    let seenAll = false;
    const safe = [];
    for (const e of entries) {
      const id = normalizeId(e?.ID ?? e?.id ?? "");
      if (specialId.enabled && id === specialId.macAll) {
        if (seenAll) continue;
        seenAll = true;
      }
      safe.push(e);
    }

    const data = safe.length ? safe : [normalizeRow({ ID: "" })];

    tbody.innerHTML = "";
    for (const e of data) {
      tbody.appendChild(createRow(e, { editableId: !readonlyExistingId }));
    }
    updateAddButtonState();
  }

  function addRow(prefill) {
    if (!canAddRow()) {
      updateAddButtonState();
      return;
    }
    const tbody = qs(tbodySel);
    if (!tbody) return;
    const tr = createRow(prefill || {}, { editableId: true });
    tbody.appendChild(tr);
    //const idInput = tr.querySelector('input[name="id"]');
    //if (idInput) { idInput.focus(); idInput.select?.(); }
    // Show one-time scope chooser for this new row
    attachNewEntryScopeChooser(tr);
    updateAddButtonState();
  }

  function getAll() {
    const rows = qsa(`${tbodySel} tr`);
    return rows.map(tr => {
      let id = tr.querySelector('input[name="id"]')?.value?.trim().toLowerCase() || "";
      if (id === "all stations") id = PolicyUtil.MAC_ALL;

      const out = { id };
      for (const col of columns) {
        if (col.type === "number") {
          const v = tr.querySelector(`input[name="${col.name}"]`)?.value ?? "";
          out[col.field || col.key] = v === "" ? null : Number(v);
        } else if (col.type === "select") {
          const v = tr.querySelector(`select[name="${col.name}"]`)?.value ?? (col.default ?? "0");
          out[col.field || col.key] = v === "" ? null : Number(v);
        }
      }
      return out;
    });
  }

  function bind() {
    const addBtn = qs(addBtnSel);
    const tbody  = qs(tbodySel);

    if (addBtn && !addBtn._boundPolicyTable) {
      addBtn.addEventListener("click", () => addRow());
      addBtn._boundPolicyTable = true;
    }

    if (tbody && !tbody._boundPolicyTable) {
      tbody.addEventListener("click", (evt) => {
        const btn = evt.target.closest(".remove-row");
        if (btn) {
          btn.closest("tr")?.remove();
          updateAddButtonState();
        }
      });

      // Keep constraints in sync when editing ID (for special "All Stations" rule)
      tbody.addEventListener("input", (evt) => {
        const input = evt.target;
        if (!(input instanceof HTMLInputElement) || input.name !== "id") return;
        let v = (input.value || "").trim().toLowerCase();
        if (v === "all stations") v = PolicyUtil.MAC_ALL;
        input.setAttribute("data-raw-id", v);
        updateAddButtonState();
      });

      tbody._boundPolicyTable = true;
    }

    updateAddButtonState();
  }

  return { render, addRow, bind, getAll };
}

// ==============================
// RSP (uses All Stations max-1 rule, max 3 rows)
// ==============================
const RSP = (() => {
  const mod = createPolicyTable({
    tbodySel: "#policy-rows",
    addBtnSel: "#add-row-btn",
    maxRows: 15,
    specialId: { enabled: true, macAll: PolicyUtil.MAC_ALL },
    readonlyExistingId: true,
    columns: [
      { type: "number", name: "steering", key: "Steering Policy", field: "steeringPolicy", min: 0, max: 2, step: 1 },
      { type: "number", name: "util",     key: "Utilization Threshold", field: "utilizationThreshold", min: 0, max: 255, step: 1 },
      { type: "number", name: "rcpi",     key: "RCPI Threshold", field: "rcpiThreshold", min: 0, max: 220, step: 1 }
    ],
    normalizeRow(e = {}) {
      const id = (e.id ?? "").trim().toLowerCase();
      return {
        id,
        steeringPolicy: e.steeringPolicy??null,
        utilizationThreshold: e.utilizationThreshold??null,
        rcpiThreshold: e.rcpiThreshold?? null

      };
    }
  });
  return mod;
})();

// ==============================
// RMP (uses All Stations max-1 rule, max 3 rows)
// ==============================
const RMP = (() => {
  const { numOrNull, toBin } = PolicyUtil;

  const mod = createPolicyTable({
    tbodySel: "#radio-metrics-rows",
    addBtnSel: "#add-radio-metrics-row",
    maxRows: 15,
    specialId: { enabled: true, macAll: PolicyUtil.MAC_ALL },
    readonlyExistingId: true,
    columns: [
      { type: "number", name: "rcpiThreshold",  key: "STA RCPI Threshold", field: "starCPIThreshold", min: 0, max: 220, step: 1 },
      { type: "number", name: "rcpiHysteresis", key: "STA RCPI Hysteresis", field: "starCPIHysteresis", min: 0, max: 100, step: 1 },
      { type: "number", name: "apUtilization", key: "AP Utilization Threshold", field: "apUtilizationThreshold", min: 0, max: 255, step: 1 },
      { type: "select", name: "staTrafficStats", key: "STA Traffic Stats", field: "staTrafficStats", options: [["0","Disabled"],["1","Enabled"]], default: "0" },
      { type: "select", name: "staLinkMetrics", key: "STA Link Metrics", field: "staLinkMetrics", options: [["0","Disabled"],["1","Enabled"]], default: "0" },
      { type: "select", name: "staStatus", key: "STA Status", field: "staStatus", options: [["0","Disabled"],["1","Enabled"]], default: "0" }
    ],
    normalizeRow(e = {}) {
      const id = PolicyUtil.normalizeId(e.ID ?? e.id ?? e.bssid ?? "");
      const rcpiThr = (e["STA RCPI Threshold"] ?? e.staRCPIThreshold ?? e.starCPIThreshold ?? null);
      const rcpiHys = (e["STA RCPI Hysteresis"] ?? e.staRCPIHysteresis ?? e.starCPIHysteresis ?? null);
      const apUtil  = (e["AP Utilization Threshold"] ?? e.apUtilizationThreshold ?? e.apUtilization ?? null);
      return {
        id: id,
        starCPIThreshold: numOrNull(rcpiThr, 0, 220),
        starCPIHysteresis: numOrNull(rcpiHys, 0, 100),
        apUtilizationThreshold: numOrNull(apUtil, 0, 255),
        staTrafficStats: toBin(e["STA Traffic Stats"] ?? e.staTrafficStats),
        staLinkMetrics: toBin(e["STA Link Metrics"] ?? e.staLinkMetrics),
        staStatus: toBin(e["STA Status"] ?? e.staStatus)
      };
    }
  });
  return mod;
})();

function setInputValue(selector, value, fallback = "") {
  const el = document.querySelector(selector);
  if (!el) return;
  const vs = String(value ?? fallback);
  const SPECIAL_MAC = PolicyUtil.MAC_ALL;
  const isBssid = el.id === "bssid" || el.name === "bssid";

  if (el.tagName === "SELECT") {
    const exists = Array.from(el.options).some(o => o.value == vs);
    el.value = exists ? vs : String(fallback);
  } else {
    if (isBssid && vs.toLowerCase() === SPECIAL_MAC) {
      el.value = "All Stations";
      el.setAttribute("data-actual-value", SPECIAL_MAC);
    } else {
      el.value = vs;
      el.removeAttribute("data-actual-value");
    }
  }
}

function fillMacTable(tbodySel, macArray) {
  const tbody = document.querySelector(tbodySel);
  if (!tbody) return;
  tbody.innerHTML = "";

  const arr = Array.isArray(macArray) && macArray.length ? macArray : [];
  arr.forEach((m) => {
    const mac = String(m || "").trim().toLowerCase();
    if (!mac) return;

    const tr = document.createElement("tr");
    tr.dataset.mac = mac;

    const tdCheckbox = document.createElement("td");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.className = "row-select";
    cb.setAttribute("aria-label", `Select ${mac}`);
    tdCheckbox.appendChild(cb);

    const tdMac = document.createElement("td");
    tdMac.textContent = mac;

    tr.appendChild(tdCheckbox);
    tr.appendChild(tdMac);
    tbody.appendChild(tr);
  });
}

function sectionMap(sectionKey) {
  // Maps data-section to the radio group's name attribute
  switch (sectionKey) {
    case "ap-metrics":        return "applyScope-ap";
    case "local-disallowed":  return "applyScope-local";
    case "btm-disallowed":    return "applyScope-btm";
    case "channel-scan":      return "applyScope-scan";
    case "dot1q-defaults":    return "applyScope-dot1q";
    case "radio-metrics":     return "applyScope-radio";
    case "radio-steering":    return "applyScope-steer";
    default:                  return "";
  }
}

function getMacList(tbodySelector) {
  const tbody = document.querySelector(tbodySelector);
  if (!tbody) return [];
  return Array.from(tbody.querySelectorAll('tr[data-mac]'))
    .map(tr => (tr.dataset.mac || "").trim().toLowerCase())
    .filter(Boolean);
}


  function collectResetPayload() {
    const select = document.getElementById("almac-select");
    const manualInput = document.getElementById("manual-almac");

    let selectedMac = select.value;

    if (selectedMac === "Other") {
      selectedMac = manualInput.value.trim();
      if (!selectedMac) {
        alert("Please enter a valid AL MAC address.");
        throw new Error("Manual AL MAC address is required.");
      }
    }


    const haulTypes = Array.from(document.querySelectorAll("input[name='haulType']:checked")).map(checkbox => {
      const haulType = checkbox.value;
      const ssid = document.getElementById(`ssid-${haulType}`)?.value || "";
      const password = document.getElementById(`password-${haulType}`)?.value || "";

      return {
        HaulType: haulType,
        SSID: ssid,
        PassPhrase: password
      };
    });

    return { selectedMac, haulTypes };
  }

  async function sendResetPayload(payload) {
    const res = await fetch("/api/v1/wifireset", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(errorText);
    }

    return await res.json();
  }

  async function handleResetSuccess(response) {
    console.log("Reset result:", response);
    alert("Wi-Fi configuration reset successfully!");
  }

  async function handleResetError(error) {
    console.error("Reset failed:", error);
    alert(`Failed to reset Wi-Fi configuration:\n${error.message}`);
  }



/**
 * Client Details Viewer Class
 * Shows detailed performance metrics for a single client in a modal
 */
class ClientDetailsViewer {
  constructor() {
    this.chart = null;
    this.currentClient = null;
    this.colors = {
      score: '#6366f1',
      snr: '#10b981',
      pr: '#f59e0b',
      per: '#ef4444',
      psy: '#8b5cf6'
    };
  }
  
  show(client) {
    this.currentClient = client;
    const modal = document.getElementById('client-details-modal');
    if (!modal) return;
    
    // Populate client header
    this.populateHeader(client);
    
    // Calculate and display performance metrics
    const metrics = this.calculatePerformanceMetrics(client);
    this.displayMetricCards(metrics);
    
    // Display additional info
    this.displayAdditionalInfo(client);
    
    // Create combined chart
    this.createCombinedChart(metrics);
    
    // Show modal
    modal.classList.add('active');
  }
  
  populateHeader(client) {
    document.getElementById('client-modal-title').textContent = 
      `${client.hostname || 'Unknown Device'} - Performance Details`;
    document.getElementById('client-detail-name').textContent = 
      client.hostname || 'Unknown Device';
    document.getElementById('client-detail-mac').textContent = client.mac;
    document.getElementById('client-detail-ip').textContent = 
      client.ip_address || 'N/A';
    document.getElementById('client-detail-status').textContent = 'Connected';
  }
  
  calculatePerformanceMetrics(client) {
    const m = client.client_metrics || {};
    
    // Score calculation
    const rssiScore = this.normalizeRSSI(m.rssi_dbm || -70);
    const snrScore = (m.snr_db || 0) / 60 * 100;
    const rateScore = Math.min((Math.max(m.tx_rate_mbps || 0, m.rx_rate_mbps || 0)) / 2000 * 100, 100);
    const lossScore = Math.max(100 - (m.packet_loss_percent || 0) * 100, 0);
    const score = Math.round(rssiScore * 0.3 + snrScore * 0.3 + rateScore * 0.2 + lossScore * 0.2);
    
    // SNR
    const snr = m.snr_db || 0;
    
    // Physical Rate (PR)
    const pr = Math.max(m.tx_rate_mbps || 0, m.rx_rate_mbps || 0);
    
    // Packet Error Rate (PER)
    const per = m.packet_loss_percent || 0;
    
    // Physical Layer Performance (PSY)
    const snrComponent = (m.snr_db || 0) / 60 * 50;
    const spatialStreams = (m.spatial_streams || 1) / 2 * 25;
    const channelWidth = (m.channel_width_mhz || 20) / 160 * 25;
    const psy = Math.round(Math.min(snrComponent + spatialStreams + channelWidth, 100));
    
    return { score, snr, pr, per, psy };
  }
  
  normalizeRSSI(rssi) {
    const min = -90;
    const max = -30;
    return Math.max(0, Math.min(100, ((rssi - min) / (max - min)) * 100));
  }
  
  displayMetricCards(metrics) {
    // Score
    document.getElementById('client-score-value').textContent = metrics.score;
    const scoreTrend = document.getElementById('client-score-trend');
    scoreTrend.textContent = this.getScoreRating(metrics.score);
    scoreTrend.className = 'metric-trend ' + (metrics.score >= 70 ? 'up' : 'down');
    
    // SNR
    document.getElementById('client-snr-value').textContent = metrics.snr.toFixed(1);
    
    // PR
    document.getElementById('client-pr-value').textContent = metrics.pr.toFixed(0);
    
    // PER
    document.getElementById('client-per-value').textContent = metrics.per.toFixed(2);
    
    // PSY
    document.getElementById('client-psy-value').textContent = metrics.psy;
    const psyTrend = document.getElementById('client-psy-trend');
    psyTrend.textContent = this.getPSYRating(metrics.psy);
    psyTrend.className = 'metric-trend ' + (metrics.psy >= 70 ? 'up' : 'down');
  }
  
  getScoreRating(score) {
    if (score >= 80) return 'Excellent';
    if (score >= 60) return 'Good';
    if (score >= 40) return 'Fair';
    return 'Poor';
  }
  
  getPSYRating(psy) {
    if (psy >= 80) return 'Excellent';
    if (psy >= 60) return 'Good';
    if (psy >= 40) return 'Fair';
    return 'Poor';
  }
  
  displayAdditionalInfo(client) {
    const m = client.client_metrics || {};
    const cap = client.capabilities || {};
    
    // Connection details
    document.getElementById('client-ap').textContent = 
      client.connected_ap_mac || 'Unknown';
    document.getElementById('client-band').textContent = 
      this.determineBand(m.channel_width_mhz);
    document.getElementById('client-channel').textContent = 
      `${m.channel_width_mhz || 'N/A'} MHz`;
    document.getElementById('client-connection-time').textContent = 
      m.connection_duration || 'N/A';
    
    // Capabilities
    const standards = cap.wifi_standards || [];
    document.getElementById('client-wifi-standard').textContent = 
      standards.length > 0 ? standards[0] : 'N/A';
    document.getElementById('client-streams').textContent = 
      `${m.spatial_streams || 1}x${m.spatial_streams || 1}`;
    document.getElementById('client-channel-width').textContent = 
      `${m.channel_width_mhz || 20} MHz`;
    document.getElementById('client-security').textContent = 
      client.auth_method || 'N/A';
  }
  
  determineBand(channelWidth) {
    if (channelWidth >= 160) return '6 GHz';
    if (channelWidth >= 80) return '5 GHz';
    return '2.4 GHz';
  }
  
  createCombinedChart(metrics) {
    const canvas = document.getElementById('client-detail-chart');
    if (!canvas) return;
    
    // Destroy existing chart
    if (this.chart) {
      this.chart.destroy();
    }
    
    const ctx = canvas.getContext('2d');
    
    // Generate time series data for all metrics
    const timeLabels = this.generateTimeLabels();
    const datasets = [
      {
        label: 'Score (0-100)',
        data: this.generateMetricData(metrics.score, 'score'),
        borderColor: this.colors.score,
        backgroundColor: this.colors.score + '20',
        yAxisID: 'y',
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'SNR (dB)',
        data: this.generateMetricData(metrics.snr, 'snr'),
        borderColor: this.colors.snr,
        backgroundColor: this.colors.snr + '20',
        yAxisID: 'y',
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'PR (Mbps / 10)',
        data: this.generateMetricData(metrics.pr / 10, 'pr'),
        borderColor: this.colors.pr,
        backgroundColor: this.colors.pr + '20',
        yAxisID: 'y',
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'PER (%) x 20',
        data: this.generateMetricData(metrics.per * 20, 'per'),
        borderColor: this.colors.per,
        backgroundColor: this.colors.per + '20',
        yAxisID: 'y',
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      },
      {
        label: 'PSY (0-100)',
        data: this.generateMetricData(metrics.psy, 'psy'),
        borderColor: this.colors.psy,
        backgroundColor: this.colors.psy + '20',
        yAxisID: 'y',
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      }
    ];
    
    this.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: timeLabels,
        datasets: datasets
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: 'index',
          intersect: false,
        },
        plugins: {
          legend: {
            display: true,
            position: 'bottom',
            labels: {
              usePointStyle: true,
              padding: 15,
              font: {
                size: 12
              }
            }
          },
          tooltip: {
            enabled: true,
            callbacks: {
              label: function(context) {
                let label = context.dataset.label || '';
                if (label) {
                  label += ': ';
                }
                let value = context.parsed.y;
                
                // Denormalize values for display
                if (label.includes('PR')) {
                  value = value * 10;
                  label = label.replace(' / 10', '');
                } else if (label.includes('PER')) {
                  value = value / 20;
                  label = label.replace(' x 20', '');
                }
                
                label += value.toFixed(2);
                return label;
              }
            }
          }
        },
        scales: {
          x: {
            grid: {
              color: 'rgba(0, 0, 0, 0.05)'
            },
            ticks: {
              font: {
                size: 10
              }
            }
          },
          y: {
            beginAtZero: true,
            min: 0,
            max: 100,
            grid: {
              color: 'rgba(0, 0, 0, 0.05)'
            },
            title: {
              display: true,
              text: 'Normalized Values (0-100)',
              font: {
                size: 13,
                weight: 'bold'
              }
            }
          }
        }
      }
    });
  }
  
  generateTimeLabels() {
    const labels = [];
    const now = new Date();
    
    for (let i = 60; i >= 0; i -= 5) {
      const time = new Date(now.getTime() - i * 60000);
      labels.push(time.toLocaleTimeString('en-US', { 
        hour: 'numeric', 
        minute: '2-digit',
        hour12: true 
      }));
    }
    
    return labels;
  }
  
  generateMetricData(baseValue, metric) {
    const data = [];
    const points = 13;
    
    for (let i = 0; i < points; i++) {
      let variation;
      
      switch(metric) {
        case 'score':
        case 'psy':
          variation = (Math.random() - 0.5) * 8;
          data.push(Math.max(0, Math.min(100, baseValue + variation)));
          break;
        case 'snr':
          variation = (Math.random() - 0.5) * 4;
          data.push(Math.max(0, Math.min(100, baseValue + variation)));
          break;
        case 'pr':
          variation = (Math.random() - 0.5) * 20;
          data.push(Math.max(0, Math.min(300, baseValue + variation)));
          break;
        case 'per':
          variation = (Math.random() - 0.5) * 2;
          data.push(Math.max(0, Math.min(100, baseValue + variation)));
          break;
        default:
          data.push(baseValue);
      }
    }
    
    return data;
  }
}

/**
 * Client Performance Monitor Class
 * Handles Score, SNR, PR, PER, PSY metrics visualization
 */
class ClientPerformanceMonitor {
  constructor(clients, devices) {
    this.chart = null;
    this.clients = clients || [];
    this.devices = devices || [];
    this.currentMetric = 'score';
    this.selectedDevice = 'all';
    this.colors = [
      '#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6',
      '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1',
      '#14b8a6', '#a855f7', '#eab308', '#22c55e', '#f43f5e'
    ];
    
    // Metric configurations
    this.metricConfig = {
      score: {
        title: 'Performance Score Over Time',
        yLabel: 'Score',
        unit: '',
        min: 0,
        max: 100
      },
      snr: {
        title: 'Signal-to-Noise Ratio (SNR) Over Time',
        yLabel: 'SNR (dB)',
        unit: ' dB',
        min: 0,
        max: 80
      },
      pr: {
        title: 'Physical Rate (PR) Over Time',
        yLabel: 'Physical Rate (Mbps)',
        unit: ' Mbps',
        min: 0,
        max: 3000
      },
      per: {
        title: 'Packet Error Rate (PER) Over Time',
        yLabel: 'PER (%)',
        unit: '%',
        min: 0,
        max: 5
      },
      psy: {
        title: 'Physical Layer Performance (PSY) Over Time',
        yLabel: 'PSY',
        unit: '',
        min: 0,
        max: 100
      }
    };
  }
  
  async init() {
    // Enhance client data with performance metrics
    this.enhanceClientData();
    
    // Setup event listeners
    this.setupEventListeners();
    
    // Populate device filter
    this.populateDeviceFilter();
    
    // Initialize chart
    this.createChart();
  }
  
  updateClients(clients, devices) {
    this.clients = clients;
    this.devices = devices || this.devices;
    this.enhanceClientData();
    this.populateDeviceFilter();
    if (this.chart) {
      this.updateChart();
    }
  }
  
  enhanceClientData() {
    this.clients = this.clients.map((client, index) => ({
      ...client,
      color: this.colors[index % this.colors.length],
      performance_metrics: this.calculatePerformanceMetrics(client)
    }));
  }
  
  calculatePerformanceMetrics(client) {
    const metrics = client.client_metrics || {};
    
    // Calculate Performance Score (0-100)
    const score = this.calculateScore(metrics);
    
    // SNR already exists
    const snr = metrics.snr_db || 0;
    
    // Physical Rate (PR) - use max of tx/rx rate
    const pr = Math.max(metrics.tx_rate_mbps || 0, metrics.rx_rate_mbps || 0);
    
    // Packet Error Rate (PER) - convert packet loss to percentage
    const per = metrics.packet_loss_percent || 0;
    
    // Physical Layer Performance (PSY) - composite metric
    const psy = this.calculatePSY(metrics);
    
    return { score, snr, pr, per, psy };
  }
  
  calculateScore(metrics) {
    // Calculate overall performance score based on multiple factors
    const rssiScore = this.normalizeRSSI(metrics.rssi_dbm || -70);
    const snrScore = (metrics.snr_db || 0) / 60 * 100;
    const rateScore = Math.min((Math.max(metrics.tx_rate_mbps || 0, metrics.rx_rate_mbps || 0)) / 2000 * 100, 100);
    const lossScore = Math.max(100 - (metrics.packet_loss_percent || 0) * 100, 0);
    
    return Math.round(
      rssiScore * 0.3 +
      snrScore * 0.3 +
      rateScore * 0.2 +
      lossScore * 0.2
    );
  }
  
  normalizeRSSI(rssi) {
    const min = -90;
    const max = -30;
    return Math.max(0, Math.min(100, ((rssi - min) / (max - min)) * 100));
  }
  
  calculatePSY(metrics) {
    const snrComponent = (metrics.snr_db || 0) / 60 * 50;
    const spatialStreams = (metrics.spatial_streams || 1) / 2 * 25;
    const channelWidth = (metrics.channel_width_mhz || 20) / 160 * 25;
    
    return Math.round(Math.min(snrComponent + spatialStreams + channelWidth, 100));
  }
  
  setupEventListeners() {
    // Metric tab switching
    document.querySelectorAll('.performance-metric-tab').forEach(tab => {
      tab.addEventListener('click', (e) => {
        const metric = e.target.dataset.metric;
        this.switchMetric(metric);
      });
    });
    
    // Device filter
    const deviceFilter = document.getElementById('performance-device-filter');
    if (deviceFilter) {
      deviceFilter.addEventListener('change', (e) => {
        this.selectedDevice = e.target.value;
        this.updateChart();
      });
    }
  }
  
  populateDeviceFilter() {
    const select = document.getElementById('performance-device-filter');
    if (!select) return;
    
    select.innerHTML = '<option value="all">All Devices</option>';
    
    // Populate with devices (agents) instead of clients
    this.devices.forEach(device => {
      const clientCount = this.clients.filter(c => c.connected_ap_mac === device.mac).length;
      const option = document.createElement('option');
      option.value = device.mac;
      option.textContent = `${device.vendor} ${device.model} (${clientCount} clients)`;
      select.appendChild(option);
    });
  }
  
  switchMetric(metric) {
    this.currentMetric = metric;
    
    // Update active tab
    document.querySelectorAll('.performance-metric-tab').forEach(tab => {
      tab.classList.remove('active');
      if (tab.dataset.metric === metric) {
        tab.classList.add('active');
      }
    });
    
    // Update chart
    this.updateChart();
  }
  
  createChart() {
    const canvas = document.getElementById('client-performance-chart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const config = this.metricConfig[this.currentMetric];
    
    this.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: this.generateTimeLabels(),
        datasets: this.generateDatasets()
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: 'index',
          intersect: false,
        },
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            enabled: true,
            callbacks: {
              label: function(context) {
                let label = context.dataset.label || '';
                if (label) {
                  label += ': ';
                }
                const value = context.parsed.y;
                const unit = context.dataset.unit || '';
                label += value.toFixed(2) + unit;
                return label;
              }
            }
          }
        },
        scales: {
          x: {
            grid: {
              color: 'rgba(0, 0, 0, 0.05)'
            },
            ticks: {
              font: {
                size: 11
              }
            }
          },
          y: {
            beginAtZero: true,
            min: config.min,
            max: config.max,
            grid: {
              color: 'rgba(0, 0, 0, 0.05)'
            },
            title: {
              display: true,
              text: config.yLabel,
              font: {
                size: 13,
                weight: 'bold'
              }
            }
          }
        }
      }
    });
    
    this.updateChartTitle();
    this.updateLegend();
  }
  
  updateChart() {
    if (!this.chart) return;
    
    const config = this.metricConfig[this.currentMetric];
    
    this.chart.data.datasets = this.generateDatasets();
    this.chart.options.scales.y.min = config.min;
    this.chart.options.scales.y.max = config.max;
    this.chart.options.scales.y.title.text = config.yLabel;
    
    this.chart.update();
    this.updateChartTitle();
    this.updateLegend();
  }
  
  updateChartTitle() {
    const config = this.metricConfig[this.currentMetric];
    const titleEl = document.getElementById('performance-chart-title');
    if (titleEl) {
      titleEl.textContent = config.title;
    }
  }
  
  generateTimeLabels() {
    const labels = [];
    const now = new Date();
    
    for (let i = 60; i >= 0; i -= 5) {
      const time = new Date(now.getTime() - i * 60000);
      labels.push(time.toLocaleTimeString('en-US', { 
        hour: 'numeric', 
        minute: '2-digit',
        hour12: true 
      }));
    }
    
    return labels;
  }
  
  generateDatasets() {
    // Filter clients by selected device (agent)
    const filteredClients = this.selectedDevice === 'all' 
      ? this.clients 
      : this.clients.filter(c => c.connected_ap_mac === this.selectedDevice);
    
    const config = this.metricConfig[this.currentMetric];
    
    return filteredClients.map(client => {
      const baseValue = client.performance_metrics[this.currentMetric];
      const data = this.generateMetricData(baseValue, this.currentMetric);
      
      return {
        label: `${client.hostname} (${client.mac.substring(0, 17)}): ${baseValue.toFixed(2)}${config.unit}`,
        data: data,
        borderColor: client.color,
        backgroundColor: client.color + '20',
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 5,
        unit: config.unit
      };
    });
  }
  
  generateMetricData(baseValue, metric) {
    const data = [];
    const points = 13;
    
    for (let i = 0; i < points; i++) {
      let variation;
      
      switch(metric) {
        case 'score':
          variation = (Math.random() - 0.5) * 10;
          data.push(Math.max(0, Math.min(100, baseValue + variation)));
          break;
        case 'snr':
          variation = (Math.random() - 0.5) * 5;
          data.push(Math.max(0, baseValue + variation));
          break;
        case 'pr':
          variation = (Math.random() - 0.5) * 200;
          data.push(Math.max(0, baseValue + variation));
          break;
        case 'per':
          variation = (Math.random() - 0.5) * 0.1;
          data.push(Math.max(0, Math.min(5, baseValue + variation)));
          break;
        case 'psy':
          variation = (Math.random() - 0.5) * 8;
          data.push(Math.max(0, Math.min(100, baseValue + variation)));
          break;
        default:
          data.push(baseValue);
      }
    }
    
    return data;
  }
  
  updateLegend() {
    const legendContainer = document.getElementById('performance-legend-items');
    if (!legendContainer) return;
    
    legendContainer.innerHTML = '';
    
    const filteredClients = this.selectedDevice === 'all' 
      ? this.clients 
      : this.clients.filter(c => c.mac === this.selectedDevice);
    
    const config = this.metricConfig[this.currentMetric];
    
    filteredClients.forEach(client => {
      const item = document.createElement('div');
      item.className = 'performance-legend-item';
      
      const value = client.performance_metrics[this.currentMetric];
      
      item.innerHTML = `
        <div class="performance-legend-color" style="background: ${client.color}"></div>
        <span><strong>${client.hostname}</strong> (${client.mac.substring(0, 17)}): ${value.toFixed(2)}${config.unit}</span>
      `;
      
      legendContainer.appendChild(item);
    });
  }
}

  // -------- Global helpers for HTML onclick handlers --------
  function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.remove('active');
  }

// -------- Initialize when DOM is loaded --------
document.addEventListener('DOMContentLoaded', () => {
  window.EasyMeshController = new EasyMeshController();
  window.EasyMeshController.init();
});

// -------- Cleanup on page unload --------
window.addEventListener('beforeunload', () => {
  if (window.EasyMeshController) window.EasyMeshController.cleanup();
});

// -------- Export for CommonJS (optional) --------
if (typeof module !== 'undefined' && module.exports) {
  module.exports = EasyMeshController;
}

