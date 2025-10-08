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

    // Dashboard actions
    document.getElementById('refresh-dashboard')?.addEventListener('click', () => {
      this.refreshDashboard();
    });

    document.getElementById('optimize-network')?.addEventListener('click', () => {
      this.optimizeNetwork();
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

    this.wsConnection.onmessage = (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch { return; }
      this.handleWebSocketMessage(data);
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

handleWebSocketMessage(data) {
  switch (data.type) {
    case 'initial':
      this.devices = data.devices || [];
      this.clients = data.clients || [];
      this.topology = data.topology || {};
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
      this.updateTopology(data.topology);
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

      // Load topology
      this.topology = await this.apiCall('/topology');

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
    const container = document.getElementById('topology-visualization');
    if (!container) return;

    // Clear existing content
    container.innerHTML = '';

    // Create SVG
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '100%');
    svg.setAttribute('viewBox', '0 0 800 600');

    // Define node positions
    const nodes = this.calculateNodePositions();

    // Draw connections
    this.drawTopologyConnections(svg, nodes);

    // Draw nodes
    this.drawTopologyNodes(svg, nodes);

    container.appendChild(svg);
  }

  /**
   * Calculate node positions for topology
   */
  calculateNodePositions() {
    const nodes = [];
    const centerX = 400;
    const centerY = 300;
    const radius = 200;

    const others = this.devices.filter(d => d.role !== 'Controller');
    const controller = this.devices.find(d => d.role === 'Controller');

    if (controller) {
      nodes.push({ device: controller, x: centerX, y: centerY, isController: true });
    }

    others.forEach((device, index) => {
      const angle = (index * 2 * Math.PI) / Math.max(1, others.length);
      nodes.push({
        device,
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        isController: false
      });
    });

    return nodes;
  }

  /**
   * Draw topology connections
   */
  drawTopologyConnections(svg, nodes) {
    const controller = nodes.find(n => n.isController);

    nodes.forEach(node => {
      if (!node.isController && controller) {
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', controller.x);
        line.setAttribute('y1', controller.y);
        line.setAttribute('x2', node.x);
        line.setAttribute('y2', node.y);
        line.setAttribute('stroke', '#3b82f6');
        line.setAttribute('stroke-width', '2');
        line.setAttribute('stroke-dasharray', '5,5');
        svg.appendChild(line);
      }
    });
  }

  /**
   * Draw topology nodes
   */
  drawTopologyNodes(svg, nodes) {
    nodes.forEach(node => {
      // Node circle
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', node.x);
      circle.setAttribute('cy', node.y);
      circle.setAttribute('r', node.isController ? '25' : '20');
      circle.setAttribute('fill', node.isController ? '#2563eb' : '#10b981');
      circle.setAttribute('stroke', '#ffffff');
      circle.setAttribute('stroke-width', '3');
      circle.style.cursor = 'pointer';
      circle.addEventListener('click', () => this.showDeviceDetails(node.device));
      svg.appendChild(circle);

      // Device icon
      const icon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      icon.setAttribute('x', node.x);
      icon.setAttribute('y', node.y + 5);
      icon.setAttribute('text-anchor', 'middle');
      icon.setAttribute('fill', '#ffffff');
      icon.setAttribute('font-family', 'Font Awesome 6 Free');
      icon.setAttribute('font-size', '16');
      icon.textContent = node.isController ? '\uf233' : '\uf1eb'; // router icons
      svg.appendChild(icon);

      // Device label
      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      label.setAttribute('x', node.x);
      label.setAttribute('y', node.y + 45);
      label.setAttribute('text-anchor', 'middle');
      label.setAttribute('fill', '#374151');
      label.setAttribute('font-size', '12');
      label.setAttribute('font-weight', '600');
      label.textContent = node.device.model;
      svg.appendChild(label);

      // Status indicator
      const status = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      status.setAttribute('cx', node.x + (node.isController ? 18 : 15));
      status.setAttribute('cy', node.y - (node.isController ? 18 : 15));
      status.setAttribute('r', '6');
      status.setAttribute('fill', node.device.status === 'Online' ? '#10b981' : '#ef4444');
      status.setAttribute('stroke', '#ffffff');
      status.setAttribute('stroke-width', '2');
      svg.appendChild(status);
    });
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
    this.refreshIntervals.topology = setInterval(() => {
      if (this.currentTab === 'topology') this.updateTopologyVisualization();
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

  updateTopology(newTopo) {
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
    this.showNotification(`Show client details: ${mac}`, 'info');
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

  // ---- Tab-specific loaders (safe stubs) ----
  async loadPerformanceData() { /* fetch & update performance tab */ }
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

        document.getElementById("reset-btn").addEventListener("click", async () => {
        const payload = collectResetPayload();
        const confirmed = confirm("Resetting the WiFi configuration may require the controller to restart.\nDo you want to continue?");
        if (!confirmed) return;

        try {
          const response = await sendResetPayload(payload);
          handleResetSuccess(response);

          // Reload the latest Wi-Fi config after successful reset
          if (typeof this.loadWifiResetConfig === 'function') {
            console.log("Reloading Wi-Fi Reset config after reset");
            await this.loadWifiResetConfig();
          }
        } catch (error) {
          handleResetError(error);
        }
        });
      } catch (err) {
        console.error("Failed to load system settings:", err);
        this.showNotification("Failed to load system settings", "error");
      }
  }
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

function handleResetSuccess(response) {
  console.log("Reset result:", response);
  alert("Wi-Fi configuration reset successfully!");
}

function handleResetError(error) {
  console.error("Reset failed:", error);
  alert(`Failed to reset Wi-Fi configuration:\n${error.message}`);
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

