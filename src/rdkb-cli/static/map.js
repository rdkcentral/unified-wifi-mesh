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
 * Coverage Map Module - Interactive wireless coverage visualization
 * Handles real-time coverage analysis, device placement, and optimization
 */

class CoverageMap {
  constructor() {
    this.svg = null;
    this.currentView = 'heatmap';
    this.currentBand = '2.4ghz';
    this.signalThreshold = -70;
    this.mapScale = 0.1; // meters per pixel
    this.zoom = 1;
    this.panOffset = { x: 0, y: 0 };
    
    // Map dimensions
    this.mapWidth = 1000;
    this.mapHeight = 600;
    
    // Coverage data
    this.devices = [];
    this.clients = [];
    this.floorPlan = null;
    this.coverageData = new Map();
    this.weakZones = [];
    this.suggestions = [];
    
    // Interaction state
    this.isDragging = false;
    this.dragStart = { x: 0, y: 0 };
    this.selectedDevice = null;
    this.measurementMode = false;
    this.placementMode = false;
    
    // Analysis data
    this.analysisResults = {
      totalCoverage: 0,
      excellentCoverage: 0,
      weakAreas: 0,
      deadZones: 0,
      interferenceLevel: 'Low'
    };

    this.init();
  }

  /**
   * Initialize coverage map
   */
  async init() {
    console.log('Initializing Coverage Map');
    
    this.setupEventHandlers();
    this.initializeSVG();
    await this.loadCoverageData();
    this.render();
    
    console.log('Coverage Map initialized');
  }

  /**
   * Setup event handlers
   */
  setupEventHandlers() {
    // View controls
    document.querySelectorAll('.view-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.switchView(e.target.dataset.view);
      });
    });

    // Band selector
    document.querySelectorAll('.band-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.switchBand(e.target.dataset.band);
      });
    });

    // Signal threshold
    const thresholdSlider = document.getElementById('signal-threshold');
    if (thresholdSlider) {
      thresholdSlider.addEventListener('input', (e) => {
        this.updateSignalThreshold(parseInt(e.target.value));
      });
    }

    // Display options
    this.setupDisplayOptions();

    // Map controls
    document.getElementById('zoom-in')?.addEventListener('click', () => this.zoomIn());
    document.getElementById('zoom-out')?.addEventListener('click', () => this.zoomOut());
    document.getElementById('fit-view')?.addEventListener('click', () => this.fitToView());
    document.getElementById('measure-tool')?.addEventListener('click', () => this.toggleMeasurement());
    document.getElementById('add-device-tool')?.addEventListener('click', () => this.togglePlacement());

    // Floor plan selector
    const floorSelector = document.getElementById('floor-selector');
    if (floorSelector) {
      floorSelector.addEventListener('change', (e) => {
        this.switchFloorPlan(e.target.value);
      });
    }

    // Map scale input
    const mapScaleInput = document.getElementById('map-scale');
    if (mapScaleInput) {
      mapScaleInput.addEventListener('change', (e) => {
        this.mapScale = parseFloat(e.target.value);
        this.updateCoverage();
      });
    }

    // Refresh and optimization
    document.getElementById('refresh-coverage')?.addEventListener('click', () => this.refreshCoverage());
    document.getElementById('optimize-placement')?.addEventListener('click', () => this.optimizePlacement());

    // Floor plan upload
    this.setupFloorPlanUpload();

    // Device placement confirmation
    document.getElementById('confirm-placement')?.addEventListener('click', () => this.confirmDevicePlacement());
  }

  /**
   * Setup display option checkboxes
   */
  setupDisplayOptions() {
    const options = [
      'show-weak-zones',
      'show-interference', 
      'show-client-paths',
      'show-predictions'
    ];

    options.forEach(optionId => {
      const checkbox = document.getElementById(optionId);
      if (checkbox) {
        checkbox.addEventListener('change', () => {
          this.updateDisplayOptions();
        });
      }
    });
  }

  /**
   * Initialize SVG canvas
   */
  initializeSVG() {
    this.svg = document.getElementById('coverage-svg');
    if (!this.svg) {
      console.error('Coverage SVG element not found');
      return;
    }

    // Setup SVG event handlers
    this.svg.addEventListener('click', (e) => this.handleMapClick(e));
    this.svg.addEventListener('mousedown', (e) => this.handleMouseDown(e));
    this.svg.addEventListener('mousemove', (e) => this.handleMouseMove(e));
    this.svg.addEventListener('mouseup', (e) => this.handleMouseUp(e));
    this.svg.addEventListener('wheel', (e) => this.handleWheel(e));
    this.svg.addEventListener('mouseleave', () => this.handleMouseLeave());

    // Initialize layers
    this.initializeLayers();
  }

  /**
   * Initialize SVG layers
   */
  initializeLayers() {
    const layers = [
      'floor-plan-layer',
      'coverage-layer', 
      'devices-layer',
      'clients-layer',
      'annotations-layer',
      'measurements-layer'
    ];

    layers.forEach(layerId => {
      const layer = document.getElementById(layerId);
      if (layer) {
        // Clear existing content
        layer.innerHTML = '';
      }
    });
  }

  /**
   * Load coverage data
   */
  async loadCoverageData() {
    try {
      // Load devices
      const devicesResponse = await this.apiCall('/devices');
      this.devices = devicesResponse.devices || [];

      // Load clients  
      const clientsResponse = await this.apiCall('/clients');
      this.clients = clientsResponse.clients || [];

      // Load coverage analysis
      const coverageResponse = await this.apiCall('/coverage/analysis');
      this.processCoverageData(coverageResponse);

      console.log(`Loaded ${this.devices.length} devices and ${this.clients.length} clients`);
    } catch (error) {
      console.error('Failed to load coverage data:', error);
      this.showNotification('Failed to load coverage data', 'error');
    }
  }

  /**
   * Process coverage data from API
   */
  processCoverageData(data) {
    if (!data) return;

    this.analysisResults = {
      totalCoverage: data.total_coverage || 0,
      excellentCoverage: data.excellent_coverage || 0, 
      weakAreas: data.weak_areas || 0,
      deadZones: data.dead_zones || 0,
      interferenceLevel: data.interference_level || 'Low'
    };

    this.weakZones = data.weak_zones || [];
    this.suggestions = data.placement_suggestions || [];

    this.updateStatistics();
  }

  /**
   * Switch view mode
   */
  switchView(view) {
    // Update active button
    document.querySelectorAll('.view-btn').forEach(btn => {
      btn.classList.remove('active');
    });
    document.querySelector(`[data-view="${view}"]`).classList.add('active');

    this.currentView = view;
    this.render();
  }

  /**
   * Switch frequency band
   */
  switchBand(band) {
    // Update active button
    document.querySelectorAll('.band-btn').forEach(btn => {
      btn.classList.remove('active');
    });
    document.querySelector(`[data-band="${band}"]`).classList.add('active');

    this.currentBand = band;
    this.updateCoverage();
  }

  /**
   * Update signal threshold
   */
  updateSignalThreshold(threshold) {
    this.signalThreshold = threshold;
    
    // Update display
    const thresholdValue = document.querySelector('.threshold-value');
    if (thresholdValue) {
      thresholdValue.textContent = `${threshold} dBm`;
    }

    this.updateCoverage();
  }

  /**
   * Update display options
   */
  updateDisplayOptions() {
    const options = {
      showWeakZones: document.getElementById('show-weak-zones')?.checked || false,
      showInterference: document.getElementById('show-interference')?.checked || false,
      showClientPaths: document.getElementById('show-client-paths')?.checked || false,
      showPredictions: document.getElementById('show-predictions')?.checked || false
    };

    this.displayOptions = options;
    this.renderAnnotations();
  }

  /**
   * Main render function
   */
  render() {
    this.showLoading(true);

    try {
      this.renderFloorPlan();
      
      switch (this.currentView) {
        case 'heatmap':
          this.renderCoverage();
          this.renderDevices();
          break;
        case 'devices':
          this.renderDevices();
          this.renderCoverageOutlines();
          break;
        case 'clients':
          this.renderDevices();
          this.renderClients();
          this.renderClientPaths();
          break;
      }

      this.renderAnnotations();
      this.updateViewTransform();
    } finally {
      this.showLoading(false);
    }
  }

  /**
   * Render floor plan
   */
  renderFloorPlan() {
    const layer = document.getElementById('floor-plan-layer');
    if (!layer || !this.floorPlan) return;

    layer.innerHTML = `
      <image href="${this.floorPlan.url}" 
             x="0" y="0" 
             width="${this.mapWidth}" 
             height="${this.mapHeight}"
             opacity="0.3"
             preserveAspectRatio="xMidYMid slice" />
    `;
  }

  /**
   * Render coverage heatmap
   */
  renderCoverage() {
    const layer = document.getElementById('coverage-layer');
    if (!layer) return;

    layer.innerHTML = '';

    this.devices.forEach(device => {
      if (device.status !== 'Online') return;

      const position = this.getDevicePosition(device);
      const coverage = this.calculateCoverage(device, this.currentBand);
      
      coverage.zones.forEach(zone => {
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', position.x);
        circle.setAttribute('cy', position.y);
        circle.setAttribute('r', zone.radius);
        circle.setAttribute('class', `coverage-circle ${zone.quality}`);
        circle.setAttribute('fill', `url(#${zone.quality}Signal)`);
        
        layer.appendChild(circle);
      });
    });
  }

  /**
   * Render coverage outlines (for devices view)
   */
  renderCoverageOutlines() {
    const layer = document.getElementById('coverage-layer');
    if (!layer) return;

    layer.innerHTML = '';

    this.devices.forEach(device => {
      if (device.status !== 'Online') return;

      const position = this.getDevicePosition(device);
      const coverage = this.calculateCoverage(device, this.currentBand);
      
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', position.x);
      circle.setAttribute('cy', position.y);
      circle.setAttribute('r', coverage.maxRadius);
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', this.getDeviceColor(device));
      circle.setAttribute('stroke-width', '2');
      circle.setAttribute('stroke-dasharray', '5,5');
      circle.setAttribute('opacity', '0.6');
      
      layer.appendChild(circle);
    });
  }

  /**
   * Render devices
   */
  renderDevices() {
    const layer = document.getElementById('devices-layer');
    if (!layer) return;

    layer.innerHTML = '';

    this.devices.forEach(device => {
      const position = this.getDevicePosition(device);
      const deviceElement = this.createDeviceIcon(device, position);
      layer.appendChild(deviceElement);
    });
  }

  /**
   * Render clients
   */
  renderClients() {
    const layer = document.getElementById('clients-layer');
    if (!layer) return;

    layer.innerHTML = '';

    this.clients.forEach(client => {
      const position = this.getClientPosition(client);
      if (position) {
        const clientElement = this.createClientIcon(client, position);
        layer.appendChild(clientElement);
      }
    });
  }

  /**
   * Render client movement paths
   */
  renderClientPaths() {
    if (!this.displayOptions?.showClientPaths) return;

    const layer = document.getElementById('clients-layer');
    // Implementation would show client movement history
    // This is a simplified version
    console.log('Rendering client paths (placeholder)');
  }

  /**
   * Render annotations (weak zones, suggestions, etc.)
   */
  renderAnnotations() {
    const layer = document.getElementById('annotations-layer');
    if (!layer) return;

    layer.innerHTML = '';

    // Render weak zones
    if (this.displayOptions?.showWeakZones) {
      this.renderWeakZones(layer);
    }

    // Render placement suggestions
    if (this.displayOptions?.showPredictions) {
      this.renderSuggestions(layer);
    }
  }

  /**
   * Render weak signal zones
   */
  renderWeakZones(layer) {
    this.weakZones.forEach((zone, index) => {
      const polygon = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
      polygon.setAttribute('points', zone.points);
      polygon.setAttribute('class', 'weak-zone');
      
      // Add warning icon at center
      const center = this.calculatePolygonCenter(zone.points);
      const warning = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      warning.setAttribute('x', center.x);
      warning.setAttribute('y', center.y);
      warning.setAttribute('text-anchor', 'middle');
      warning.setAttribute('dominant-baseline', 'middle');
      warning.setAttribute('font-family', 'Font Awesome 6 Free');
      warning.setAttribute('font-size', '20');
      warning.setAttribute('fill', '#ef4444');
      warning.textContent = '⚠';
      
      layer.appendChild(polygon);
      layer.appendChild(warning);
    });
  }

  /**
   * Render placement suggestions
   */
  renderSuggestions(layer) {
    this.suggestions.forEach(suggestion => {
      const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      group.setAttribute('class', 'suggestion-marker');
      group.setAttribute('transform', `translate(${suggestion.x}, ${suggestion.y})`);
      
      // Suggestion circle
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '0');
      circle.setAttribute('cy', '0');
      circle.setAttribute('r', '15');
      circle.setAttribute('fill', '#06b6d4');
      circle.setAttribute('stroke', '#ffffff');
      circle.setAttribute('stroke-width', '2');
      
      // Plus icon
      const plus = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      plus.setAttribute('x', '0');
      plus.setAttribute('y', '0');
      plus.setAttribute('text-anchor', 'middle');
      plus.setAttribute('dominant-baseline', 'middle');
      plus.setAttribute('font-family', 'Font Awesome 6 Free');
      plus.setAttribute('font-size', '16');
      plus.setAttribute('fill', '#ffffff');
      plus.textContent = '+';
      
      group.appendChild(circle);
      group.appendChild(plus);
      
      // Click handler
      group.addEventListener('click', () => {
        this.showDevicePlacementModal(suggestion.x, suggestion.y);
      });
      
      layer.appendChild(group);
    });
  }

  /**
   * Create device icon
   */
  createDeviceIcon(device, position) {
    const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    group.setAttribute('class', `device-icon ${device.role.toLowerCase()}`);
    group.setAttribute('transform', `translate(${position.x}, ${position.y})`);
    
    // Device circle
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '0');
    circle.setAttribute('cy', '0');
    circle.setAttribute('r', device.role === 'Controller' ? '20' : '15');
    circle.setAttribute('fill', this.getDeviceColor(device));
    circle.setAttribute('stroke', '#ffffff');
    circle.setAttribute('stroke-width', '2');
    
    // Device icon
    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    icon.setAttribute('x', '0');
    icon.setAttribute('y', '0');
    icon.setAttribute('text-anchor', 'middle');
    icon.setAttribute('dominant-baseline', 'middle');
    icon.setAttribute('font-family', 'Font Awesome 6 Free');
    icon.setAttribute('font-size', device.role === 'Controller' ? '16' : '12');
    icon.setAttribute('fill', '#ffffff');
    icon.textContent = device.role === 'Controller' ? '🏠' : '📡';
    
    // Status indicator
    const status = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    const radius = device.role === 'Controller' ? 15 : 12;
    status.setAttribute('cx', radius);
    status.setAttribute('cy', -radius);
    status.setAttribute('r', '5');
    status.setAttribute('fill', device.status === 'Online' ? '#10b981' : '#ef4444');
    status.setAttribute('stroke', '#ffffff');
    status.setAttribute('stroke-width', '1');
    
    group.appendChild(circle);
    group.appendChild(icon);
    group.appendChild(status);
    
    // Add click handler
    group.addEventListener('click', (e) => {
      e.stopPropagation();
      this.showDeviceDetails(device);
    });
    
    return group;
  }

  /**
   * Create client icon
   */
  createClientIcon(client, position) {
    const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    group.setAttribute('class', 'client-icon');
    group.setAttribute('transform', `translate(${position.x}, ${position.y})`);
    
    // Client circle
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '0');
    circle.setAttribute('cy', '0');
    circle.setAttribute('r', '8');
    circle.setAttribute('fill', this.getClientColor(client));
    circle.setAttribute('stroke', '#ffffff');
    circle.setAttribute('stroke-width', '1');
    
    // Client icon
    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    icon.setAttribute('x', '0');
    icon.setAttribute('y', '0');
    icon.setAttribute('text-anchor', 'middle');
    icon.setAttribute('dominant-baseline', 'middle');
    icon.setAttribute('font-family', 'Font Awesome 6 Free');
    icon.setAttribute('font-size', '8');
    icon.setAttribute('fill', '#ffffff');
    icon.textContent = this.getClientIcon(client.device_type);
    
    group.appendChild(circle);
    group.appendChild(icon);
    
    // Add click handler
    group.addEventListener('click', (e) => {
      e.stopPropagation();
      this.showClientDetails(client);
    });
    
    return group;
  }

  /**
   * Calculate coverage for a device
   */
  calculateCoverage(device, band) {
    const baseRadius = this.getBaseRadius(device, band);
    const zones = [];

    // Create coverage zones based on signal strength
    const ranges = [
      { quality: 'excellent', factor: 0.3, threshold: -50 },
      { quality: 'good', factor: 0.5, threshold: -60 },
      { quality: 'fair', factor: 0.7, threshold: -70 },
      { quality: 'poor', factor: 1.0, threshold: -80 }
    ];

    ranges.forEach(range => {
      if (this.signalThreshold <= range.threshold) {
        zones.push({
          quality: range.quality,
          radius: baseRadius * range.factor,
          threshold: range.threshold
        });
      }
    });

    return {
      zones: zones,
      maxRadius: baseRadius
    };
  }

  /**
   * Get base coverage radius for device and band
   */
  getBaseRadius(device, band) {
    const powerDbm = device.metrics?.tx_power_dbm || 20;
    const frequency = this.getBandFrequency(band);
    
    // Simplified path loss calculation
    // Free space path loss: FSPL = 20*log10(d) + 20*log10(f) + 32.45
    const targetRSSI = -80; // Minimum usable signal
    const pathLoss = powerDbm - targetRSSI;
    
    // Calculate distance in meters
    const distance = Math.pow(10, (pathLoss - 32.45 - 20 * Math.log10(frequency)) / 20);
    
    // Convert to pixels based on map scale
    return Math.max(20, distance / this.mapScale);
  }

  /**
   * Get frequency for band
   */
  getBandFrequency(band) {
    const frequencies = {
      '2.4ghz': 2400,
      '5ghz': 5000,
      '6ghz': 6000
    };
    return frequencies[band] || 2400;
  }

  /**
   * Get device position on map
   */
  getDevicePosition(device) {
    if (device.location?.position_3d) {
      // Convert 3D position to 2D map coordinates
      const x = (device.location.position_3d.x / this.mapScale) + (this.mapWidth / 2);
      const y = (device.location.position_3d.y / this.mapScale) + (this.mapHeight / 2);
      return { x: Math.max(0, Math.min(this.mapWidth, x)), 
               y: Math.max(0, Math.min(this.mapHeight, y)) };
    }
    
    // Default positions if no location data
    const positions = {
      'AA:BB:CC:00:00:01': { x: 200, y: 300 },
      'AA:BB:CC:00:00:02': { x: 500, y: 200 },
      'AA:BB:CC:00:00:03': { x: 750, y: 400 }
    };
    
    return positions[device.mac] || { x: 100, y: 100 };
  }

  /**
   * Get client position on map
   */
  getClientPosition(client) {
    if (client.location?.estimated_position) {
      const x = (client.location.estimated_position.x / this.mapScale) + (this.mapWidth / 2);
      const y = (client.location.estimated_position.y / this.mapScale) + (this.mapHeight / 2);
      return { x: Math.max(0, Math.min(this.mapWidth, x)), 
               y: Math.max(0, Math.min(this.mapHeight, y)) };
    }
    return null;
  }

  /**
   * Get device color
   */
  getDeviceColor(device) {
    if (device.role === 'Controller') return '#2563eb';
    if (device.status === 'Online') return '#10b981';
    return '#6b7280';
  }

  /**
   * Get client color
   */
  getClientColor(client) {
    const rssi = client.client_metrics?.rssi_dbm || -70;
    if (rssi >= -50) return '#10b981';
    if (rssi >= -60) return '#3b82f6';
    if (rssi >= -70) return '#f59e0b';
    return '#ef4444';
  }

  /**
   * Get client icon
   */
  getClientIcon(deviceType) {
    const icons = {
      smartphone: '📱',
      laptop: '💻',
      tablet: '📱',
      'smart-tv': '📺',
      'gaming-console': '🎮',
      'iot-device': '🏠'
    };
    return icons[deviceType] || '📱';
  }

  /**
   * Handle map interactions
   */
  handleMapClick(e) {
    if (this.placementMode) {
      const coords = this.getSVGCoordinates(e);
      this.showDevicePlacementModal(coords.x, coords.y);
      return;
    }

    if (this.measurementMode) {
      this.addMeasurementPoint(e);
      return;
    }

    // Clear selection
    this.selectedDevice = null;
    this.updateDeviceSelection();
  }

  handleMouseDown(e) {
    if (e.button === 0 && !this.placementMode && !this.measurementMode) {
      this.isDragging = true;
      this.dragStart = { x: e.clientX, y: e.clientY };
      this.svg.style.cursor = 'grabbing';
    }
  }

  handleMouseMove(e) {
    // Update coordinates display
    const coords = this.getSVGCoordinates(e);
    const coordsDisplay = document.getElementById('mouse-coordinates');
    if (coordsDisplay) {
      const realX = (coords.x - this.mapWidth/2) * this.mapScale;
      const realY = (coords.y - this.mapHeight/2) * this.mapScale;
      coordsDisplay.textContent = `${realX.toFixed(1)}m, ${realY.toFixed(1)}m`;
    }

    if (this.isDragging) {
      const dx = e.clientX - this.dragStart.x;
      const dy = e.clientY - this.dragStart.y;
      
      this.panOffset.x += dx;
      this.panOffset.y += dy;
      
      this.updateViewTransform();
      this.dragStart = { x: e.clientX, y: e.clientY };
    }
  }

  handleMouseUp(e) {
    this.isDragging = false;
    this.svg.style.cursor = this.placementMode ? 'crosshair' : 'default';
  }

  handleMouseLeave() {
    this.isDragging = false;
    this.svg.style.cursor = 'default';
  }

  handleWheel(e) {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    this.zoom *= delta;
    this.zoom = Math.max(0.1, Math.min(5, this.zoom));
    this.updateViewTransform();
    this.updateZoomDisplay();
  }

  /**
   * Get SVG coordinates from mouse event
   */
  getSVGCoordinates(e) {
    const rect = this.svg.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / this.zoom) - (this.panOffset.x / this.zoom);
    const y = ((e.clientY - rect.top) / this.zoom) - (this.panOffset.y / this.zoom);
    return { x, y };
  }

  /**
   * Update view transform
   */
  updateViewTransform() {
    const transform = `translate(${this.panOffset.x}, ${this.panOffset.y}) scale(${this.zoom})`;
    
    // Apply transform to all layers except grid
    const layers = ['coverage-layer', 'devices-layer', 'clients-layer', 'annotations-layer', 'measurements-layer'];
    layers.forEach(layerId => {
      const layer = document.getElementById(layerId);
      if (layer) {
        layer.setAttribute('transform', transform);
      }
    });
  }

  /**
   * Zoom controls
   */
  zoomIn() {
    this.zoom *= 1.2;
    this.zoom = Math.min(5, this.zoom);
    this.updateViewTransform();
    this.updateZoomDisplay();
  }

  zoomOut() {
    this.zoom *= 0.8;
    this.zoom = Math.max(0.1, this.zoom);
    this.updateViewTransform();
    this.updateZoomDisplay();
  }

  fitToView() {
    this.zoom = 1;
    this.panOffset = { x: 0, y: 0 };
    this.updateViewTransform();
    this.updateZoomDisplay();
  }

  updateZoomDisplay() {
    const zoomDisplay = document.querySelector('.zoom-level');
    if (zoomDisplay) {
      zoomDisplay.textContent = `Zoom: ${Math.round(this.zoom * 100)}%`;
    }
  }

  /**
   * Tool toggles
   */
  toggleMeasurement() {
    this.measurementMode = !this.measurementMode;
    const btn = document.getElementById('measure-tool');
    if (btn) {
      btn.classList.toggle('active', this.measurementMode);
    }
    this.svg.style.cursor = this.measurementMode ? 'crosshair' : 'default';
  }

  togglePlacement() {
    this.placementMode = !this.placementMode;
    const btn = document.getElementById('add-device-tool');
    if (btn) {
      btn.classList.toggle('active', this.placementMode);
    }
    this.svg.style.cursor = this.placementMode ? 'crosshair' : 'default';
  }

  /**
   * Update coverage analysis
   */
  async updateCoverage() {
    this.showLoading(true);
    
    try {
      const response = await this.apiCall('/coverage/analyze', {
        method: 'POST',
        body: {
          band: this.currentBand,
          threshold: this.signalThreshold,
          map_scale: this.mapScale
        }
      });
      
      this.processCoverageData(response);
      this.render();
    } catch (error) {
      console.error('Failed to update coverage:', error);
      this.showNotification('Failed to update coverage analysis', 'error');
    } finally {
      this.showLoading(false);
    }
  }

  /**
   * Refresh coverage data
   */
  async refreshCoverage() {
    await this.loadCoverageData();
    await this.updateCoverage();
    this.showNotification('Coverage data refreshed', 'success');
  }

  /**
   * Optimize device placement
   */
  async optimizePlacement() {
    this.showLoading(true);
    
    try {
      const response = await this.apiCall('/coverage/optimize', {
        method: 'POST',
        body: {
          band: this.currentBand,
          coverage_target: 95,
          signal_threshold: this.signalThreshold
        }
      });
      
      if (response.suggestions) {
        this.suggestions = response.suggestions;
        this.renderAnnotations();
        
        // Show analysis panel
        const panel = document.getElementById('analysis-panel');
        if (panel) {
          panel.classList.add('active');
          this.updateAnalysisPanel(response);
        }
        
        this.showNotification(`Found ${response.suggestions.length} optimization suggestions`, 'success');
      }
    } catch (error) {
      console.error('Optimization failed:', error);
      this.showNotification('Failed to optimize placement', 'error');
    } finally {
      this.showLoading(false);
    }
  }

  /**
   * Update statistics display
   */
  updateStatistics() {
    const stats = {
      'total-coverage': `${this.analysisResults.totalCoverage}%`,
      'excellent-coverage': `${this.analysisResults.excellentCoverage}%`,
      'weak-areas': `${this.analysisResults.weakAreas} m²`,
      'dead-zones': `${this.analysisResults.deadZones} m²`,
      'interference-level': this.analysisResults.interferenceLevel
    };

    Object.entries(stats).forEach(([id, value]) => {
      const element = document.getElementById(id);
      if (element) {
        element.textContent = value;
      }
    });
  }

  /**
   * Show/hide loading
   */
  showLoading(show) {
    const loading = document.getElementById('map-loading');
    if (loading) {
      loading.classList.toggle('active', show);
    }
  }

  /**
   * Utility functions
   */
  calculatePolygonCenter(points) {
    const coords = points.split(' ').map(p => {
      const [x, y] = p.split(',').map(Number);
      return { x, y };
    });
    
    const centerX = coords.reduce((sum, p) => sum + p.x, 0) / coords.length;
    const centerY = coords.reduce((sum, p) => sum + p.y, 0) / coords.length;
    
    return { x: centerX, y: centerY };
  }

  showDevicePlacementModal(x, y) {
    const modal = document.getElementById('device-placement-modal');
    const coords = document.getElementById('placement-coordinates');
    
    if (modal && coords) {
      const realX = (x - this.mapWidth/2) * this.mapScale;
      const realY = (y - this.mapHeight/2) * this.mapScale;
      
      coords.textContent = `X: ${realX.toFixed(1)}m, Y: ${realY.toFixed(1)}m`;
      
      // Store placement coordinates
      this.placementCoords = { x, y, realX, realY };
      
      // Calculate predicted coverage
      this.updatePlacementPrediction(x, y);
      
      modal.classList.add('active');
    }
  }

  updatePlacementPrediction(x, y) {
    // Simplified prediction calculation
    const nearestDevice = this.findNearestDevice(x, y);
    const distance = nearestDevice ? this.calculateDistance(x, y, nearestDevice.position.x, nearestDevice.position.y) : 100;
    
    const predictions = {
      radius: Math.max(15, 50 - distance * 0.1),
      quality: distance < 30 ? 'Excellent' : distance < 60 ? 'Good' : 'Fair',
      interference: distance < 20 ? 'Medium' : 'Low'
    };
    
    document.getElementById('predicted-radius').textContent = `${predictions.radius.toFixed(0)}m`;
    document.getElementById('predicted-quality').textContent = predictions.quality;
    document.getElementById('predicted-interference').textContent = predictions.interference;
  }

  findNearestDevice(x, y) {
    let nearest = null;
    let minDistance = Infinity;
    
    this.devices.forEach(device => {
      const pos = this.getDevicePosition(device);
      const distance = this.calculateDistance(x, y, pos.x, pos.y);
      if (distance < minDistance) {
        minDistance = distance;
        nearest = { device, position: pos };
      }
    });
    
    return nearest;
  }

  calculateDistance(x1, y1, x2, y2) {
    return Math.sqrt(Math.pow(x2 - x1, 2) + Math.pow(y2 - y1, 2)) * this.mapScale;
  }

  confirmDevicePlacement() {
    // Implementation would add device to system
    console.log('Device placement confirmed at:', this.placementCoords);
    this.showNotification('Device placement confirmed', 'success');
    this.closeModal('device-placement-modal');
  }

  switchFloorPlan(planId) {
    if (planId === 'custom') {
      document.getElementById('floor-plan-modal').classList.add('active');
    } else {
      this.loadFloorPlan(planId);
    }
  }

  async loadFloorPlan(planId) {
    // Implementation would load floor plan
    console.log('Loading floor plan:', planId);
    this.floorPlan = { url: `/static/floorplans/${planId}.jpg` };
    this.renderFloorPlan();
  }

  setupFloorPlanUpload() {
    // Implementation for floor plan upload
    console.log('Floor plan upload setup (placeholder)');
  }

  closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove('active');
    }
  }

  async apiCall(endpoint, options = {}) {
  const base = (window.EasyMeshController && window.EasyMeshController.apiBase) || '/api/v1';
  const url = `${base}${endpoint}`;
  const resp = await fetch(url, {
    method: options.method || 'GET',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    body: options.body ? JSON.stringify(options.body) : null
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
  return resp.json();
}

  showNotification(message, type = 'info') {
    if (typeof window.EasyMeshController !== 'undefined') {
      window.EasyMeshController.showNotification(message, type);
    } else {
      console.log(`${type.toUpperCase()}: ${message}`);
    }
  }
}

// Initialize coverage map when DOM is ready
window.CoverageMapInstance = null;

document.addEventListener('DOMContentLoaded', () => {
  // Initialize when coverage tab is first shown
  const coverageTab = document.querySelector('[data-tab="coverage"]');
  if (coverageTab) {
    coverageTab.addEventListener('click', () => {
      if (!window.CoverageMapInstance) {
        setTimeout(() => {
          window.CoverageMapInstance = new CoverageMap();
        }, 100);
      }
    });
  }
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CoverageMap;
}
