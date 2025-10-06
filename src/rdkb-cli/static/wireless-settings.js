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
 * Wireless Settings Module - JavaScript functionality
 * Handles all wireless configuration features
 */

class WirelessSettings {
  constructor() {
    this.networkProfiles = [];
    this.radioConfigs = {};
    this.scanResults = {};
    this.isScanning = false;
    this.currentEditingProfile = null;

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.init());
    } else {
      this.init();
    }
  }

  /**
   * Initialize wireless settings
   */
  async init() {
    console.log('🔧 Initializing Wireless Settings');
    
    this.setupEventHandlers();
    await this.loadWirelessSettings();
    this.updateAllDisplays();
  }

  /**
   * Setup all event handlers
   */
  setupEventHandlers() {
    // Radio band tab switching
    document.querySelectorAll('.radio-tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.switchRadioBand(e.target.dataset.band);
      });
    });

    // Channel mode toggles
    document.querySelectorAll('input[name^="channel-"][name$="-mode"]').forEach(radio => {
      radio.addEventListener('change', (e) => {
        this.handleChannelModeChange(e.target);
      });
    });

    // Power mode toggles
    document.querySelectorAll('input[name^="power-"][name$="-mode"]').forEach(radio => {
      radio.addEventListener('change', (e) => {
        this.handlePowerModeChange(e.target);
      });
    });

    // Power sliders
    document.querySelectorAll('input[type="range"][id*="power"]').forEach(slider => {
      slider.addEventListener('input', (e) => {
        this.updatePowerDisplay(e.target);
      });
    });

    // Network profile management
    const addProfileBtn = document.getElementById('add-network-profile');
    if (addProfileBtn) {
      addProfileBtn.addEventListener('click', () => this.showProfileModal());
    }

    const profileForm = document.getElementById('network-profile-form');
    if (profileForm) {
      profileForm.addEventListener('submit', (e) => this.saveNetworkProfile(e));
    }

    // Security type changes in profile modal
    const securitySelect = document.getElementById('profile-security');
    if (securitySelect) {
      securitySelect.addEventListener('change', (e) => {
        this.handleSecurityTypeChange(e.target.value);
      });
    }

    // Guest network toggle
    const guestToggle = document.getElementById('profile-guest');
    if (guestToggle) {
      guestToggle.addEventListener('change', (e) => {
        this.handleGuestNetworkToggle(e.target.checked);
      });
    }

    // Channel scanning
    const scanBtn = document.getElementById('wireless-scan-channels');
    if (scanBtn) {
      scanBtn.addEventListener('click', () => this.scanChannels());
    }

    // Save settings
    const saveBtn = document.getElementById('save-wireless-settings');
    if (saveBtn) {
      saveBtn.addEventListener('click', () => this.saveWirelessSettings());
    }

    // Advanced feature toggles
    this.setupAdvancedFeatureHandlers();
  }

  /**
   * Setup handlers for advanced features
   */
  setupAdvancedFeatureHandlers() {
    const advancedFeatures = [
      'band-steering-enabled',
      'load-balancing-enabled',
      'ofdma-enabled',
      'mu-mimo-enabled',
      'beamforming-enabled',
      'twt-enabled',
      'airtime-fairness-enabled',
      'fast-transition-enabled',
      'mlo-enabled',
      'multi-ru-enabled',
      'punctured-preamble'
    ];

    advancedFeatures.forEach(featureId => {
      const toggle = document.getElementById(featureId);
      if (toggle) {
        toggle.addEventListener('change', (e) => {
          this.handleAdvancedFeatureToggle(featureId, e.target.checked);
        });
      }
    });
  }

  /**
   * Switch radio band tab
   */
  switchRadioBand(band) {
    // Update tab buttons
    document.querySelectorAll('.radio-tab-btn').forEach(btn => {
      btn.classList.remove('active');
    });
    document.querySelector(`[data-band="${band}"]`).classList.add('active');

    // Show corresponding panel
    document.querySelectorAll('.radio-config-panel').forEach(panel => {
      panel.classList.remove('active');
    });
    document.getElementById(`radio-${band}`).classList.add('active');

    // Update scan results if available
    this.updateScanResults(band);
  }

  /**
   * Handle channel mode changes (auto/manual)
   */
  handleChannelModeChange(radioInput) {
    const band = this.extractBandFromName(radioInput.name);
    const isManual = radioInput.value === 'manual';
    const manualSelect = document.getElementById(`channel-${band}-manual`);
    
    if (manualSelect) {
      manualSelect.disabled = !isManual;
      if (isManual) {
        manualSelect.focus();
      }
    }
  }

  /**
   * Handle power mode changes (auto/manual)
   */
  handlePowerModeChange(radioInput) {
    const band = this.extractBandFromName(radioInput.name);
    const isManual = radioInput.value === 'manual';
    const manualSlider = document.getElementById(`power-${band}-manual`);
    
    if (manualSlider) {
      manualSlider.disabled = !isManual;
      if (isManual) {
        this.updatePowerDisplay(manualSlider);
      }
    }
  }

  /**
   * Update power display value
   */
  updatePowerDisplay(slider) {
    const valueSpan = slider.parentElement.querySelector('.power-value');
    if (valueSpan) {
      valueSpan.textContent = `${slider.value} dBm`;
    }
  }

  /**
   * Extract band name from input name attribute
   */
  extractBandFromName(name) {
    if (name.includes('2g4')) return '2g4';
    if (name.includes('5g')) return '5g';
    if (name.includes('6g')) return '6g';
    return '';
  }

  /**
   * Load wireless settings from API
   */
  async loadWirelessSettings() {
    try {
      // Load network profiles
      const profilesResponse = await this.apiCall('/wireless/profiles');
      this.networkProfiles = profilesResponse.profiles || [];

      // Load radio configurations
      const radioResponse = await this.apiCall('/wireless/radios');
      this.radioConfigs = radioResponse.radios || {};

      // Load advanced settings
      const advancedResponse = await this.apiCall('/wireless/advanced');
      this.advancedSettings = advancedResponse.settings || {};

      console.log('✅ Wireless settings loaded successfully');
    } catch (error) {
      console.error('❌ Failed to load wireless settings:', error);
      this.showNotification('Failed to load wireless settings', 'error');
    }
  }

  /**
   * Update all wireless displays
   */
  updateAllDisplays() {
    this.updateNetworkProfiles();
    this.updateRadioConfigurations();
    this.updateAdvancedSettings();
  }

  /**
   * Update network profiles display
   */
  updateNetworkProfiles() {
    const grid = document.getElementById('network-profiles-grid');
    if (!grid) return;

    grid.innerHTML = '';

    if (this.networkProfiles.length === 0) {
      grid.innerHTML = `
        <div class="empty-state">
          <i class="fas fa-wifi"></i>
          <h4>No Network Profiles</h4>
          <p>Create your first network profile to get started</p>
        </div>
      `;
      return;
    }

    this.networkProfiles.forEach(profile => {
      const profileCard = this.createProfileCard(profile);
      grid.appendChild(profileCard);
    });
  }

  /**
   * Create network profile card
   */
  createProfileCard(profile) {
    const card = document.createElement('div');
    card.className = `profile-card ${profile.enabled ? 'active' : ''}`;
    card.onclick = () => this.editProfile(profile.id);

    const securityIcon = this.getSecurityIcon(profile.security_type);
    const bandInfo = this.getBandInfo(profile);

    card.innerHTML = `
      <div class="profile-header">
        <div class="profile-info">
          <h4>${profile.name}</h4>
          <div class="profile-ssid">${profile.ssid}</div>
        </div>
        <div class="profile-status ${profile.enabled ? 'enabled' : 'disabled'}">
          <i class="fas fa-circle"></i>
          ${profile.enabled ? 'Enabled' : 'Disabled'}
        </div>
      </div>

      <div class="profile-details">
        <div class="profile-detail">
          <span class="label">Security</span>
          <span class="value">
            <i class="fas ${securityIcon}"></i>
            ${profile.security_type}
          </span>
        </div>
        <div class="profile-detail">
          <span class="label">VLAN</span>
          <span class="value">${profile.vlan_id || 1}</span>
        </div>
        <div class="profile-detail">
          <span class="label">Bands</span>
          <span class="value">${bandInfo}</span>
        </div>
        <div class="profile-detail">
          <span class="label">Clients</span>
          <span class="value">${this.getProfileClientCount(profile.ssid)}</span>
        </div>
      </div>

      <div class="profile-actions">
        <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); window.WirelessSettings.toggleProfile('${profile.id}')">
          <i class="fas fa-power-off"></i>
          ${profile.enabled ? 'Disable' : 'Enable'}
        </button>
        <button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); window.WirelessSettings.editProfile('${profile.id}')">
          <i class="fas fa-edit"></i>
          Edit
        </button>
        <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); window.WirelessSettings.deleteProfile('${profile.id}')">
          <i class="fas fa-trash"></i>
          Delete
        </button>
      </div>
    `;

    return card;
  }

  /**
   * Get security icon based on type
   */
  getSecurityIcon(securityType) {
    const icons = {
      'WPA3-SAE': 'fa-shield-alt',
      'WPA3-Enterprise': 'fa-shield-alt',
      'WPA2-PSK': 'fa-lock',
      'Enhanced-Open': 'fa-unlock-alt',
      'Open': 'fa-unlock'
    };
    return icons[securityType] || 'fa-lock';
  }

  /**
   * Get band information for profile
   */
  getBandInfo(profile) {
    const bands = [];
    if (profile.bands) {
      if (profile.bands.includes('2.4GHz')) bands.push('2.4G');
      if (profile.bands.includes('5GHz')) bands.push('5G');
      if (profile.bands.includes('6GHz')) bands.push('6G');
    } else {
      bands.push('All');
    }
    return bands.join(', ');
  }

  /**
   * Get client count for profile
   */
  getProfileClientCount(ssid) {
    if (typeof window.EasyMeshController !== 'undefined') {
      return window.EasyMeshController.clients.filter(client => 
        client.ssid === ssid
      ).length;
    }
    return 0;
  }

  /**
   * Update radio configurations
   */
  updateRadioConfigurations() {
    Object.entries(this.radioConfigs).forEach(([band, config]) => {
      const bandKey = band.replace('.', '').replace('GHz', 'g');
      
      // Update radio enabled status
      const enabledToggle = document.getElementById(`radio-${bandKey}-enabled`);
      if (enabledToggle) enabledToggle.checked = config.enabled;

      // Update channel settings
      const channelMode = config.auto_channel ? 'auto' : 'manual';
      const channelRadio = document.querySelector(`input[name="channel-${bandKey}-mode"][value="${channelMode}"]`);
      if (channelRadio) channelRadio.checked = true;

      const manualChannel = document.getElementById(`channel-${bandKey}-manual`);
      if (manualChannel) {
        manualChannel.value = config.channel;
        manualChannel.disabled = config.auto_channel;
      }

      // Update channel width
      const channelWidth = document.getElementById(`channel-width-${bandKey}`);
      if (channelWidth) channelWidth.value = config.channel_width;

      // Update power settings
      const powerMode = config.tx_power_auto ? 'auto' : 'manual';
      const powerRadio = document.querySelector(`input[name="power-${bandKey}-mode"][value="${powerMode}"]`);
      if (powerRadio) powerRadio.checked = true;

      const manualPower = document.getElementById(`power-${bandKey}-manual`);
      if (manualPower) {
        manualPower.value = config.tx_power_dbm;
        manualPower.disabled = config.tx_power_auto;
        this.updatePowerDisplay(manualPower);
      }
    });
  }

  /**
   * Update advanced settings
   */
  updateAdvancedSettings() {
    if (!this.advancedSettings) return;

    // Update feature toggles
    const featureMap = {
      'band-steering-enabled': this.advancedSettings.band_steering,
      'load-balancing-enabled': this.advancedSettings.load_balancing,
      'ofdma-enabled': this.advancedSettings.ofdma,
      'mu-mimo-enabled': this.advancedSettings.mu_mimo,
      'beamforming-enabled': this.advancedSettings.beamforming,
      'twt-enabled': this.advancedSettings.twt,
      'airtime-fairness-enabled': this.advancedSettings.airtime_fairness,
      'fast-transition-enabled': this.advancedSettings.fast_transition,
      'mlo-enabled': this.advancedSettings.mlo,
      'multi-ru-enabled': this.advancedSettings.multi_ru,
      'punctured-preamble': this.advancedSettings.punctured_preamble
    };

    Object.entries(featureMap).forEach(([toggleId, value]) => {
      const toggle = document.getElementById(toggleId);
      if (toggle && value !== undefined) {
        toggle.checked = value;
      }
    });

    // Update other advanced settings
    const steeringPolicy = document.getElementById('steering-policy');
    if (steeringPolicy && this.advancedSettings.steering_policy) {
      steeringPolicy.value = this.advancedSettings.steering_policy;
    }

    const rssiThreshold = document.getElementById('rssi-threshold');
    if (rssiThreshold && this.advancedSettings.rssi_threshold) {
      rssiThreshold.value = this.advancedSettings.rssi_threshold;
    }
  }

  /**
   * Show network profile modal
   */
  showProfileModal(profileId = null) {
    const modal = document.getElementById('network-profile-modal');
    const title = document.getElementById('profile-modal-title');
    const form = document.getElementById('network-profile-form');
    
    if (!modal || !title || !form) return;

    this.currentEditingProfile = profileId;
    
    if (profileId) {
      const profile = this.networkProfiles.find(p => p.id === profileId);
      if (profile) {
        title.textContent = 'Edit Network Profile';
        this.populateProfileForm(profile);
      }
    } else {
      title.textContent = 'Add Network Profile';
      form.reset();
      this.handleSecurityTypeChange('WPA3-SAE');
    }

    modal.classList.add('active');
  }

  /**
   * Populate profile form with data
   */
  populateProfileForm(profile) {
    document.getElementById('profile-name').value = profile.name || '';
    document.getElementById('profile-ssid').value = profile.ssid || '';
    document.getElementById('profile-security').value = profile.security_type || 'WPA3-SAE';
    document.getElementById('profile-passphrase').value = profile.passphrase || '';
    document.getElementById('profile-vlan').value = profile.vlan_id || 1;
    document.getElementById('profile-hidden').checked = profile.hidden || false;
    document.getElementById('profile-guest').checked = profile.guest_network || false;
    
    if (profile.bandwidth_limit_mbps) {
      document.getElementById('profile-bandwidth').value = profile.bandwidth_limit_mbps;
    }

    this.handleSecurityTypeChange(profile.security_type);
    this.handleGuestNetworkToggle(profile.guest_network);
  }

  /**
   * Handle security type change in modal
   */
  handleSecurityTypeChange(securityType) {
    const passphraseGroup = document.getElementById('passphrase-group');
    if (passphraseGroup) {
      const needsPassphrase = ['WPA3-SAE', 'WPA2-PSK'].includes(securityType);
      passphraseGroup.style.display = needsPassphrase ? 'flex' : 'none';
    }
  }

  /**
   * Handle guest network toggle in modal
   */
  handleGuestNetworkToggle(isGuest) {
    const bandwidthGroup = document.getElementById('bandwidth-limit-group');
    if (bandwidthGroup) {
      bandwidthGroup.style.display = isGuest ? 'flex' : 'none';
    }
  }

  /**
   * Save network profile
   */
  async saveNetworkProfile(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const profileData = {
      name: formData.get('profile-name') || document.getElementById('profile-name').value,
      ssid: formData.get('profile-ssid') || document.getElementById('profile-ssid').value,
      security_type: document.getElementById('profile-security').value,
      passphrase: document.getElementById('profile-passphrase').value,
      vlan_id: parseInt(document.getElementById('profile-vlan').value),
      hidden: document.getElementById('profile-hidden').checked,
      guest_network: document.getElementById('profile-guest').checked,
      enabled: true
    };

    if (profileData.guest_network) {
      const bandwidthLimit = document.getElementById('profile-bandwidth').value;
      if (bandwidthLimit) {
        profileData.bandwidth_limit_mbps = parseInt(bandwidthLimit);
      }
    }

    try {
      let response;
      if (this.currentEditingProfile) {
        response = await this.apiCall(`/wireless/profiles/${this.currentEditingProfile}`, {
          method: 'PUT',
          body: profileData
        });
      } else {
        response = await this.apiCall('/wireless/profiles', {
          method: 'POST',
          body: profileData
        });
      }

      if (response.success) {
        this.showNotification(
          this.currentEditingProfile ? 'Profile updated successfully' : 'Profile created successfully',
          'success'
        );
        
        await this.loadWirelessSettings();
        this.updateNetworkProfiles();
        this.closeModal('network-profile-modal');
      }
    } catch (error) {
      console.error('Failed to save profile:', error);
      this.showNotification('Failed to save profile', 'error');
    }
  }

  /**
   * Edit profile
   */
  editProfile(profileId) {
    this.showProfileModal(profileId);
  }

  /**
   * Toggle profile enabled/disabled
   */
  async toggleProfile(profileId) {
    const profile = this.networkProfiles.find(p => p.id === profileId);
    if (!profile) return;

    try {
      const response = await this.apiCall(`/wireless/profiles/${profileId}/toggle`, {
        method: 'POST'
      });

      if (response.success) {
        profile.enabled = !profile.enabled;
        this.updateNetworkProfiles();
        this.showNotification(
          `Profile ${profile.enabled ? 'enabled' : 'disabled'}`,
          'success'
        );
      }
    } catch (error) {
      console.error('Failed to toggle profile:', error);
      this.showNotification('Failed to toggle profile', 'error');
    }
  }

  /**
   * Delete profile
   */
  async deleteProfile(profileId) {
    const profile = this.networkProfiles.find(p => p.id === profileId);
    if (!profile) return;

    if (!confirm(`Are you sure you want to delete "${profile.name}"?`)) {
      return;
    }

    try {
      const response = await this.apiCall(`/wireless/profiles/${profileId}`, {
        method: 'DELETE'
      });

      if (response.success) {
        this.networkProfiles = this.networkProfiles.filter(p => p.id !== profileId);
        this.updateNetworkProfiles();
        this.showNotification('Profile deleted successfully', 'success');
      }
    } catch (error) {
      console.error('Failed to delete profile:', error);
      this.showNotification('Failed to delete profile', 'error');
    }
  }

  /**
   * Handle advanced feature toggle
   */
  handleAdvancedFeatureToggle(featureId, enabled) {
    console.log(`Advanced feature ${featureId}: ${enabled ? 'enabled' : 'disabled'}`);
    
    // Update internal state
    if (!this.advancedSettings) this.advancedSettings = {};
    
    const featureKey = featureId.replace(/-enabled$/, '').replace(/-/g, '_');
    this.advancedSettings[featureKey] = enabled;

    // Show notification for important features
    const importantFeatures = ['band-steering-enabled', 'load-balancing-enabled', 'mlo-enabled'];
    if (importantFeatures.includes(featureId)) {
      const featureName = featureId.replace(/-enabled$/, '').replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
      this.showNotification(`${featureName} ${enabled ? 'enabled' : 'disabled'}`, 'info');
    }
  }

  /**
   * Scan channels
   */
  async scanChannels() {
    if (this.isScanning) return;
    
    this.isScanning = true;
    const scanBtn = document.getElementById('wireless-scan-channels');
    
    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
    }

    try {
      this.showNotification('Starting channel scan...', 'info');
      
      const response = await this.apiCall('/wireless/scan', {
        method: 'POST',
        body: { scan_duration: 30 }
      });

      if (response.success) {
        this.scanResults = response.results || {};
        this.updateScanResults();
        this.showNotification('Channel scan completed', 'success');
      }
    } catch (error) {
      console.error('Channel scan failed:', error);
      this.showNotification('Channel scan failed', 'error');
    } finally {
      this.isScanning = false;
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fas fa-radar"></i> Scan Channels';
      }
    }
  }

  /**
   * Update scan results display
   */
  updateScanResults(currentBand = null) {
    if (!this.scanResults || Object.keys(this.scanResults).length === 0) return;

    // Get current active band if not specified
    if (!currentBand) {
      const activeTab = document.querySelector('.radio-tab-btn.active');
      currentBand = activeTab ? activeTab.dataset.band : '2.4ghz';
    }

    // Create or update scan results section
    let resultsSection = document.querySelector('.channel-scan-results');
    if (!resultsSection) {
      resultsSection = document.createElement('div');
      resultsSection.className = 'channel-scan-results';
      
      const activePanel = document.querySelector('.radio-config-panel.active');
      if (activePanel) {
        activePanel.appendChild(resultsSection);
      }
    }

    const bandData = this.scanResults[currentBand];
    if (!bandData) return;

    resultsSection.innerHTML = `
      <h4><i class="fas fa-radar"></i> Channel Scan Results - ${currentBand.replace('ghz', 'GHz').replace('.', '.')}</h4>
      <div class="scan-results-grid" id="scan-results-${currentBand}">
        ${this.generateScanResultsHTML(bandData)}
      </div>
    `;
  }

  /**
   * Generate scan results HTML
   */
  generateScanResultsHTML(bandData) {
    if (!bandData.channels) return '<p>No scan data available</p>';

    return bandData.channels.map(channel => {
      const utilization = channel.utilization || 0;
      const utilizationClass = utilization > 70 ? 'high' : utilization > 40 ? 'medium' : 'low';
      const statusClass = utilization > 70 ? 'occupied' : utilization < 20 ? 'recommended' : '';

      return `
        <div class="channel-result ${statusClass}">
          <div class="channel-number">${channel.channel}</div>
          <div class="channel-frequency">${channel.frequency} MHz</div>
          <div class="channel-utilization">${utilization}%</div>
          <div class="utilization-bar">
            <div class="utilization-fill ${utilizationClass}" style="width: ${utilization}%"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  /**
   * Save wireless settings
   */
  async saveWirelessSettings() {
    const saveBtn = document.getElementById('save-wireless-settings');
    
    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
    }

    try {
      const settings = this.collectAllSettings();
      
      const response = await this.apiCall('/wireless/config', {
        method: 'PUT',
        body: settings
      });

      if (response.success) {
        this.showNotification('Wireless settings saved successfully', 'success');
        await this.loadWirelessSettings();
        this.updateAllDisplays();
      }
    } catch (error) {
      console.error('Failed to save wireless settings:', error);
      this.showNotification('Failed to save wireless settings', 'error');
    } finally {
      if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.innerHTML = '<i class="fas fa-save"></i> Apply Settings';
      }
    }
  }

  /**
   * Collect all settings from form
   */
  collectAllSettings() {
    const settings = {
      radio_configs: this.collectRadioConfigs(),
      advanced_settings: this.collectAdvancedSettings(),
      network_profiles: this.networkProfiles
    };

    return settings;
  }

  /**
   * Collect radio configuration settings
   */
  collectRadioConfigs() {
    const configs = {};
    const bands = ['2g4', '5g', '6g'];

    bands.forEach(band => {
      const bandKey = band === '2g4' ? '2.4GHz' : band === '5g' ? '5GHz' : '6GHz';
      
      configs[bandKey] = {
        enabled: document.getElementById(`radio-${band}-enabled`)?.checked || false,
        auto_channel: document.querySelector(`input[name="channel-${band}-mode"]:checked`)?.value === 'auto',
        channel: parseInt(document.getElementById(`channel-${band}-manual`)?.value) || 1,
        channel_width: parseInt(document.getElementById(`channel-width-${band}`)?.value) || 20,
        tx_power_auto: document.querySelector(`input[name="power-${band}-mode"]:checked`)?.value === 'auto',
        tx_power_dbm: parseInt(document.getElementById(`power-${band}-manual`)?.value) || 20
      };

      // Band-specific settings
      if (band === '5g') {
        configs[bandKey].dfs_enabled = document.getElementById('dfs-enabled')?.checked || false;
      }

      if (band === '6g') {
        configs[bandKey].psc_only = document.getElementById('psc-only')?.checked || false;
        configs[bandKey].wifi7_features = {
          mlo_enabled: document.getElementById('mlo-enabled')?.checked || false,
          multi_ru_enabled: document.getElementById('multi-ru-enabled')?.checked || false,
          punctured_preamble: document.getElementById('punctured-preamble')?.checked || false
        };
      }
    });

    return configs;
  }

  /**
   * Collect advanced settings
   */
  collectAdvancedSettings() {
    return {
      band_steering: document.getElementById('band-steering-enabled')?.checked || false,
      load_balancing: document.getElementById('load-balancing-enabled')?.checked || false,
      steering_policy: document.getElementById('steering-policy')?.value || 'balanced',
      rssi_threshold: parseInt(document.getElementById('rssi-threshold')?.value) || -65,
      ofdma: document.getElementById('ofdma-enabled')?.checked || false,
      mu_mimo: document.getElementById('mu-mimo-enabled')?.checked || false,
      beamforming: document.getElementById('beamforming-enabled')?.checked || false,
      twt: document.getElementById('twt-enabled')?.checked || false,
      airtime_fairness: document.getElementById('airtime-fairness-enabled')?.checked || false,
      fast_transition: document.getElementById('fast-transition-enabled')?.checked || false
    };
  }

  /**
   * Close modal
   */
  closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove('active');
    }
    this.currentEditingProfile = null;
  }

  /**
   * Make API call
   */
 async apiCall(endpoint, options = {}) {
  const base = (window.EasyMeshController && window.EasyMeshController.apiBase) || '/api/v1';
  const url = `${base}${endpoint}`;
  try {
    const response = await fetch(url, {
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      body: options.body ? JSON.stringify(options.body) : null
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error(`API call failed for ${endpoint}:`, error);
    throw error;
  }
}

  /**
   * Show notification
   */
  showNotification(message, type = 'info') {
    if (typeof window.EasyMeshController !== 'undefined') {
      window.EasyMeshController.showNotification(message, type);
    } else {
      console.log(`${type.toUpperCase()}: ${message}`);
    }
  }
}

// Initialize wireless settings when script loads
window.WirelessSettings = new WirelessSettings();

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = WirelessSettings;
}
