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
    this.updatedNetworkProfiles = [];
    this.radioConfigs = {};
    this.scanResults = {};
    this.isScanning = false;
    this.updateChannelConfig = {};
    this.currentEditingProfile = null;
    this.updatedProfileKeys = new Set();

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

    // Channel scanning
    const scanBtn = document.getElementById('wireless-scan-channels');
    if (scanBtn) {
      scanBtn.addEventListener('click', () => this.scanChannels());
    }

    // Save settings
    const saveBtn = document.getElementById('save-radio-settings');
    if (saveBtn) {
      saveBtn.addEventListener('click', () => this.saveRadioSettings());
    }

    // Save network profilesettings
    const ssidApplyBtn = document.getElementById('save-profile-settings');
    if (ssidApplyBtn) {
      ssidApplyBtn.addEventListener('click', () => this.saveNetworkProfileSettings());
    }

    // toggle eye button to show/hide passphase
    document.getElementById('toggle-passphrase').addEventListener('click', function () {
      const passInput = document.getElementById('profile-passphrase');
      const isHidden = passInput.type === 'password';
      passInput.type = isHidden ? 'text' : 'password';

      this.classList.toggle('active', isHidden);
      this.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
    });

    // Advanced feature toggles
    this.setupAdvancedFeatureHandlers();
  }

  /**
   * update network profile apply button state
  */
  updateProfileApplyButtonState() {
    // Enable only if at least one profile has been updated
    const shouldEnable = this.updatedProfileKeys.size > 0;

    const applyBtn = document.getElementById('save-profile-settings');
    if (applyBtn) {
      applyBtn.disabled = !shouldEnable;
    }
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
      this.networkProfiles = profilesResponse.haulConfig || [];
      this.updatedNetworkProfiles = JSON.parse(JSON.stringify(this.networkProfiles));

      // Load radio configurations
      const radioResponse = await this.apiCall('/wireless/radios');
      this.radioConfigs = radioResponse.radios || {};

      // Load advanced settings
      const advancedResponse = await this.apiCall('/wireless/advanced');
      this.advancedSettings = advancedResponse.settings || {};

      // clear updatedProfileKeys
      this.updatedProfileKeys.clear();
      this.updateProfileApplyButtonState();

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

    if (this.updatedNetworkProfiles.length === 0) {
      grid.innerHTML = `
        <div class="empty-state">
          <i class="fas fa-wifi"></i>
          <h4>No Network Profiles</h4>
        </div>
      `;
      return;
    }

    this.updatedNetworkProfiles.forEach(profile => {
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
    let profileName = profile.HaulType
    if (profileName == "Fronthaul") {
      profileName = "Home Network"
    } else if (profileName == "IoT") {
      profileName = "IOT"
    }

    const securityIcon = this.getSecurityIcon(profile.Security);
    const bands = profile.Band;
    const bandString = bands.length ? bands.join(', ') : 'N/A';

    // toggle should be disabled (greyed out) for backhaul
    const isMeshBackhaul = profile.HaulType === 'Backhaul';

    card.innerHTML = `
      <div class="profile-header">
        <div class="profile-info">
          <h4>${profileName}</h4>
          <div class="profile-ssid">${profile.SSID}</div>
        </div>
        <div class="profile-disable">
          <label class="toggle-switch ${isMeshBackhaul ? 'toggle-disabled' : ''}" ${isMeshBackhaul ? 'aria-disabled="true"' : ''}>
            <input
              type="checkbox"
              id="profile_enable_disable"
              ${profile.Enable ? 'checked' : ''}
              aria-checked="${profile.Enable ? 'true' : 'false'}"
              ${isMeshBackhaul ? 'disabled' : ''}
              title="${isMeshBackhaul ? 'Backhaul settings are managed automatically' : 'Enable/disable this profile'}"
            >
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>
      <div class="profile-details">
        <div class="profile-detail">
          <span class="label">Security</span>
          <span class="value">
            <i class="fas ${securityIcon}"></i>
            ${profile.Security}
          </span>
        </div>
        <div class="profile-detail">
          <span class="label">VLAN</span>
          <span class="value">${profile.vlanId || 0}</span>
        </div>
        <div class="profile-detail">
          <span class="label">Bands</span>
          <span class="value">${bandString}</span>
        </div>
      </div>
      <div class="profile-actions">
        <button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); window.WirelessSettings.editProfile('${profile.HaulType}')"
         ${profile.Enable ? '' : 'disabled aria-disabled="true"'}
          title="${profile.Enable ? 'Edit profile' : 'Enable the profile to edit'}">
          <i class="fas fa-edit"></i>
          Edit
        </button>
      </div>
    `;

    // event listener for toggle button
    const toggleInput = card.querySelector('#profile_enable_disable');
    if (toggleInput && !isMeshBackhaul) {
      toggleInput.addEventListener('click', (event) => {
        const isChecked = event.target.checked;

        // update the Enable state based on toggle button
        profile.Enable = isChecked;

        // Grey out the Edit button if profile is toggled to disabled.
        const editBtn = card.querySelector('.btn.btn-sm.btn-primary')
        if (editBtn) {
          editBtn.disabled = !isChecked;;
          editBtn.setAttribute('aria-disabled', String(!isChecked));
          editBtn.title = isChecked ? 'Edit profile' : 'Enable the profile to edit';
        }

        // Check if Enable state is changes as per original state.
        const index = this.networkProfiles.findIndex(p => p.HaulType === profile.HaulType);
        if (index !== -1) {
          if(this.networkProfiles[index].Enable !== profile.Enable) {
            this.updatedProfileKeys.add(this.networkProfiles[index].Enable);
          } else {
            if (this.updatedProfileKeys.has(this.networkProfiles[index].Enable)) {
              this.updatedProfileKeys.delete(this.networkProfiles[index].Enable);
            }
          }
        }
        // Enable/diable the Apply button if state is changed.
        this.updateProfileApplyButtonState();
      });
    }
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
    // Validate for empty radioConfigs
    if (!Array.isArray(this.radioConfigs)) {
      console.warn('radioConfigs is not an array:', this.radioConfigs);
      this.updateChannelConfig = {};
      // Toggle enable button to disable
      this.setAllRadioPanelsDisabled(true);
      return;
    }

    if (!this.updateChannelConfig) this.updateChannelConfig = {};

    this.radioConfigs.forEach((config) => {
      const bandLabel = String(config?.band ?? '').trim();
      if (!bandLabel) {
        console.warn('Missing band label in config:', config);
      }

      // Normalize band key to match with html IDs
      const bandKey = bandLabel.replace('.', '_').replace(/ghz/i, 'g');
      const bandIndex = this.getRadioIndexFromBand(bandKey);

      // ---- DOM elements ----
      const radioEnabledToggle = document.getElementById(`radio-${bandKey}-enabled`);
      const operatingClassSelect = document.getElementById(`radio-${bandKey}-class`);
      const manualChannel = document.getElementById(`channel-${bandKey}-manual`);
      const panel = document.getElementById(`radio-${bandKey}hz`);

      if (!radioEnabledToggle) {
        console.warn(`Missing #radio-${bandKey}-enabled element`);
        return;
      } else {
          // Initialize toggle from config.enabled (default false)
          const isEnabled = Boolean(config?.enabled);
          radioEnabledToggle.checked = isEnabled;

          if (panel) {
            operatingClassSelect.disabled = !isEnabled;
            panel.classList.toggle('disabled', !isEnabled);
          }

          // Avoid duplicate listeners if function runs multiple times
          radioEnabledToggle.onchange = null;
          radioEnabledToggle.addEventListener('change', (e) => {
          const checked = Boolean(e.target.checked);
          config.enabled = checked;

          // Disable class/channel controls when radio is off
          if (operatingClassSelect) operatingClassSelect.disabled = !checked;
          if (manualChannel) manualChannel.disabled = !checked || Boolean(config?.auto_channel);

          if (panel) panel.classList.toggle('disabled', !checked);
        }, { once: false });
      }

      if (!operatingClassSelect) {
        console.warn(`Missing #radio-${bandKey}-class element`);
        return;
      }
      if (!manualChannel) {
        console.warn(`Missing #channel-${bandKey}-manual element`);
        return;
      }

      // Supported operating classes
      const supportedClass = Array.isArray(config.supported_class) ? config.supported_class : [];

      // Previously selected class and channel
      const prevSelectedClass    = String(config?.selected_config?.class ?? '').trim();
      const PrevSelectedChannel = Array.isArray(config.selected_config.channels)
        ? String(config.selected_config.channels[0] ?? '') : '';

      // Clear the previous options fo operating class.
      operatingClassSelect.innerHTML = '';

      if (supportedClass.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'No classes available';
        opt.disabled = true;
        opt.selected = true;
        operatingClassSelect.appendChild(opt);

        // Also clear channels
        manualChannel.innerHTML = '';
        manualChannel.disabled = true;
        console.warn(`No supported_class for ${bandLabel}`);
        return;
      }

      // Build class options,
      const classFrag = document.createDocumentFragment();
      supportedClass.forEach((clsObj, idx) => {
        const clsValue = String(clsObj?.class ?? '').trim();
        if (!clsValue) {
          console.warn(`Missing "class" in supported_class[${idx}] for ${bandLabel}`, clsObj);
          return;
        }
        const opt = document.createElement('option');
        opt.value = clsValue;
        opt.textContent = clsValue;
        classFrag.appendChild(opt);
      });
      operatingClassSelect.appendChild(classFrag);

      // Respect auto_channel
      manualChannel.disabled = Boolean(config?.auto_channel);

      const populateChannelsForClass = (classValue) => {
        const classValueStr = String(classValue).trim();

        if (!this.updateChannelConfig[bandIndex]) {
          this.updateChannelConfig[bandIndex] = {channels: [], class: '', radio_index: -1 };
        }
        this.updateChannelConfig[bandIndex].class = parseInt(classValueStr, 10) || 0;
        this.updateChannelConfig[bandIndex].radio_index = bandIndex;

        // Clear channel options
        while (manualChannel.firstChild) manualChannel.removeChild(manualChannel.firstChild);

        const clsObj = supportedClass.find(sc => String(sc?.class) === classValueStr);

        if (!clsObj) {
          const opt = document.createElement('option');
          opt.value = '';
          opt.textContent = 'No channels available for selected class';
          opt.disabled = true;
          opt.selected = true;
          manualChannel.appendChild(opt);
          this.updateChannelConfig[bandIndex].channels = [];
          console.warn(`[${bandKey}] Class not found:`, classValueStr, supportedClass);
          return;
        }

        const channels = Array.isArray(clsObj.supported_channels) ? clsObj.supported_channels : [];

        if (channels.length === 0) {
          const opt = document.createElement('option');
          opt.value = '';
          opt.textContent = 'No channels available';
          opt.disabled = true;
          opt.selected = true;
          manualChannel.appendChild(opt);
          console.warn(`[${bandKey}] No supported_channels for class ${classValueStr}`);
          return;
        }

        // Build options efficiently
        const chanFrag = document.createDocumentFragment();
        channels.forEach((ch) => {
          const s = String(ch);
          const opt = document.createElement('option');
          opt.value = s;
          opt.textContent = s;
          chanFrag.appendChild(opt);
        });
        manualChannel.appendChild(chanFrag);

        const channelStrings = new Set(channels.map(String));
        const currentValue = manualChannel.value;

        let initialChannelValue = '';
       if (PrevSelectedChannel && channelStrings.has(String(PrevSelectedChannel))) {
          initialChannelValue = String(PrevSelectedChannel);
        } else if (currentValue && channelStrings.has(String(currentValue))) {
          initialChannelValue = String(currentValue);
        } else {
          initialChannelValue = String(channels[0]);
        }

        manualChannel.value = initialChannelValue;
        this.updateChannelConfig[bandIndex].channels = initialChannelValue
                    ? [Number.parseInt(initialChannelValue, 10)]: [];


        // Attach listener on channel change
        if (!manualChannel.__channelListenerAttached) {
          manualChannel.addEventListener('change', (e) => {
            const raw = e.target?.value ?? '';
            const newChannel = raw.trim();
            const nextChannels = newChannel ? [Number.parseInt(newChannel, 10)] : [];
            this.updateChannelConfig[bandIndex] = {...this.updateChannelConfig[bandIndex], channels: nextChannels};
            console.log(`[${bandKey}] channel changed ->`, nextChannels);

          });
          manualChannel.__channelListenerAttached = true;
        }
      };

      // ----- Initial selection & population -----
      const prevStr = String(prevSelectedClass).trim();
      const selectStr = String(operatingClassSelect.value).trim();

      const initialClassValue = (prevStr === "0") ? selectStr : prevStr;

      operatingClassSelect.value = initialClassValue;
      populateChannelsForClass(initialClassValue);

      // ----- Class change listener
      operatingClassSelect.onchange = null;

      operatingClassSelect.addEventListener('change', (e) => {
        const newVal = String(e.target.value);
        console.log(`[${bandKey}] class changed:`, newVal);

        if (!this.updateChannelConfig[bandIndex]) {
          this.updateChannelConfig[bandIndex] = {class: parseInt(newVal, 10), channels: [] , radio_index: bandIndex};
        } else {
          this.updateChannelConfig[bandIndex].class = parseInt(newVal, 10);
        }

        populateChannelsForClass(newVal);
      }, { once: false });
    });
  }

  setAllRadioPanelsDisabled(disabled = true) {
    const panelIds = ['2_4g', '5g', '6g'];
    panelIds.forEach((pid) => {
      const panel = document.getElementById(`radio-${pid}hz`);
      if (!panel) {
        console.warn(`Panel #${pid} not found`);
        return;
      }
      const radioEnabledToggle = document.getElementById(`radio-${pid}-enabled`);
      const operatingClassSelect = document.getElementById(`radio-${pid}-class`);
      const manualChannel = document.getElementById(`channel-${pid}-manual`);
      radioEnabledToggle.checked = false;
      operatingClassSelect.disabled = disabled;
      manualChannel.disabled = disabled;
    });
  }

getRadioIndexFromBand(bandLabel) {
  const s = String(bandLabel || '').toLowerCase().trim();
  if (s.includes('2_4g')) return 0;
  if (s.includes('5g'))   return 1;
  if (s.includes('6g'))   return 2;
  // Fallback (if band not recognized)
  return -1;
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
      const profile = this.updatedNetworkProfiles.find(p => p.HaulType === profileId);
      if (profile) {
        title.textContent = 'Edit Network Profile';
        this.populateProfileForm(profile);
      }
    } else {
        console.error('Could not found a valid network profile: ', profileId);
        this.showNotification('Could not found a valid network profile', 'profileId');
    }

    modal.classList.add('active');
  }

  /**
   * Populate profile form with data
   */
  populateProfileForm(profile) {
    let profileName = profile.HaulType
    if (profileName == "Fronthaul") {
      profileName = "Home Network"
    } else if (profileName == "IoT") {
      profileName = "IOT"
    }

    document.getElementById('profile-name').value = profileName || '';
    document.getElementById('profile-ssid').value = profile.SSID || '';
    document.getElementById('profile-security').value = profile.Security || '';
    document.getElementById('profile-passphrase').value = profile.PassPhrase || '';
    document.getElementById('profile-vlan').value = profile.vlanId || 0;
    document.getElementById('profile-hidden').checked = profile.hidden || false;

    // hide the passphrase by default
    const passInput = document.getElementById('profile-passphrase');
    const toggleBtn = document.getElementById('toggle-passphrase');
    if (passInput.type === "text") {
      passInput.type = "password";
      toggleBtn?.setAttribute('aria-label', 'Show password');
      toggleBtn?.classList.toggle('active', false);
    }

    const selectedBands = Array.isArray(profile.Band) ? profile.Band.map(b => b) : [];

    // Clear Previous state for band
    document.getElementById('band-24').checked = false;
    document.getElementById('band-5').checked  = false;
    document.getElementById('band-6').checked  = false;

    // Set updated value as per available band
    if (selectedBands.includes('2.4GHz')) {
      document.getElementById('band-24').checked = true;
    }
    if (selectedBands.includes('5GHz')) {
      document.getElementById('band-5').checked = true;
    }
    if (selectedBands.includes('6GHz')) {
      document.getElementById('band-6').checked = true;
    }
  }

  /**
   * Handle security type change in modal
   */
  handleSecurityTypeChange(securityType) {
    const passphraseGroup = document.getElementById('passphrase-group');
    if (!passphraseGroup) return;
    const needsPassphrase = [
      'WPA2 Personal',
      'WPA3 Personal',
      'WPA3 Transition'
    ].includes(securityType);

    passphraseGroup.style.display = needsPassphrase ? 'flex' : 'none';
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
    
    const form = event.target;
    const formData = new FormData(form);
    const selectedBands = Array.from(
        form.querySelectorAll('input[name="bands"]:checked')).map(el => el.value);

    const profileData = {
      name: formData.get('profile-name') || document.getElementById('profile-name').value,
      ssid: formData.get('profile-ssid') || document.getElementById('profile-ssid').value,
      security_type: document.getElementById('profile-security').value,
      passphrase: document.getElementById('profile-passphrase').value,
      vlan_id: parseInt(document.getElementById('profile-vlan').value),
      hidden: document.getElementById('profile-hidden').checked,
      selectedBands,
      enabled: true
    };

    // Store updated data locally, will send complete update on apply button
    if (this.currentEditingProfile) {
      const index = this.networkProfiles.findIndex(p => p.HaulType === this.currentEditingProfile);
        if (index !== -1) {
          if((profileData.ssid !== this.networkProfiles[index].SSID) || 
             (profileData.passphrase !== this.networkProfiles[index].PassPhrase) ||
             (profileData.security_type!== this.networkProfiles[index].security_type)) {
              this.updatedProfileKeys.add(this.networkProfiles[index].HaulType);
          } else {
            if (this.updatedProfileKeys.has(this.networkProfiles[index].HaulType)) {
              this.updatedProfileKeys.delete(this.networkProfiles[index].HaulType);
            }
          }
          const updateIndex = this.updatedNetworkProfiles.findIndex(p => p.HaulType === this.currentEditingProfile);
            if (updateIndex !== -1) {
              this.updatedNetworkProfiles[updateIndex].SSID = profileData.ssid;
              this.updatedNetworkProfiles[updateIndex].PassPhrase = profileData.passphrase;
              this.updatedNetworkProfiles[updateIndex].Security = profileData.security_type;
              this.updatedNetworkProfiles[updateIndex].vlanId = profileData.vlan_id;
            }
        }
    }

    this.showNotification(
        this.currentEditingProfile ? 'Profile updated locally' : 'Profile created locally',
        'info'
    );

    this.updateProfileApplyButtonState();
    this.updateNetworkProfiles();
    this.closeModal('network-profile-modal');
  }

  /**
   * Edit profile
   */
  editProfile(profileId) {
    this.showProfileModal(profileId);
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
   * Send updated network profiles to backend 
  */
  async saveNetworkProfileSettings() {
    const saveBtn = document.getElementById('save-profile-settings');

    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
    }

    try {
      const settings = this.updatedNetworkProfiles;

      const response = await this.apiCall('/wireless/profiles', {
        method: 'POST',
        body: settings
      });

      if (response.success) {
        this.showNotification('Wireless network profile saved successfully', 'success');
        await this.loadWirelessSettings();
        this.updateAllDisplays();
      }
    } catch (error) {
      console.error('Failed to save wireless settings:', error);
      this.showNotification('Failed to save wireless network profile  settings', 'error');
    } finally {
      if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<i class="fas fa-save"></i> Apply Network profile';
      }
    }
  }
  /**
   * Save wireless settings
   */
  async saveRadioSettings() {
    const saveBtn = document.getElementById('save-radio-settings');
    
    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
    }

    try {
      const settings = this.updateChannelConfig;
      const channelConfigs = Object.values(settings).map(cfg => {
        const radioIndex = typeof cfg.radio_index === 'string'
          ? parseInt(cfg.radio_index, 10) : cfg.radio_index;

        const classVal = typeof cfg.class === 'string'
          ? parseInt(cfg.class, 10) : cfg.class;

        // Ensure channels is an array of integers
        const channels = Array.isArray(cfg.channels)
          ? cfg.channels.map(ch => (typeof ch === 'string' ? parseInt(ch, 10) : ch)) : [];

        return {
          radio_index: Number.isInteger(radioIndex) ? radioIndex : 0,
          class: Number.isInteger(classVal) ? classVal : 0,
          channels,
        };
      });

      console.log('Updating channel config: ', channelConfigs);
      
      const response = await this.apiCall('/wireless/radios', {
        method: 'POST',
        body: channelConfigs
      });

      if (response.success) {
        this.showNotification('Wireless settings saved successfully', 'success');
        this.updateChannelConfig = {};
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
