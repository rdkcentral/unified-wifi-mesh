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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
        "math"
        "math/rand"
        "sort"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// ===== SIMPLIFIED DATA MODELS =====

type Device struct {
	MAC             string         `json:"mac"`
	Role            string         `json:"role"`
	Vendor          string         `json:"vendor"`
	Model           string         `json:"model"`
	IPAddress       string         `json:"ip_address"`
	Status          string         `json:"status"`
	LastSeen        time.Time      `json:"last_seen"`
	Uptime          string         `json:"uptime"`
	Capabilities    Capability     `json:"capabilities"`
	Metrics         DeviceMetrics  `json:"metrics"`
	SecurityProfile SecurityProfile `json:"security_profile"`
	Location        Location       `json:"location"`
}

type Capability struct {
	WiFi7Support   bool     `json:"wifi7_support"`
	MaxMeshLinks   int      `json:"max_mesh_links"`
	Firmware       string   `json:"firmware"`
	SerialNumber   string   `json:"serial_number"`
	SupportedBands []string `json:"supported_bands"`
}

type DeviceMetrics struct {
	CPUUsage         float64   `json:"cpu_usage_percent"`
	MemoryUsage      float64   `json:"memory_usage_percent"`
	Temperature      float64   `json:"temperature_celsius"`
	PowerConsumption float64   `json:"power_consumption_watts"`
	LastUpdated      time.Time `json:"last_updated"`
}

type Client struct {
	MAC            string        `json:"mac"`
	Hostname       string        `json:"hostname"`
	IPAddress      string        `json:"ip_address"`
	ConnectedAP    string        `json:"connected_ap_mac"`
	ConnectedBSSID string        `json:"connected_bssid"`
	ConnectionTime time.Time     `json:"connection_time"`
	DeviceType     string        `json:"device_type"`
	Manufacturer   string        `json:"manufacturer"`
	LastActivity   time.Time     `json:"last_activity"`
	ClientMetrics  ClientMetrics `json:"client_metrics"`
	Location       ClientLocation `json:"location"`
}

type ClientMetrics struct {
	RSSI        int       `json:"rssi_dbm"`
	SNR         int       `json:"snr_db"`
	TxRate      int       `json:"tx_rate_mbps"`
	RxRate      int       `json:"rx_rate_mbps"`
	Latency     float64   `json:"latency_ms"`
	DataUsage   uint64    `json:"data_usage_bytes"`
	LastUpdated time.Time `json:"last_updated"`
}

type Location struct {
	Building    string  `json:"building"`
	Floor       string  `json:"floor"`
	Room        string  `json:"room"`
	Description string  `json:"description"`
	Position3D  Point3D `json:"position_3d"`
}

type Point3D struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
	Z float64 `json:"z"`
}

type ClientLocation struct {
	EstimatedPosition Point3D   `json:"estimated_position"`
	ConnectedAP       string    `json:"connected_ap"`
	LastUpdate        time.Time `json:"last_update"`
	Accuracy          float64   `json:"accuracy_meters"`
}

type SecurityProfile struct {
	ProfileName    string `json:"profile_name"`
	AuthMethod     string `json:"auth_method"`
	EncryptionType string `json:"encryption_type"`
	SecurityLevel  string `json:"security_level"`
}

type MeshTopology struct {
	MeshID        string             `json:"mesh_id"`
	ControllerMAC string             `json:"controller_mac"`
	Nodes         int                `json:"nodes"`
	Protocol      string             `json:"protocol"`
	Version       string             `json:"version"`
	Performance   PerformanceMetrics `json:"performance"`
	LastUpdated   time.Time          `json:"last_updated"`
}

type PerformanceMetrics struct {
	AverageThroughput float64 `json:"average_throughput_mbps"`
	AverageLatency    float64 `json:"average_latency_ms"`
	TotalClients      int     `json:"total_clients"`
}

type SystemConfig struct {
	ControllerSettings ControllerSettings `json:"controller_settings"`
	SecuritySettings   SecuritySettings   `json:"security_settings"`
}

type ControllerSettings struct {
	AutoOptimization   bool `json:"auto_optimization"`
	ChannelPlanning    bool `json:"channel_planning"`
	PowerManagement    bool `json:"power_management"`
	FirmwareManagement bool `json:"firmware_management"`
}

type SecuritySettings struct {
	IntrusionDetection bool     `json:"intrusion_detection"`
	AccessControl      bool     `json:"access_control"`
	ThreatProtection   bool     `json:"threat_protection"`
	AllowedMACs        []string `json:"allowed_macs"`
	BlockedMACs        []string `json:"blocked_macs"`
}
//ckp start
type WirelessProfile struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	SSID              string            `json:"ssid"`
	SecurityType      string            `json:"security_type"`
	Passphrase        string            `json:"passphrase,omitempty"`
	VlanID            int               `json:"vlan_id"`
	Hidden            bool              `json:"hidden"`
	GuestNetwork      bool              `json:"guest_network"`
	Enabled           bool              `json:"enabled"`
	BandwidthLimitMbps int              `json:"bandwidth_limit_mbps,omitempty"`
	Bands             []string          `json:"bands"`
	CaptivePortal     *CaptivePortal    `json:"captive_portal,omitempty"`
	TimeRestriction   *TimeRestriction  `json:"time_restriction,omitempty"`
	DeviceIsolation   bool              `json:"device_isolation"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

type CaptivePortal struct {
	Enabled           bool   `json:"enabled"`
	SplashPage        string `json:"splash_page"`
	TermsAcceptance   bool   `json:"terms_acceptance"`
	SessionTimeoutMin int    `json:"session_timeout_minutes"`
}

type TimeRestriction struct {
	Enabled      bool     `json:"enabled"`
	AllowedHours string   `json:"allowed_hours"`
	AllowedDays  []string `json:"allowed_days"`
}

type RadioConfig struct {
	Band            string            `json:"band"`
	Enabled         bool              `json:"enabled"`
	AutoChannel     bool              `json:"auto_channel"`
	Channel         int               `json:"channel"`
	ChannelWidth    int               `json:"channel_width"`
	TxPowerAuto     bool              `json:"tx_power_auto"`
	TxPowerDbm      int               `json:"tx_power_dbm"`
	CountryCode     string            `json:"country_code"`
	BeaconInterval  int               `json:"beacon_interval_ms"`
	DTIMPeriod      int               `json:"dtim_period"`
	RTSThreshold    int               `json:"rts_threshold"`
	FragThreshold   int               `json:"fragmentation_threshold"`
	DFSEnabled      bool              `json:"dfs_enabled,omitempty"`
	PSCOnly         bool              `json:"psc_only,omitempty"`
	WiFi7Features   *WiFi7Features    `json:"wifi7_features,omitempty"`
	SupportedChannels []ChannelInfo   `json:"supported_channels"`
}
type WiFi7Features struct {
	MLOEnabled          bool `json:"mlo_enabled"`
	MultiRUEnabled      bool `json:"multi_ru_enabled"`
	PuncturedPreamble   bool `json:"punctured_preamble"`
	Support320MHz       bool `json:"support_320mhz"`
}

type ChannelInfo struct {
	Channel     int    `json:"channel"`
	Frequency   int    `json:"frequency_mhz"`
	DFSRequired bool   `json:"dfs_required"`
	MaxTxPower  int    `json:"max_tx_power_dbm"`
	Availability string `json:"availability"`
	Utilization  float64 `json:"utilization,omitempty"`
	NoiseFloor   int    `json:"noise_floor_dbm,omitempty"`
}

type AdvancedWirelessSettings struct {
	BandSteering     *BandSteeringConfig `json:"band_steering"`
	LoadBalancing    *LoadBalancingConfig `json:"load_balancing"`
	AirtimeFairness  bool                `json:"airtime_fairness"`
	FastTransition   bool                `json:"fast_transition"`
	OFDMA            bool                `json:"ofdma"`
	MUMIMO           bool                `json:"mu_mimo"`
	Beamforming      bool                `json:"beamforming"`
	TWT              bool                `json:"twt"`
	SpatialReuse     bool                `json:"spatial_reuse"`
	UpdatedAt        time.Time           `json:"updated_at"`
}

type BandSteeringConfig struct {
	Enabled               bool    `json:"enabled"`
	Policy                string  `json:"policy"` // conservative, balanced, aggressive
	RSSIThreshold2G4      int     `json:"rssi_threshold_2g4"`
	RSSIThreshold5G       int     `json:"rssi_threshold_5g"`
	RSSIThreshold6G       int     `json:"rssi_threshold_6g"`
	UtilizationThreshold  float64 `json:"utilization_threshold_percent"`
	BlockTimeSeconds      int     `json:"block_time_seconds"`
	ProbeResponseSuppress bool    `json:"probe_response_suppression"`
}

type LoadBalancingConfig struct {
	Enabled                   bool    `json:"enabled"`
	Algorithm                 string  `json:"algorithm"` // client_count, airtime_fairness, rssi_load_balanced
	RebalanceIntervalSeconds  int     `json:"rebalance_interval_seconds"`
	ClientCountThreshold      int     `json:"client_count_threshold"`
	UtilizationThreshold      float64 `json:"utilization_threshold_percent"`
	RSSIDifferenceThreshold   int     `json:"rssi_difference_threshold"`
}
type ChannelScanRequest struct {
	ScanDuration  int      `json:"scan_duration"` // seconds
	Bands         []string `json:"bands,omitempty"`
	PassiveScan   bool     `json:"passive_scan"`
}

type ChannelScanResults struct {
	ScanTime    time.Time                        `json:"scan_time"`
	Duration    int                              `json:"duration_seconds"`
	Results     map[string]*BandScanResults      `json:"results"` // band -> results
	Recommendations map[string]*ChannelRecommendation `json:"recommendations"`
}

type BandScanResults struct {
	Band         string        `json:"band"`
	Channels     []ChannelInfo `json:"channels"`
	Interference float64       `json:"interference_level"`
	NoiseFloor   int           `json:"average_noise_floor"`
}

type ChannelRecommendation struct {
	RecommendedChannel int     `json:"recommended_channel"`
	Reason            string  `json:"reason"`
	ExpectedImprovement float64 `json:"expected_improvement_percent"`
}
//ckp end
//ckp cov start
// ===== COVERAGE MAP DATA STRUCTURES =====

type CoverageAnalysis struct {
	TotalCoverage     float64              `json:"total_coverage"`
	ExcellentCoverage float64              `json:"excellent_coverage"`
	GoodCoverage      float64              `json:"good_coverage"`
	FairCoverage      float64              `json:"fair_coverage"`
	PoorCoverage      float64              `json:"poor_coverage"`
	WeakAreas         float64              `json:"weak_areas"`
	DeadZones         float64              `json:"dead_zones"`
	InterferenceLevel string               `json:"interference_level"`
	WeakZones         []WeakZone           `json:"weak_zones"`
	PlacementSuggestions []PlacementSuggestion `json:"placement_suggestions"`
	CoverageMap       [][]SignalPoint      `json:"coverage_map,omitempty"`
	AnalyzedAt        time.Time            `json:"analyzed_at"`
}

type WeakZone struct {
	ID          string    `json:"id"`
	Points      string    `json:"points"` // SVG polygon points
	Area        float64   `json:"area_m2"`
	AverageRSSI int       `json:"average_rssi"`
	Severity    string    `json:"severity"` // low, medium, high, critical
	Reason      string    `json:"reason"`
	Center      Point2D   `json:"center"`
}

type PlacementSuggestion struct {
	ID                  string    `json:"id"`
	X                   float64   `json:"x"`
	Y                   float64   `json:"y"`
	Z                   float64   `json:"z,omitempty"`
	DeviceType          string    `json:"device_type"` // controller, agent, extender
	PredictedRadius     float64   `json:"predicted_radius_m"`
	PredictedQuality    string    `json:"predicted_quality"`
	InterferenceRisk    string    `json:"interference_risk"`
	CoverageImprovement float64   `json:"coverage_improvement_percent"`
	Priority            int       `json:"priority"` // 1-10, higher is better
	Reason              string    `json:"reason"`
	EstimatedCost       float64   `json:"estimated_cost,omitempty"`
}

type SignalPoint struct {
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	RSSI      int     `json:"rssi"`
	SNR       int     `json:"snr,omitempty"`
	Quality   string  `json:"quality"` // excellent, good, fair, poor, none
	Sources   []string `json:"sources,omitempty"` // Contributing device MACs
	Interference float64 `json:"interference,omitempty"`
}

type Point2D struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type CoverageRequest struct {
	Band            string  `json:"band"`             // 2.4ghz, 5ghz, 6ghz
	Threshold       int     `json:"threshold"`        // Minimum RSSI in dBm
	MapScale        float64 `json:"map_scale"`        // Meters per pixel
	Resolution      int     `json:"resolution,omitempty"` // Analysis grid resolution
	IncludeHeatmap  bool    `json:"include_heatmap,omitempty"`
	FloorPlanID     string  `json:"floor_plan_id,omitempty"`
}

type OptimizationRequest struct {
	Band            string  `json:"band"`
	CoverageTarget  float64 `json:"coverage_target"`  // Desired coverage percentage
	SignalThreshold int     `json:"signal_threshold"` // Minimum acceptable RSSI
	MaxDevices      int     `json:"max_devices,omitempty"` // Budget constraint
	Budget          float64 `json:"budget,omitempty"`      // Cost constraint
	Priorities      []string `json:"priorities,omitempty"` // coverage, cost, performance
}

type FloorPlan struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Width       int       `json:"width_pixels"`
	Height      int       `json:"height_pixels"`
	Scale       float64   `json:"scale_meters_per_pixel"`
	Obstacles   []Obstacle `json:"obstacles,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Obstacle struct {
	Type        string    `json:"type"` // wall, door, window, furniture
	Points      []Point2D `json:"points"`
	Attenuation float64   `json:"attenuation_db"` // Signal loss in dB
	Material    string    `json:"material,omitempty"`
}

//ckp cov end
// ===== GLOBAL VARIABLES =====
var (
	devices      []Device
	clients      []Client
	meshTopology MeshTopology
	systemConfig SystemConfig

	upgrader = websocket.Upgrader{
		// Allow all origins for demo; tighten for prod
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	wsConnections []*websocket.Conn
	wsMu          sync.Mutex
        wirelessProfiles []WirelessProfile
	radioConfigs     map[string]*RadioConfig
	advancedSettings *AdvancedWirelessSettings
	lastScanResults  *ChannelScanResults
	wirelessMutex    sync.RWMutex
        currentCoverage  *CoverageAnalysis
	floorPlans       map[string]*FloorPlan
	coverageMutex    sync.RWMutex
	analysisCache    map[string]*CoverageAnalysis // Cache for different analysis parameters
	cacheExpiration  = 5 * time.Minute
)

// ===== INITIALIZATION =====

func init() {
	loadDevices()
	loadClients()
	generateMeshTopology()
	loadSystemConfig()
        initWirelessSettings()
        initCoverageMap()
        initDefaultFloorPlans()
}


func initCoverageMap() {
	floorPlans = make(map[string]*FloorPlan)
	analysisCache = make(map[string]*CoverageAnalysis)
	
	// Initialize default floor plans
	initDefaultFloorPlans()
	
	// Run initial coverage analysis
	go func() {
		time.Sleep(2 * time.Second) // Wait for devices to load
		analyzeCurrentCoverage()
	}()
	
	log.Printf("Coverage map initialized")
}

func initDefaultFloorPlans() {
	defaultPlan := &FloorPlan{
		ID:        "1st-floor",
		Name:      "1st Floor",
		URL:       "/static/floorplans/1st-floor.jpg",
		Width:     1000,
		Height:    600,
		Scale:     0.1, // 10cm per pixel
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	floorPlans["1st-floor"] = defaultPlan
	floorPlans["default"] = defaultPlan
}

// ===== COVERAGE ANALYSIS HANDLERS =====

func getCoverageAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	coverageMutex.RLock()
	defer coverageMutex.RUnlock()

	if currentCoverage == nil {
		// Run analysis if not available
		go analyzeCurrentCoverage()
		
		// Return basic response
		response := &CoverageAnalysis{
			TotalCoverage:     85.0,
			ExcellentCoverage: 60.0,
			WeakAreas:        15.5,
			DeadZones:        5.2,
			InterferenceLevel: "Low",
			WeakZones:        []WeakZone{},
			PlacementSuggestions: []PlacementSuggestion{},
			AnalyzedAt:       time.Now(),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(currentCoverage)
}

func analyzeCoverageHandler(w http.ResponseWriter, r *http.Request) {
	var request CoverageRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate request
	if request.Band == "" {
		request.Band = "2.4ghz"
	}
	if request.Threshold == 0 {
		request.Threshold = -70
	}
	if request.MapScale == 0 {
		request.MapScale = 0.1
	}

	// Check cache
	cacheKey := fmt.Sprintf("%s_%d_%.3f", request.Band, request.Threshold, request.MapScale)
	coverageMutex.RLock()
	if cached, exists := analysisCache[cacheKey]; exists {
		if time.Since(cached.AnalyzedAt) < cacheExpiration {
			coverageMutex.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(cached)
			return
		}
	}
	coverageMutex.RUnlock()

	// Run analysis
	analysis, err := performCoverageAnalysis(request)
	if err != nil {
		http.Error(w, fmt.Sprintf("Analysis failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Cache result
	coverageMutex.Lock()
	analysisCache[cacheKey] = analysis
	if currentCoverage == nil || request.Band == "2.4ghz" {
		currentCoverage = analysis
	}
	coverageMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(analysis)
}

func optimizePlacementHandler(w http.ResponseWriter, r *http.Request) {
	var request OptimizationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate request
	if request.Band == "" {
		request.Band = "2.4ghz"
	}
	if request.CoverageTarget == 0 {
		request.CoverageTarget = 95.0
	}
	if request.SignalThreshold == 0 {
		request.SignalThreshold = -70
	}

	// Run optimization
	suggestions, err := optimizeDevicePlacement(request)
	if err != nil {
		http.Error(w, fmt.Sprintf("Optimization failed: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success":     true,
		"suggestions": suggestions,
		"parameters":  request,
		"timestamp":   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
// ===== FLOOR PLAN HANDLERS =====

func getFloorPlansHandler(w http.ResponseWriter, r *http.Request) {
	coverageMutex.RLock()
	defer coverageMutex.RUnlock()

	response := map[string]interface{}{
		"floor_plans": floorPlans,
		"total":       len(floorPlans),
		"timestamp":   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func uploadFloorPlanHandler(w http.ResponseWriter, r *http.Request) {
	var floorPlan FloorPlan
	if err := json.NewDecoder(r.Body).Decode(&floorPlan); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate floor plan
	if floorPlan.Name == "" {
		http.Error(w, "Floor plan name is required", http.StatusBadRequest)
		return
	}

	coverageMutex.Lock()
	defer coverageMutex.Unlock()

	// Generate unique ID if not provided
	if floorPlan.ID == "" {
		floorPlan.ID = fmt.Sprintf("floorplan_%d", time.Now().UnixNano())
	}

	floorPlan.CreatedAt = time.Now()
	floorPlan.UpdatedAt = time.Now()

	floorPlans[floorPlan.ID] = &floorPlan

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Floor plan uploaded successfully",
		"plan":    floorPlan,
	})
}

func getFloorPlanHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	coverageMutex.RLock()
	defer coverageMutex.RUnlock()

	floorPlan, exists := floorPlans[id]
	if !exists {
		http.Error(w, "Floor plan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(floorPlan)
}

func updateFloorPlanHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var updatedPlan FloorPlan
	if err := json.NewDecoder(r.Body).Decode(&updatedPlan); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	coverageMutex.Lock()
	defer coverageMutex.Unlock()

	existingPlan, exists := floorPlans[id]
	if !exists {
		http.Error(w, "Floor plan not found", http.StatusNotFound)
		return
	}

	// Preserve creation time and ID
	updatedPlan.ID = id
	updatedPlan.CreatedAt = existingPlan.CreatedAt
	updatedPlan.UpdatedAt = time.Now()

	floorPlans[id] = &updatedPlan

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Floor plan updated successfully",
		"plan":    updatedPlan,
	})
}

func deleteFloorPlanHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	coverageMutex.Lock()
	defer coverageMutex.Unlock()

	_, exists := floorPlans[id]
	if !exists {
		http.Error(w, "Floor plan not found", http.StatusNotFound)
		return
	}

	delete(floorPlans, id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Floor plan deleted successfully",
	})
}

// ===== COVERAGE HEATMAP HANDLERS =====

func getCoverageHeatmapHandler(w http.ResponseWriter, r *http.Request) {
	coverageMutex.RLock()
	defer coverageMutex.RUnlock()

	if currentCoverage == nil {
		// Run analysis if not available
		go analyzeCurrentCoverage()
		
		http.Error(w, "Coverage analysis in progress", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"heatmap":   currentCoverage.CoverageMap,
		"timestamp": currentCoverage.AnalyzedAt,
	})
}

func getBandHeatmapHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	band := vars["band"]

	// Default to 2.4GHz if no band specified
	if band == "" {
		band = "2.4ghz"
	}

	// Perform band-specific coverage analysis
	request := CoverageRequest{
		Band:           band,
		Threshold:      -70,
		MapScale:       0.1,
		IncludeHeatmap: true,
	}

	analysis, err := performCoverageAnalysis(request)
	if err != nil {
		http.Error(w, fmt.Sprintf("Analysis failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"band":      band,
		"heatmap":   analysis.CoverageMap,
		"timestamp": analysis.AnalyzedAt,
	})
}

// ===== ADDITIONAL SIMULATION AND PLACEMENT HANDLERS =====

func simulateDevicePlacementHandler(w http.ResponseWriter, r *http.Request) {
	var placementRequest struct {
		Devices []Point3D `json:"devices"`
		Band    string    `json:"band"`
	}

	if err := json.NewDecoder(r.Body).Decode(&placementRequest); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if placementRequest.Band == "" {
		placementRequest.Band = "2.4ghz"
	}

	// Simulate coverage with proposed device placements
	coverage, err := simulateCoverageWithPlacement(placementRequest.Devices, placementRequest.Band)
	if err != nil {
		http.Error(w, fmt.Sprintf("Simulation failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"coverage":   coverage,
		"devices":    placementRequest.Devices,
		"timestamp":  time.Now(),
	})
}

func predictPlacementHandler(w http.ResponseWriter, r *http.Request) {
	var request OptimizationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Default values if not provided
	if request.Band == "" {
		request.Band = "2.4ghz"
	}
	if request.CoverageTarget == 0 {
		request.CoverageTarget = 95.0
	}
	if request.SignalThreshold == 0 {
		request.SignalThreshold = -70
	}

	suggestions, err := optimizeDevicePlacement(request)
	if err != nil {
		http.Error(w, fmt.Sprintf("Placement prediction failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"suggestions": suggestions,
		"request":     request,
		"timestamp":   time.Now(),
	})
}

// Simulation function (you'll want to implement a full simulation logic)
// In the simulateCoverageWithPlacement function, modify the function signature and implementation:
func simulateCoverageWithPlacement(devicePositions []Point3D, band string) (*CoverageAnalysis, error) {
    // Create temporary devices from positions
    var simulatedDevices []Device
    for _, pos := range devicePositions {
        simulatedDevice := Device{
            MAC:      fmt.Sprintf("SIM:%f:%f:%f", pos.X, pos.Y, pos.Z),
            Status:   "Online",
            Location: Location{Position3D: pos},
        }
        simulatedDevices = append(simulatedDevices, simulatedDevice)
    }

    // Temporarily replace global devices
    originalDevices := devices
    devices = append(originalDevices, simulatedDevices...)
    defer func() { devices = originalDevices }()

    request := CoverageRequest{
        Band:           band,
        Threshold:      -70,
        MapScale:       0.1,
        IncludeHeatmap: true,
    }

    return performCoverageAnalysis(request)
}
// Weak zone and dead spot handlers
func getWeakZonesHandler(w http.ResponseWriter, r *http.Request) {
	coverageMutex.RLock()
	defer coverageMutex.RUnlock()

	if currentCoverage == nil {
		http.Error(w, "No coverage analysis available", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"weak_zones": currentCoverage.WeakZones,
		"timestamp":  currentCoverage.AnalyzedAt,
	})
}

func getDeadSpotsHandler(w http.ResponseWriter, r *http.Request) {
	coverageMutex.RLock()
	defer coverageMutex.RUnlock()

	if currentCoverage == nil {
		http.Error(w, "No coverage analysis available", http.StatusServiceUnavailable)
		return
	}

	deadSpots := []WeakZone{}
	for _, zone := range currentCoverage.WeakZones {
		if zone.Severity == "critical" {
			deadSpots = append(deadSpots, zone)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"dead_spots": deadSpots,
		"timestamp":  currentCoverage.AnalyzedAt,
	})
}

// Reporting handlers
func generateCoverageReportHandler(w http.ResponseWriter, r *http.Request) {
	coverageMutex.RLock()
	defer coverageMutex.RUnlock()

	if currentCoverage == nil {
		http.Error(w, "No coverage analysis available", http.StatusServiceUnavailable)
		return
	}

	report := map[string]interface{}{
		"total_coverage":     currentCoverage.TotalCoverage,
		"excellent_coverage": currentCoverage.ExcellentCoverage,
		"weak_zones":         currentCoverage.WeakZones,
		"placement_suggestions": currentCoverage.PlacementSuggestions,
		"timestamp":          currentCoverage.AnalyzedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func generateCoverageReportPDFHandler(w http.ResponseWriter, r *http.Request) {
	// This would typically use a PDF generation library
	// For this example, we'll return a placeholder
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename=coverage_report.pdf")
	
	// In a real implementation, you'd generate a PDF
	w.Write([]byte("PDF Generation Placeholder"))
}

// ===== COVERAGE CALCULATION FUNCTIONS =====

func performCoverageAnalysis(request CoverageRequest) (*CoverageAnalysis, error) {
	log.Printf("Performing coverage analysis for band %s with threshold %d dBm", request.Band, request.Threshold)

	analysis := &CoverageAnalysis{
		WeakZones:            []WeakZone{},
		PlacementSuggestions: []PlacementSuggestion{},
		AnalyzedAt:          time.Now(),
	}

	// Get online devices
	onlineDevices := getOnlineDevices()
	if len(onlineDevices) == 0 {
		return analysis, fmt.Errorf("no online devices found")
	}

	// Create signal coverage grid
	gridSize := 50 // 50x50 grid for analysis
	if request.Resolution > 0 {
		gridSize = request.Resolution
	}

	signalGrid := make([][]SignalPoint, gridSize)
	for i := range signalGrid {
		signalGrid[i] = make([]SignalPoint, gridSize)
	}

	// Calculate coverage for each grid point
	mapWidth := 1000.0  // pixels
	mapHeight := 600.0  // pixels
	
	for x := 0; x < gridSize; x++ {
		for y := 0; y < gridSize; y++ {
			pixelX := (float64(x) / float64(gridSize-1)) * mapWidth
			pixelY := (float64(y) / float64(gridSize-1)) * mapHeight
			
			signalPoint := calculateSignalAtPoint(pixelX, pixelY, onlineDevices, request.Band, request.MapScale)
			signalGrid[x][y] = signalPoint
		}
	}

	// Analyze coverage statistics
	analysis = calculateCoverageStatistics(signalGrid, request.Threshold)
	analysis.WeakZones = identifyWeakZones(signalGrid, request.Threshold, request.MapScale)
	
	// Include heatmap data if requested
	if request.IncludeHeatmap {
		analysis.CoverageMap = signalGrid
	}

	return analysis, nil
}

func calculateSignalAtPoint(x, y float64, devices []Device, band string, mapScale float64) SignalPoint {
	point := SignalPoint{
		X:       x,
		Y:       y,
		RSSI:    -100, // Start with very weak signal
		Sources: []string{},
	}

	maxRSSI := -100
	var contributingSources []string

	for _, device := range devices {
		if device.Status != "Online" {
			continue
		}

		// Get device position
		devicePos := getDeviceMapPosition(device)
		
		// Calculate distance
		distance := calculateEuclideanDistance(x, y, devicePos.X, devicePos.Y) * mapScale
		if distance < 0.1 { // Minimum distance 10cm
			distance = 0.1
		}

		// Calculate RSSI using simplified path loss model
		rssi := calculatePathLoss(device, distance, band)
		
		if rssi > maxRSSI {
			maxRSSI = rssi
			contributingSources = append(contributingSources, device.MAC)
		}

		// Add interference from multiple sources
		if rssi > -90 {
			contributingSources = append(contributingSources, device.MAC)
		}
	}

	point.RSSI = maxRSSI
	point.Sources = contributingSources
	point.Quality = classifySignalQuality(maxRSSI)
	
	// Calculate SNR (simplified)
	noiseFloor := -95
	if band == "5ghz" {
		noiseFloor = -98
	} else if band == "6ghz" {
		noiseFloor = -100
	}
	point.SNR = maxRSSI - noiseFloor

	return point
}

func calculatePathLoss(device Device, distanceM float64, band string) int {
	// Get transmit power
	txPower := 20.0 // Default 20 dBm
	if device.Metrics.PowerConsumption > 0 {
		// Estimate based on power consumption (simplified)
		if band == "2.4ghz" {
			txPower = 20.0
		} else if band == "5ghz" {
			txPower = 24.0
		} else if band == "6ghz" {
			txPower = 30.0
		}
	}

	// Get frequency
	frequency := getBandFrequencyMHz(band)
	
	// Free Space Path Loss: FSPL = 20*log10(d) + 20*log10(f) + 32.45
	// where d is distance in km, f is frequency in MHz
	distanceKm := distanceM / 1000.0
	if distanceKm < 0.001 {
		distanceKm = 0.001 // Minimum 1 meter
	}

	fspl := 20*math.Log10(distanceKm) + 20*math.Log10(frequency) + 32.45
	
	// Add environmental factors
	environmentalLoss := calculateEnvironmentalLoss(distanceM, band)
	
	// Calculate received signal strength
	rssi := txPower - fspl - environmentalLoss
	
	return int(math.Max(-100, math.Min(0, rssi)))
}

func getBandFrequencyMHz(band string) float64 {
	frequencies := map[string]float64{
		"2.4ghz": 2400.0,
		"5ghz":   5000.0,
		"6ghz":   6000.0,
	}
	
	if freq, exists := frequencies[band]; exists {
		return freq
	}
	return 2400.0
}

func calculateEnvironmentalLoss(distance float64, band string) float64 {
	// Simplified environmental loss calculation
	// In a real implementation, this would consider walls, obstacles, etc.
	
	loss := 0.0
	
	// Add loss based on distance (beyond free space)
	if distance > 10 {
		loss += 2.0 * math.Log10(distance/10) // 2 dB per decade beyond 10m
	}
	
	// Add frequency-dependent indoor loss
	switch band {
	case "2.4ghz":
		loss += 2.0  // 2.4 GHz penetrates walls better
	case "5ghz":
		loss += 5.0  // 5 GHz has more loss indoors
	case "6ghz":
		loss += 8.0  // 6 GHz has highest indoor loss
	}
	
	// Add random variation for realistic modeling
	variation := (rand.Float64() - 0.5) * 4.0 // ±2 dB variation
	loss += variation
	
	return math.Max(0, loss)
}

func classifySignalQuality(rssi int) string {
	if rssi >= -50 {
		return "excellent"
	} else if rssi >= -60 {
		return "good"
	} else if rssi >= -70 {
		return "fair"
	} else if rssi >= -80 {
		return "poor"
	}
	return "none"
}

func calculateCoverageStatistics(signalGrid [][]SignalPoint, threshold int) *CoverageAnalysis {
	totalPoints := len(signalGrid) * len(signalGrid[0])
	excellentCount := 0
	goodCount := 0
	fairCount := 0
	poorCount := 0
	noneCount := 0

	for _, row := range signalGrid {
		for _, point := range row {
			switch point.Quality {
			case "excellent":
				excellentCount++
			case "good":
				goodCount++
			case "fair":
				fairCount++
			case "poor":
				poorCount++
			case "none":
				noneCount++
			}
		}
	}

	analysis := &CoverageAnalysis{
		TotalCoverage:     float64(totalPoints-noneCount) / float64(totalPoints) * 100,
		ExcellentCoverage: float64(excellentCount) / float64(totalPoints) * 100,
		GoodCoverage:      float64(goodCount) / float64(totalPoints) * 100,
		FairCoverage:      float64(fairCount) / float64(totalPoints) * 100,
		PoorCoverage:      float64(poorCount) / float64(totalPoints) * 100,
		WeakAreas:        float64(poorCount) / float64(totalPoints) * 100,
		DeadZones:        float64(noneCount) / float64(totalPoints) * 100,
		InterferenceLevel: calculateInterferenceLevel(signalGrid),
		AnalyzedAt:       time.Now(),
	}

	return analysis
}

func calculateInterferenceLevel(signalGrid [][]SignalPoint) string {
	totalInterference := 0.0
	points := 0

	for _, row := range signalGrid {
		for _, point := range row {
			if len(point.Sources) > 1 {
				// Multiple sources contribute to interference
				totalInterference += float64(len(point.Sources) - 1)
			}
			points++
		}
	}

	avgInterference := totalInterference / float64(points)
	
	if avgInterference > 2.0 {
		return "High"
	} else if avgInterference > 1.0 {
		return "Medium"
	}
	return "Low"
}

func identifyWeakZones(signalGrid [][]SignalPoint, threshold int, mapScale float64) []WeakZone {
	var weakZones []WeakZone
	visited := make([][]bool, len(signalGrid))
	for i := range visited {
		visited[i] = make([]bool, len(signalGrid[0]))
	}

	zoneID := 1
	
	// Find connected regions of weak signal
	for x := 0; x < len(signalGrid); x++ {
		for y := 0; y < len(signalGrid[0]); y++ {
			if !visited[x][y] && signalGrid[x][y].RSSI < threshold {
				zone := exploreWeakZone(signalGrid, visited, x, y, threshold, mapScale)
				if zone.Area > 1.0 { // Only include zones larger than 1 m²
					zone.ID = fmt.Sprintf("weak_zone_%d", zoneID)
					weakZones = append(weakZones, zone)
					zoneID++
				}
			}
		}
	}

	return weakZones
}

func exploreWeakZone(grid [][]SignalPoint, visited [][]bool, startX, startY, threshold int, mapScale float64) WeakZone {
	// Simple flood fill to identify connected weak areas
	var points []Point2D
	var rssiSum int
	var count int
	
	queue := []Point2D{{X: float64(startX), Y: float64(startY)}}
	
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		
		x, y := int(current.X), int(current.Y)
		
		if x < 0 || x >= len(grid) || y < 0 || y >= len(grid[0]) || visited[x][y] {
			continue
		}
		
		if grid[x][y].RSSI >= threshold {
			continue
		}
		
		visited[x][y] = true
		
		// Convert grid coordinates to map coordinates
		mapX := (float64(x) / float64(len(grid)-1)) * 1000
		mapY := (float64(y) / float64(len(grid[0])-1)) * 600
		
		points = append(points, Point2D{X: mapX, Y: mapY})
		rssiSum += grid[x][y].RSSI
		count++
		
		// Add neighbors to queue
		neighbors := []Point2D{
			{X: float64(x-1), Y: float64(y)},
			{X: float64(x+1), Y: float64(y)},
			{X: float64(x), Y: float64(y-1)},
			{X: float64(x), Y: float64(y+1)},
		}
		
		queue = append(queue, neighbors...)
	}
	
	// Calculate zone properties
	avgRSSI := rssiSum / count
	area := float64(count) * math.Pow(mapScale*20, 2) // Approximate area
	
	// Generate SVG polygon points
	svgPoints := ""
	for i, point := range points {
		if i > 0 {
			svgPoints += " "
		}
		svgPoints += fmt.Sprintf("%.1f,%.1f", point.X, point.Y)
	}
	
	// Calculate center
	center := calculateCentroid(points)
	
	zone := WeakZone{
		Points:      svgPoints,
		Area:        area,
		AverageRSSI: avgRSSI,
		Severity:    classifyZoneSeverity(avgRSSI),
		Reason:      generateWeakZoneReason(avgRSSI),
		Center:      center,
	}
	
	return zone
}

func calculateCentroid(points []Point2D) Point2D {
	if len(points) == 0 {
		return Point2D{}
	}
	
	sumX, sumY := 0.0, 0.0
	for _, point := range points {
		sumX += point.X
		sumY += point.Y
	}
	
	return Point2D{
		X: sumX / float64(len(points)),
		Y: sumY / float64(len(points)),
	}
}

func classifyZoneSeverity(avgRSSI int) string {
	if avgRSSI < -90 {
		return "critical"
	} else if avgRSSI < -85 {
		return "high"
	} else if avgRSSI < -80 {
		return "medium"
	}
	return "low"
}

func generateWeakZoneReason(avgRSSI int) string {
	if avgRSSI < -90 {
		return "Dead zone - no usable signal"
	} else if avgRSSI < -85 {
		return "Very weak signal - connectivity issues likely"
	} else if avgRSSI < -80 {
		return "Weak signal - reduced performance"
	}
	return "Marginal signal quality"
}

// ===== PLACEMENT OPTIMIZATION =====

func optimizeDevicePlacement(request OptimizationRequest) ([]PlacementSuggestion, error) {
	log.Printf("Optimizing device placement for %s band with %.1f%% coverage target", 
		request.Band, request.CoverageTarget)

	// Analyze current coverage
	coverageRequest := CoverageRequest{
		Band:      request.Band,
		Threshold: request.SignalThreshold,
		MapScale:  0.1,
	}
	
	currentAnalysis, err := performCoverageAnalysis(coverageRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze current coverage: %v", err)
	}

	// If already meeting target, return minimal suggestions
	if currentAnalysis.TotalCoverage >= request.CoverageTarget {
		return generateMinimalSuggestions(currentAnalysis), nil
	}

	// Generate placement suggestions
	suggestions := []PlacementSuggestion{}
	
	// Strategy 1: Fill coverage gaps
	gapSuggestions := findCoverageGaps(currentAnalysis, request)
	suggestions = append(suggestions, gapSuggestions...)
	
	// Strategy 2: Improve weak zones
	weakZoneSuggestions := improveWeakZones(currentAnalysis, request)
	suggestions = append(suggestions, weakZoneSuggestions...)
	
	// Strategy 3: Load balancing suggestions
	if len(suggestions) < 3 {
		balancingSuggestions := generateLoadBalancingSuggestions(request)
		suggestions = append(suggestions, balancingSuggestions...)
	}

	// Sort by priority and limit results
	suggestions = prioritizeSuggestions(suggestions, request)
	
	if len(suggestions) > 5 {
		suggestions = suggestions[:5]
	}

	return suggestions, nil
}

func findCoverageGaps(analysis *CoverageAnalysis, request OptimizationRequest) []PlacementSuggestion {
	var suggestions []PlacementSuggestion
	
	// Analyze current device positions
	onlineDevices := getOnlineDevices()
	
	// Find areas far from any device
	candidates := []Point2D{
		{X: 200, Y: 150},  // Top-left quadrant
		{X: 800, Y: 150},  // Top-right quadrant
		{X: 200, Y: 450},  // Bottom-left quadrant
		{X: 800, Y: 450},  // Bottom-right quadrant
		{X: 500, Y: 300},  // Center
	}
	
	for i, candidate := range candidates {
		// Check if this position would improve coverage
		improvement := estimateCoverageImprovement(candidate, onlineDevices, request.Band)
		
		if improvement > 5.0 { // Only suggest if significant improvement
			suggestion := PlacementSuggestion{
				ID:                  fmt.Sprintf("gap_fill_%d", i+1),
				X:                   candidate.X,
				Y:                   candidate.Y,
				DeviceType:          "agent",
				PredictedRadius:     calculatePredictedRadius(candidate, request.Band),
				PredictedQuality:    "Good",
				InterferenceRisk:    "Low",
				CoverageImprovement: improvement,
				Priority:            int(improvement / 2),
				Reason:              "Fill coverage gap in underserved area",
			}
			
			suggestions = append(suggestions, suggestion)
		}
	}
	
	return suggestions
}

func improveWeakZones(analysis *CoverageAnalysis, request OptimizationRequest) []PlacementSuggestion {
	var suggestions []PlacementSuggestion
	
	for i, weakZone := range analysis.WeakZones {
		if weakZone.Severity == "high" || weakZone.Severity == "critical" {
			// Suggest placement near the center of weak zone
			suggestion := PlacementSuggestion{
				ID:                  fmt.Sprintf("weak_zone_%d", i+1),
				X:                   weakZone.Center.X,
				Y:                   weakZone.Center.Y,
				DeviceType:          "agent",
				PredictedRadius:     25.0,
				PredictedQuality:    "Good",
				InterferenceRisk:    "Low",
				CoverageImprovement: 15.0,
				Priority:            8,
				Reason:              fmt.Sprintf("Improve %s weak zone (%.1f m²)", weakZone.Severity, weakZone.Area),
			}
			
			suggestions = append(suggestions, suggestion)
		}
	}
	
	return suggestions
}

func generateLoadBalancingSuggestions(request OptimizationRequest) []PlacementSuggestion {
	suggestions := []PlacementSuggestion{
		{
			ID:                  "load_balance_1",
			X:                   350,
			Y:                   200,
			DeviceType:          "agent",
			PredictedRadius:     20.0,
			PredictedQuality:    "Good",
			InterferenceRisk:    "Medium",
			CoverageImprovement: 8.0,
			Priority:            6,
			Reason:              "Improve load distribution and reduce congestion",
		},
	}
	
	return suggestions
}

func generateMinimalSuggestions(analysis *CoverageAnalysis) []PlacementSuggestion {
	return []PlacementSuggestion{
		{
			ID:                  "optimization_1",
			X:                   600,
			Y:                   250,
			DeviceType:          "agent",
			PredictedRadius:     22.0,
			PredictedQuality:    "Excellent",
			InterferenceRisk:    "Low",
			CoverageImprovement: 3.0,
			Priority:            4,
			Reason:              "Fine-tune coverage for optimal performance",
		},
	}
}

func estimateCoverageImprovement(position Point2D, devices []Device, band string) float64 {
	// Simplified estimation of coverage improvement
	// In practice, this would run a full coverage simulation
	
	nearestDistance := math.Inf(1)
	for _, device := range devices {
		devicePos := getDeviceMapPosition(device)
		distance := calculateEuclideanDistance(position.X, position.Y, devicePos.X, devicePos.Y)
		if distance < nearestDistance {
			nearestDistance = distance
		}
	}
	
	// More improvement for positions far from existing devices
	if nearestDistance > 200 {
		return 20.0
	} else if nearestDistance > 100 {
		return 12.0
	} else if nearestDistance > 50 {
		return 8.0
	}
	return 3.0
}

func calculatePredictedRadius(position Point2D, band string) float64 {
	// Simplified radius calculation
	baseRadius := map[string]float64{
		"2.4ghz": 30.0,
		"5ghz":   25.0,
		"6ghz":   20.0,
	}
	
	if radius, exists := baseRadius[band]; exists {
		return radius
	}
	return 25.0
}

func prioritizeSuggestions(suggestions []PlacementSuggestion, request OptimizationRequest) []PlacementSuggestion {
	// Sort by priority (higher is better)
	sort.Slice(suggestions, func(i, j int) bool {
		return suggestions[i].Priority > suggestions[j].Priority
	})
	
	return suggestions
}

// ===== UTILITY FUNCTIONS =====

func getOnlineDevices() []Device {
	var onlineDevices []Device
	for _, device := range devices {
		if device.Status == "Online" {
			onlineDevices = append(onlineDevices, device)
		}
	}
	return onlineDevices
}

func getDeviceMapPosition(device Device) Point2D {
	// Convert device location to map coordinates
	if device.Location.Position3D.X != 0 || device.Location.Position3D.Y != 0 {
		// Convert 3D position to 2D map coordinates
		x := (device.Location.Position3D.X / 0.1) + 500 // Assuming map center at 500,300
		y := (device.Location.Position3D.Y / 0.1) + 300
		return Point2D{
			X: math.Max(0, math.Min(1000, x)),
			Y: math.Max(0, math.Min(600, y)),
		}
	}
	
	// Default positions based on MAC address
	positions := map[string]Point2D{
		"AA:BB:CC:00:00:01": {X: 200, Y: 300},
		"AA:BB:CC:00:00:02": {X: 500, Y: 200},
		"AA:BB:CC:00:00:03": {X: 750, Y: 400},
	}
	
	if pos, exists := positions[device.MAC]; exists {
		return pos
	}
	
	// Random position if not found
	return Point2D{X: 100, Y: 100}
}

func calculateEuclideanDistance(x1, y1, x2, y2 float64) float64 {
	return math.Sqrt(math.Pow(x2-x1, 2) + math.Pow(y2-y1, 2))
}

func analyzeCurrentCoverage() {
	request := CoverageRequest{
		Band:      "2.4ghz",
		Threshold: -70,
		MapScale:  0.1,
	}
	
	analysis, err := performCoverageAnalysis(request)
	if err != nil {
		log.Printf("Failed to analyze coverage: %v", err)
		return
	}
	
	coverageMutex.Lock()
	currentCoverage = analysis
	coverageMutex.Unlock()
	
	log.Printf("Coverage analysis completed: %.1f%% total coverage", analysis.TotalCoverage)
}

func initWirelessSettings() {
	wirelessProfiles = getDefaultWirelessProfiles()
	radioConfigs = getDefaultRadioConfigs()
	advancedSettings = getDefaultAdvancedSettings()
	log.Printf("Initialized wireless settings with %d profiles", len(wirelessProfiles))
}
// ===== WIRELESS PROFILE HANDLERS =====

func getWirelessProfilesHandler(w http.ResponseWriter, r *http.Request) {
	wirelessMutex.RLock()
	defer wirelessMutex.RUnlock()

	response := map[string]interface{}{
		"profiles":  wirelessProfiles,
		"total":     len(wirelessProfiles),
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func createWirelessProfileHandler(w http.ResponseWriter, r *http.Request) {
	var profile WirelessProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate profile
	if err := validateWirelessProfile(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	wirelessMutex.Lock()
	defer wirelessMutex.Unlock()

	// Generate ID and timestamps
	profile.ID = generateProfileID()
	profile.CreatedAt = time.Now()
	profile.UpdatedAt = time.Now()
	
	// Set default bands if not specified
	if len(profile.Bands) == 0 {
		profile.Bands = []string{"2.4GHz", "5GHz", "6GHz"}
	}

	wirelessProfiles = append(wirelessProfiles, profile)

	// Broadcast update
	broadcastWirelessUpdate("profile_created", profile)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Profile created successfully",
		"profile": profile,
	})
}

func updateWirelessProfileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profileID := vars["id"]

	var updatedProfile WirelessProfile
	if err := json.NewDecoder(r.Body).Decode(&updatedProfile); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	wirelessMutex.Lock()
	defer wirelessMutex.Unlock()

	for i, profile := range wirelessProfiles {
		if profile.ID == profileID {
			// Preserve created time and ID
			updatedProfile.ID = profile.ID
			updatedProfile.CreatedAt = profile.CreatedAt
			updatedProfile.UpdatedAt = time.Now()

			// Validate updated profile
			if err := validateWirelessProfile(&updatedProfile); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			wirelessProfiles[i] = updatedProfile

			// Broadcast update
			broadcastWirelessUpdate("profile_updated", updatedProfile)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "Profile updated successfully",
				"profile": updatedProfile,
			})
			return
		}
	}

	http.Error(w, "Profile not found", http.StatusNotFound)
}

func deleteWirelessProfileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profileID := vars["id"]

	wirelessMutex.Lock()
	defer wirelessMutex.Unlock()

	for i, profile := range wirelessProfiles {
		if profile.ID == profileID {
			wirelessProfiles = append(wirelessProfiles[:i], wirelessProfiles[i+1:]...)

			// Broadcast update
			broadcastWirelessUpdate("profile_deleted", map[string]string{"id": profileID})

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "Profile deleted successfully",
			})
			return
		}
	}

	http.Error(w, "Profile not found", http.StatusNotFound)
}

func toggleWirelessProfileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profileID := vars["id"]

	wirelessMutex.Lock()
	defer wirelessMutex.Unlock()

	for i, profile := range wirelessProfiles {
		if profile.ID == profileID {
			wirelessProfiles[i].Enabled = !profile.Enabled
			wirelessProfiles[i].UpdatedAt = time.Now()

			// Broadcast update
			broadcastWirelessUpdate("profile_toggled", wirelessProfiles[i])

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Profile %s", 
					map[bool]string{true: "enabled", false: "disabled"}[wirelessProfiles[i].Enabled]),
				"enabled": wirelessProfiles[i].Enabled,
			})
			return
		}
	}

	http.Error(w, "Profile not found", http.StatusNotFound)
}

// ===== RADIO CONFIGURATION HANDLERS =====

func getRadioConfigsHandler(w http.ResponseWriter, r *http.Request) {
	wirelessMutex.RLock()
	defer wirelessMutex.RUnlock()

	response := map[string]interface{}{
		"radios":    radioConfigs,
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func updateRadioConfigHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	band := vars["band"]

	var config RadioConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	wirelessMutex.Lock()
	defer wirelessMutex.Unlock()

	// Validate configuration
	if err := validateRadioConfig(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	radioConfigs[band] = &config

	// Broadcast update
	broadcastWirelessUpdate("radio_config_updated", map[string]interface{}{
		"band":   band,
		"config": config,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Radio configuration for %s updated", band),
	})
}

// ===== ADVANCED SETTINGS HANDLERS =====

func getAdvancedWirelessSettingsHandler(w http.ResponseWriter, r *http.Request) {
	wirelessMutex.RLock()
	defer wirelessMutex.RUnlock()

	response := map[string]interface{}{
		"settings":  advancedSettings,
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func updateAdvancedWirelessSettingsHandler(w http.ResponseWriter, r *http.Request) {
	var settings AdvancedWirelessSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	wirelessMutex.Lock()
	defer wirelessMutex.Unlock()

	settings.UpdatedAt = time.Now()
	advancedSettings = &settings

	// Broadcast update
	broadcastWirelessUpdate("advanced_settings_updated", settings)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Advanced wireless settings updated",
	})
}

// ===== CHANNEL SCANNING HANDLERS =====

func startChannelScanHandler(w http.ResponseWriter, r *http.Request) {
	var scanRequest ChannelScanRequest
	if err := json.NewDecoder(r.Body).Decode(&scanRequest); err != nil {
		// Use default scan parameters
		scanRequest = ChannelScanRequest{
			ScanDuration: 30,
			Bands:        []string{"2.4GHz", "5GHz", "6GHz"},
			PassiveScan:  false,
		}
	}

	// Validate scan request
	if scanRequest.ScanDuration < 10 || scanRequest.ScanDuration > 300 {
		scanRequest.ScanDuration = 30
	}

	go performChannelScan(scanRequest)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Channel scan started",
		"duration": scanRequest.ScanDuration,
	})
}

func getChannelScanResultsHandler(w http.ResponseWriter, r *http.Request) {
	wirelessMutex.RLock()
	defer wirelessMutex.RUnlock()

	if lastScanResults == nil {
		http.Error(w, "No scan results available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"results": lastScanResults,
	})
}

// ===== COMPLETE WIRELESS CONFIG HANDLERS =====

func getWirelessConfigHandler(w http.ResponseWriter, r *http.Request) {
	wirelessMutex.RLock()
	defer wirelessMutex.RUnlock()

	response := map[string]interface{}{
		"profiles":           wirelessProfiles,
		"radio_configs":      radioConfigs,
		"advanced_settings":  advancedSettings,
		"last_scan_results":  lastScanResults,
		"timestamp":          time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func updateWirelessConfigHandler(w http.ResponseWriter, r *http.Request) {
	var configUpdate struct {
		RadioConfigs     map[string]*RadioConfig   `json:"radio_configs,omitempty"`
		AdvancedSettings *AdvancedWirelessSettings `json:"advanced_settings,omitempty"`
		NetworkProfiles  []WirelessProfile         `json:"network_profiles,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&configUpdate); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	wirelessMutex.Lock()
	defer wirelessMutex.Unlock()

	// Update radio configurations
	if configUpdate.RadioConfigs != nil {
		for band, config := range configUpdate.RadioConfigs {
			if err := validateRadioConfig(config); err != nil {
				http.Error(w, fmt.Sprintf("Invalid radio config for %s: %v", band, err), http.StatusBadRequest)
				return
			}
			radioConfigs[band] = config
		}
	}

	// Update advanced settings
	if configUpdate.AdvancedSettings != nil {
		configUpdate.AdvancedSettings.UpdatedAt = time.Now()
		advancedSettings = configUpdate.AdvancedSettings
	}

	// Update network profiles
	if configUpdate.NetworkProfiles != nil {
		for _, profile := range configUpdate.NetworkProfiles {
			if err := validateWirelessProfile(&profile); err != nil {
				http.Error(w, fmt.Sprintf("Invalid profile %s: %v", profile.Name, err), http.StatusBadRequest)
				return
			}
		}
		wirelessProfiles = configUpdate.NetworkProfiles
	}

	// Broadcast complete update
	broadcastWirelessUpdate("config_updated", map[string]interface{}{
		"radio_configs":     radioConfigs,
		"advanced_settings": advancedSettings,
		"profiles":          wirelessProfiles,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Wireless configuration updated successfully",
	})
}

// ===== VALIDATION FUNCTIONS =====

func validateWirelessProfile(profile *WirelessProfile) error {
	if profile.Name == "" {
		return fmt.Errorf("profile name is required")
	}

	if profile.SSID == "" {
		return fmt.Errorf("SSID is required")
	}

	if len(profile.SSID) > 32 {
		return fmt.Errorf("SSID must be 32 characters or less")
	}

	validSecurityTypes := []string{"WPA3-SAE", "WPA3-Enterprise", "WPA2-PSK", "Enhanced-Open", "Open"}
	validSecurity := false
	for _, validType := range validSecurityTypes {
		if profile.SecurityType == validType {
			validSecurity = true
			break
		}
	}
	if !validSecurity {
		return fmt.Errorf("invalid security type")
	}

	// Validate passphrase for security types that require it
	if profile.SecurityType == "WPA3-SAE" || profile.SecurityType == "WPA2-PSK" {
		if profile.Passphrase == "" {
			return fmt.Errorf("passphrase is required for %s", profile.SecurityType)
		}
		if len(profile.Passphrase) < 8 || len(profile.Passphrase) > 63 {
			return fmt.Errorf("passphrase must be 8-63 characters")
		}
	}

	if profile.VlanID < 1 || profile.VlanID > 4094 {
		return fmt.Errorf("VLAN ID must be between 1 and 4094")
	}

	return nil
}

func validateRadioConfig(config *RadioConfig) error {
	validBands := []string{"2.4GHz", "5GHz", "6GHz"}
	validBand := false
	for _, band := range validBands {
		if config.Band == band {
			validBand = true
			break
		}
	}
	if !validBand {
		return fmt.Errorf("invalid band: %s", config.Band)
	}

	// Validate channel based on band
	switch config.Band {
	case "2.4GHz":
		validChannels := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
		if !contains(validChannels, config.Channel) {
			return fmt.Errorf("invalid 2.4GHz channel: %d", config.Channel)
		}
		validWidths := []int{20, 40}
		if !contains(validWidths, config.ChannelWidth) {
			return fmt.Errorf("invalid channel width for 2.4GHz: %d", config.ChannelWidth)
		}
	case "5GHz":
		// Simplified validation - in production, this would be more comprehensive
		if config.Channel < 32 || config.Channel > 173 {
			return fmt.Errorf("invalid 5GHz channel: %d", config.Channel)
		}
		validWidths := []int{20, 40, 80, 160}
		if !contains(validWidths, config.ChannelWidth) {
			return fmt.Errorf("invalid channel width for 5GHz: %d", config.ChannelWidth)
		}
	case "6GHz":
		if config.Channel < 1 || config.Channel > 233 {
			return fmt.Errorf("invalid 6GHz channel: %d", config.Channel)
		}
		validWidths := []int{20, 40, 80, 160, 320}
		if !contains(validWidths, config.ChannelWidth) {
			return fmt.Errorf("invalid channel width for 6GHz: %d", config.ChannelWidth)
		}
	}

	if config.TxPowerDbm < 1 || config.TxPowerDbm > 30 {
		return fmt.Errorf("invalid TX power: %d dBm", config.TxPowerDbm)
	}

	return nil
}

// ===== UTILITY FUNCTIONS =====

func generateProfileID() string {
	return fmt.Sprintf("profile_%d", time.Now().UnixNano())
}

func contains(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func performChannelScan(request ChannelScanRequest) {
	log.Printf("Starting channel scan for %d seconds", request.ScanDuration)

	// Simulate channel scanning
	scanResults := &ChannelScanResults{
		ScanTime:        time.Now(),
		Duration:        request.ScanDuration,
		Results:         make(map[string]*BandScanResults),
		Recommendations: make(map[string]*ChannelRecommendation),
	}

	// Generate simulated scan results for each band
	for _, band := range request.Bands {
		bandResults := generateBandScanResults(band)
		scanResults.Results[band] = bandResults
		
		// Generate recommendation
		recommendation := generateChannelRecommendation(bandResults)
		scanResults.Recommendations[band] = recommendation
	}

	// Sleep to simulate scan duration
	time.Sleep(time.Duration(request.ScanDuration) * time.Second)

	wirelessMutex.Lock()
	lastScanResults = scanResults
	wirelessMutex.Unlock()

	// Broadcast scan completion
	broadcastWirelessUpdate("channel_scan_completed", scanResults)

	log.Printf("Channel scan completed with %d band results", len(scanResults.Results))
}

func generateBandScanResults(band string) *BandScanResults {
	results := &BandScanResults{
		Band:         band,
		Channels:     []ChannelInfo{},
		Interference: 0.0,
		NoiseFloor:   -95,
	}

	// Generate channel data based on band
	switch band {
	case "2.4GHz":
		channels := []int{1, 6, 11} // Common non-overlapping channels
		for _, ch := range channels {
			utilization := 20.0 + float64(ch)*5.0 + (float64(time.Now().Unix()%100))/10.0
			if utilization > 100 {
				utilization = 100
			}
			
			results.Channels = append(results.Channels, ChannelInfo{
				Channel:      ch,
				Frequency:    2412 + (ch-1)*5,
				DFSRequired:  false,
				MaxTxPower:   20,
				Availability: "Available",
				Utilization:  utilization,
				NoiseFloor:   -95 + int(utilization/10),
			})
		}
		results.Interference = 0.15
	case "5GHz":
		channels := []int{36, 40, 44, 48, 149, 153, 157, 161}
		for _, ch := range channels {
			utilization := 10.0 + float64(ch)/10.0 + (float64(time.Now().Unix()%50))/10.0
			if utilization > 100 {
				utilization = 100
			}
			
			results.Channels = append(results.Channels, ChannelInfo{
				Channel:      ch,
				Frequency:    5000 + ch*5,
				DFSRequired:  ch >= 52 && ch <= 144,
				MaxTxPower:   24,
				Availability: "Available",
				Utilization:  utilization,
				NoiseFloor:   -98 + int(utilization/15),
			})
		}
		results.Interference = 0.08
	case "6GHz":
		channels := []int{37, 41, 45, 49, 93, 97}
		for _, ch := range channels {
			utilization := 2.0 + float64(ch)/20.0 + (float64(time.Now().Unix()%20))/10.0
			if utilization > 100 {
				utilization = 100
			}
			
			results.Channels = append(results.Channels, ChannelInfo{
				Channel:      ch,
				Frequency:    5950 + ch*5,
				DFSRequired:  false,
				MaxTxPower:   30,
				Availability: "Available",
				Utilization:  utilization,
				NoiseFloor:   -100 + int(utilization/20),
			})
		}
		results.Interference = 0.02
	}

	return results
}

func generateChannelRecommendation(bandResults *BandScanResults) *ChannelRecommendation {
	if len(bandResults.Channels) == 0 {
		return &ChannelRecommendation{
			RecommendedChannel:  1,
			Reason:             "No scan data available",
			ExpectedImprovement: 0,
		}
	}

	// Find channel with lowest utilization
	bestChannel := bandResults.Channels[0]
	for _, channel := range bandResults.Channels {
		if channel.Utilization < bestChannel.Utilization {
			bestChannel = channel
		}
	}

	reason := fmt.Sprintf("Lowest utilization (%.1f%%)", bestChannel.Utilization)
	if bestChannel.Utilization < 20 {
		reason += " - Excellent choice"
	} else if bestChannel.Utilization < 50 {
		reason += " - Good choice"
	} else {
		reason += " - Best available option"
	}

	return &ChannelRecommendation{
		RecommendedChannel:  bestChannel.Channel,
		Reason:             reason,
		ExpectedImprovement: math.Max(0, 80.0-bestChannel.Utilization),
	}
}

func broadcastWirelessUpdate(updateType string, data interface{}) {
	message := map[string]interface{}{
		"type":      "wireless_update",
		"subtype":   updateType,
		"data":      data,
		"timestamp": time.Now(),
	}

	broadcastMessage(message)
}

// ===== DEFAULT DATA GENERATORS =====

func getDefaultWirelessProfiles() []WirelessProfile {
	return []WirelessProfile{
		{
			ID:           "profile_home",
			Name:         "Home Network",
			SSID:         "EasyMesh-Home",
			SecurityType: "WPA3-SAE",
			Passphrase:   "SecureHome2024!",
			VlanID:       1,
			Hidden:       false,
			GuestNetwork: false,
			Enabled:      true,
			Bands:        []string{"2.4GHz", "5GHz", "6GHz"},
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		},
		{
			ID:                "profile_guest",
			Name:              "Guest Network",
			SSID:              "EasyMesh-Guest",
			SecurityType:      "WPA3-SAE",
			Passphrase:        "Guest2024!",
			VlanID:            20,
			Hidden:            false,
			GuestNetwork:      true,
			Enabled:           true,
			BandwidthLimitMbps: 50,
			Bands:             []string{"2.4GHz", "5GHz"},
			DeviceIsolation:   true,
			CaptivePortal: &CaptivePortal{
				Enabled:           true,
				SplashPage:        "default",
				TermsAcceptance:   true,
				SessionTimeoutMin: 240,
			},
			TimeRestriction: &TimeRestriction{
				Enabled:      true,
				AllowedHours: "08:00-22:00",
				AllowedDays:  []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
}

func getDefaultRadioConfigs() map[string]*RadioConfig {
	return map[string]*RadioConfig{
		"2.4GHz": {
			Band:            "2.4GHz",
			Enabled:         true,
			AutoChannel:     true,
			Channel:         6,
			ChannelWidth:    40,
			TxPowerAuto:     true,
			TxPowerDbm:      20,
			CountryCode:     "US",
			BeaconInterval:  100,
			DTIMPeriod:      2,
			RTSThreshold:    2347,
			FragThreshold:   2346,
			SupportedChannels: generateSupportedChannels("2.4GHz"),
		},
		"5GHz": {
			Band:            "5GHz",
			Enabled:         true,
			AutoChannel:     true,
			Channel:         149,
			ChannelWidth:    80,
			TxPowerAuto:     true,
			TxPowerDbm:      24,
			CountryCode:     "US",
			BeaconInterval:  100,
			DTIMPeriod:      2,
			RTSThreshold:    2347,
			FragThreshold:   2346,
			DFSEnabled:      true,
			SupportedChannels: generateSupportedChannels("5GHz"),
		},
		"6GHz": {
			Band:            "6GHz",
			Enabled:         true,
			AutoChannel:     true,
			Channel:         37,
			ChannelWidth:    160,
			TxPowerAuto:     true,
			TxPowerDbm:      30,
			CountryCode:     "US",
			BeaconInterval:  100,
			DTIMPeriod:      2,
			RTSThreshold:    2347,
			FragThreshold:   2346,
			PSCOnly:         false,
			WiFi7Features: &WiFi7Features{
				MLOEnabled:        true,
				MultiRUEnabled:    true,
				PuncturedPreamble: true,
				Support320MHz:     false,
			},
			SupportedChannels: generateSupportedChannels("6GHz"),
		},
	}
}

func generateSupportedChannels(band string) []ChannelInfo {
	var channels []ChannelInfo

	switch band {
	case "2.4GHz":
		for ch := 1; ch <= 11; ch++ {
			channels = append(channels, ChannelInfo{
				Channel:      ch,
				Frequency:    2412 + (ch-1)*5,
				DFSRequired:  false,
				MaxTxPower:   20,
				Availability: "Available",
			})
		}
	case "5GHz":
		channelList := []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}
		for _, ch := range channelList {
			channels = append(channels, ChannelInfo{
				Channel:      ch,
				Frequency:    5000 + ch*5,
				DFSRequired:  ch >= 52 && ch <= 144,
				MaxTxPower:   24,
				Availability: "Available",
			})
		}
	case "6GHz":
		for ch := 1; ch <= 233; ch += 4 {
			channels = append(channels, ChannelInfo{
				Channel:      ch,
				Frequency:    5950 + ch*5,
				DFSRequired:  false,
				MaxTxPower:   30,
				Availability: "Available",
			})
		}
	}

	return channels
}

func getDefaultAdvancedSettings() *AdvancedWirelessSettings {
	return &AdvancedWirelessSettings{
		BandSteering: &BandSteeringConfig{
			Enabled:               true,
			Policy:                "balanced",
			RSSIThreshold2G4:      -70,
			RSSIThreshold5G:       -65,
			RSSIThreshold6G:       -60,
			UtilizationThreshold:  75.0,
			BlockTimeSeconds:      30,
			ProbeResponseSuppress: true,
		},
		LoadBalancing: &LoadBalancingConfig{
			Enabled:                  true,
			Algorithm:                "airtime_fairness",
			RebalanceIntervalSeconds: 60,
			ClientCountThreshold:     15,
			UtilizationThreshold:     70.0,
			RSSIDifferenceThreshold:  10,
		},
		AirtimeFairness: true,
		FastTransition:  true,
		OFDMA:          true,
		MUMIMO:         true,
		Beamforming:    true,
		TWT:            true,
		SpatialReuse:   true,
		UpdatedAt:      time.Now(),
	}
}


func loadDevices() {
	file, err := os.Open("devices.json")
	if err != nil {
		log.Printf("Warning: Could not load devices.json: %v", err)
		devices = getDefaultDevices()
		return
	}
	defer file.Close()

	data, _ := io.ReadAll(file)
	if err := json.Unmarshal(data, &devices); err != nil {
		log.Printf("Error parsing devices.json: %v", err)
		devices = getDefaultDevices()
	}
	log.Printf("Loaded %d devices", len(devices))
}

func loadClients() {
	file, err := os.Open("clients.json")
	if err != nil {
		log.Printf("Warning: Could not load clients.json: %v", err)
		clients = getSampleClients()
		return
	}
	defer file.Close()

	data, _ := io.ReadAll(file)
	if err := json.Unmarshal(data, &clients); err != nil {
		log.Printf("Error parsing clients.json: %v", err)
		clients = getSampleClients()
	}
	log.Printf("Loaded %d clients", len(clients))
}

func loadSystemConfig() {
	systemConfig = getDefaultSystemConfig()
	log.Printf("Loaded system configuration")
}

// ===== MAIN SERVER =====

func main() {
	router := mux.NewRouter()

	// Serve static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	router.HandleFunc("/", serveIndex).Methods("GET")

	// API Routes
	api := router.PathPrefix("/api/v1").Subrouter()

	// Device Management
	api.HandleFunc("/devices", getDevicesHandler).Methods("GET")
	api.HandleFunc("/devices/{mac}", getDeviceHandler).Methods("GET")
	api.HandleFunc("/devices/{mac}/reboot", rebootDeviceHandler).Methods("POST")

	// Client Management
	api.HandleFunc("/clients", getClientsHandler).Methods("GET")
	api.HandleFunc("/clients/{mac}", getClientHandler).Methods("GET")
	api.HandleFunc("/clients/{mac}/disconnect", disconnectClientHandler).Methods("POST")
	api.HandleFunc("/clients/{mac}/block", blockClientHandler).Methods("POST")
	api.HandleFunc("/clients/{mac}/unblock", unblockClientHandler).Methods("POST")
        //ckp1 start
        // ===== NEW WIRELESS SETTINGS ROUTES =====
	
	// Wireless Profile Management
	api.HandleFunc("/wireless/profiles", getWirelessProfilesHandler).Methods("GET")
	api.HandleFunc("/wireless/profiles", createWirelessProfileHandler).Methods("POST")
	api.HandleFunc("/wireless/profiles/{id}", updateWirelessProfileHandler).Methods("PUT")
	api.HandleFunc("/wireless/profiles/{id}", deleteWirelessProfileHandler).Methods("DELETE")
	api.HandleFunc("/wireless/profiles/{id}/toggle", toggleWirelessProfileHandler).Methods("POST")

	// Radio Configuration
	api.HandleFunc("/wireless/radios", getRadioConfigsHandler).Methods("GET")
	api.HandleFunc("/wireless/radios/{band}", updateRadioConfigHandler).Methods("PUT")

	// Advanced Wireless Settings
	api.HandleFunc("/wireless/advanced", getAdvancedWirelessSettingsHandler).Methods("GET")
	api.HandleFunc("/wireless/advanced", updateAdvancedWirelessSettingsHandler).Methods("PUT")

	// Channel Scanning
	api.HandleFunc("/wireless/scan", startChannelScanHandler).Methods("POST")
	api.HandleFunc("/wireless/scan/results", getChannelScanResultsHandler).Methods("GET")

	// Complete Wireless Configuration
	api.HandleFunc("/wireless/config", getWirelessConfigHandler).Methods("GET")
	api.HandleFunc("/wireless/config", updateWirelessConfigHandler).Methods("PUT")
        // ===== NEW COVERAGE MAP ROUTES =====
	
	// Coverage Analysis
	api.HandleFunc("/coverage/analysis", getCoverageAnalysisHandler).Methods("GET")
	api.HandleFunc("/coverage/analyze", analyzeCoverageHandler).Methods("POST")
	
	// Placement Optimization
	api.HandleFunc("/coverage/optimize", optimizePlacementHandler).Methods("POST")
	
	// Floor Plan Management
	api.HandleFunc("/coverage/floorplans", getFloorPlansHandler).Methods("GET")
	api.HandleFunc("/coverage/floorplans", uploadFloorPlanHandler).Methods("POST")
	api.HandleFunc("/coverage/floorplans/{id}", getFloorPlanHandler).Methods("GET")
	api.HandleFunc("/coverage/floorplans/{id}", updateFloorPlanHandler).Methods("PUT")
	api.HandleFunc("/coverage/floorplans/{id}", deleteFloorPlanHandler).Methods("DELETE")
	
	// Coverage Heatmap Data
	api.HandleFunc("/coverage/heatmap", getCoverageHeatmapHandler).Methods("GET")
	api.HandleFunc("/coverage/heatmap/{band}", getBandHeatmapHandler).Methods("GET")
	
	// Device Placement Simulation
	api.HandleFunc("/coverage/simulate", simulateDevicePlacementHandler).Methods("POST")
	api.HandleFunc("/coverage/placement/predict", predictPlacementHandler).Methods("POST")
	
	// Weak Zone Analysis
	api.HandleFunc("/coverage/weakzones", getWeakZonesHandler).Methods("GET")
	api.HandleFunc("/coverage/deadspots", getDeadSpotsHandler).Methods("GET")
	
	// Coverage Reports
	api.HandleFunc("/coverage/report", generateCoverageReportHandler).Methods("GET")
	api.HandleFunc("/coverage/report/pdf", generateCoverageReportPDFHandler).Methods("GET")

	// Existing routes continue...
	api.HandleFunc("/topology", getTopologyHandler).Methods("GET")
	api.HandleFunc("/topology/optimize", optimizeTopologyHandler).Methods("POST")

        //ckp1 end
	// Topology and Network
	api.HandleFunc("/topology", getTopologyHandler).Methods("GET")
	api.HandleFunc("/topology/optimize", optimizeTopologyHandler).Methods("POST")
 
	// Metrics and Monitoring
	api.HandleFunc("/metrics/devices", getDeviceMetricsHandler).Methods("GET")
	api.HandleFunc("/metrics/clients", getClientMetricsHandler).Methods("GET")
	api.HandleFunc("/metrics/performance", getPerformanceMetricsHandler).Methods("GET")
	api.HandleFunc("/metrics/interference", getInterferenceAnalysisHandler).Methods("GET")

	// Configuration
	api.HandleFunc("/config", getSystemConfigHandler).Methods("GET")
	api.HandleFunc("/config", updateSystemConfigHandler).Methods("PUT")

	// Security
	api.HandleFunc("/security/profiles", getSecurityProfilesHandler).Methods("GET")
	api.HandleFunc("/security/threats", getThreatAnalysisHandler).Methods("GET")

	// Firmware Management
	api.HandleFunc("/firmware/status", getFirmwareStatusHandler).Methods("GET")
	api.HandleFunc("/firmware/update", updateFirmwareHandler).Methods("POST")

	// Reports
	api.HandleFunc("/reports/usage", getUsageReportHandler).Methods("GET")
	api.HandleFunc("/reports/performance", getPerformanceReportHandler).Methods("GET")
	// WebSocket
	api.HandleFunc("/ws", websocketHandler)

	// System Operations
	api.HandleFunc("/system/status", getSystemStatusHandler).Methods("GET")
	api.HandleFunc("/system/logs", getSystemLogsHandler).Methods("GET")

	// Enable CORS
	router.Use(corsMiddleware)

	// Start background tasks
	go startMetricsUpdater()
	go startWebSocketBroadcaster()

	fmt.Printf("🌐 EasyMesh R6 Controller running on http://0.0.0.0:8888\n")
	fmt.Printf("📊 Dashboard: http://0.0.0.0:8888\n")
	fmt.Printf("🔌 WebSocket: ws://0.0.0.0:8888/api/v1/ws\n")

	log.Fatal(http.ListenAndServe("0.0.0.0:8888", router))
}

// ===== MIDDLEWARE =====

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Relaxed CORS for demo; scope for prod
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ===== HANDLERS =====

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/index.html")
}

func getDevicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	onlineCount := 0
	for _, device := range devices {
		if device.Status == "Online" {
			onlineCount++
		}
	}

	response := map[string]interface{}{
		"devices": devices,
		"total":   len(devices),
		"online":  onlineCount,
		"updated": time.Now(),
	}

	_ = json.NewEncoder(w).Encode(response)
}

func getDeviceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mac := vars["mac"]

	for _, device := range devices {
		if device.MAC == mac {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(device)
			return
		}
	}

	http.Error(w, "Device not found", http.StatusNotFound)
}

func rebootDeviceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mac := vars["mac"]

	for i, device := range devices {
		if device.MAC == mac {
			devices[i].Status = "Rebooting"
			devices[i].LastSeen = time.Now()

			broadcastDeviceUpdate(devices[i])

			go func(deviceIndex int) {
				time.Sleep(30 * time.Second)
				devices[deviceIndex].Status = "Online"
				devices[deviceIndex].LastSeen = time.Now()
				broadcastDeviceUpdate(devices[deviceIndex])
			}(i)

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":  "success",
				"message": "Device reboot initiated",
			})
			return
		}
	}

	http.Error(w, "Device not found", http.StatusNotFound)
}

func getClientsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	activeCount := 0
	for _, client := range clients {
		if time.Since(client.LastActivity) < 5*time.Minute {
			activeCount++
		}
	}

	response := map[string]interface{}{
		"clients": clients,
		"total":   len(clients),
		"active":  activeCount,
		"updated": time.Now(),
	}

	_ = json.NewEncoder(w).Encode(response)
}

func getClientHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mac := vars["mac"]

	for _, client := range clients {
		if client.MAC == mac {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(client)
			return
		}
	}

	http.Error(w, "Client not found", http.StatusNotFound)
}

func disconnectClientHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mac := vars["mac"]

	for i, client := range clients {
		if client.MAC == mac {
			clients = append(clients[:i], clients[i+1:]...)

			broadcastMessage(map[string]interface{}{
				"type":      "client_disconnected",
				"mac":       mac,
				"timestamp": time.Now(),
			})

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":  "success",
				"message": "Client disconnected",
			})
			return
		}
	}

	http.Error(w, "Client not found", http.StatusNotFound)
}

func blockClientHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mac := vars["mac"]

	systemConfig.SecuritySettings.BlockedMACs = append(systemConfig.SecuritySettings.BlockedMACs, mac)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Client blocked",
	})
}

func unblockClientHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mac := vars["mac"]

	for i, blockedMAC := range systemConfig.SecuritySettings.BlockedMACs {
		if blockedMAC == mac {
			systemConfig.SecuritySettings.BlockedMACs = append(
				systemConfig.SecuritySettings.BlockedMACs[:i],
				systemConfig.SecuritySettings.BlockedMACs[i+1:]...,
			)
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Client unblocked",
	})
}

func getTopologyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meshTopology)
}

func optimizeTopologyHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Starting topology optimization...")
	generateMeshTopology()

	broadcastMessage(map[string]interface{}{
		"type":      "topology_optimized",
		"topology":  meshTopology,
		"timestamp": time.Now(),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "success",
		"message":  "Topology optimization completed",
		"topology": meshTopology,
	})
}

func getDeviceMetricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := make(map[string]interface{})
	for _, device := range devices {
		metrics[device.MAC] = device.Metrics
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"metrics":   metrics,
		"timestamp": time.Now(),
	})
}

func getClientMetricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := make(map[string]interface{})
	for _, client := range clients {
		metrics[client.MAC] = client.ClientMetrics
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"metrics":   metrics,
		"timestamp": time.Now(),
	})
}

func getPerformanceMetricsHandler(w http.ResponseWriter, r *http.Request) {
	performance := calculatePerformanceMetrics()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(performance)
}

func getInterferenceAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	analysis := map[string]interface{}{
		"bands": map[string]interface{}{
			"2.4GHz": map[string]interface{}{
				"interference_level": 0.15,
				"noise_floor":        -95,
				"sources":            []string{"Microwave Oven", "Bluetooth Devices"},
			},
			"5GHz": map[string]interface{}{
				"interference_level": 0.08,
				"noise_floor":        -98,
				"sources":            []string{"Neighboring APs"},
			},
			"6GHz": map[string]interface{}{
				"interference_level": 0.02,
				"noise_floor":        -100,
				"sources":            []string{},
			},
		},
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(analysis)
}

func getSystemConfigHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(systemConfig)
}

func updateSystemConfigHandler(w http.ResponseWriter, r *http.Request) {
	var newConfig SystemConfig
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	systemConfig = newConfig

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "System configuration updated",
	})
}

func getSecurityProfilesHandler(w http.ResponseWriter, r *http.Request) {
	profiles := []SecurityProfile{
		{
			ProfileName:    "Enterprise-Grade",
			AuthMethod:     "WPA3-SAE",
			EncryptionType: "AES-256",
			SecurityLevel:  "High",
		},
		{
			ProfileName:    "Consumer-Premium",
			AuthMethod:     "WPA3-SAE",
			EncryptionType: "AES-256",
			SecurityLevel:  "High",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"profiles":  profiles,
		"timestamp": time.Now(),
	})
}

func getThreatAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	threats := map[string]interface{}{
		"threat_level":     "low",
		"active_threats":   0,
		"blocked_attempts": 5,
		"security_score":   98,
		"timestamp":        time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(threats)
}

func getFirmwareStatusHandler(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"current_version":  "6.2.1",
		"latest_version":   "6.2.2",
		"update_available": true,
		"timestamp":        time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func updateFirmwareHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "success",
		"message":        "Firmware update initiated",
		"estimated_time": "15 minutes",
		"timestamp":      time.Now(),
	})
}

func getUsageReportHandler(w http.ResponseWriter, r *http.Request) {
	timeRange := r.URL.Query().Get("range")
	if timeRange == "" {
		timeRange = "7d"
	}

	report := map[string]interface{}{
		"timeRange":     timeRange,
		"totalData":     "125.4 GB",
		"avgThroughput": "847 Mbps",
		"timestamp":     time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

func getPerformanceReportHandler(w http.ResponseWriter, r *http.Request) {
	report := map[string]interface{}{
		"avgLatency":  "3.2 ms",
		"packetLoss":  "0.08%",
		"uptime":      "99.95%",
		"healthScore": calculateHealthScore(),
		"timestamp":   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

func getSystemStatusHandler(w http.ResponseWriter, r *http.Request) {
	onlineDevices := 0
	for _, device := range devices {
		if device.Status == "Online" {
			onlineDevices++
		}
	}

	activeClients := 0
	for _, client := range clients {
		if time.Since(client.LastActivity) < 5*time.Minute {
			activeClients++
		}
	}

	status := map[string]interface{}{
		"controller":     "running",
		"version":        "EasyMesh R6 v1.0.0",
		"protocol":       "IEEE 1905.1 + Multi-AP R6",
		"uptime":         "7 days, 3 hours, 42 minutes",
		"mesh_nodes":     len(devices),
		"online_nodes":   onlineDevices,
		"active_clients": activeClients,
		"health_score":   calculateHealthScore(),
		"timestamp":      time.Now().Format(time.RFC3339),
		"features": map[string]bool{
			"wifi7_support":      true,
			"coordinated_scan":   true,
			"optimized_roaming":  true,
			"traffic_separation": true,
			"advanced_security":  true,
			"ai_optimization":    true,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func getSystemLogsHandler(w http.ResponseWriter, r *http.Request) {
	level := r.URL.Query().Get("level")
	countStr := r.URL.Query().Get("count")

	count := 100
	if countStr != "" {
		if c, err := strconv.Atoi(countStr); err == nil {
			count = c
		}
	}

	logs := []map[string]interface{}{
		{"level": "info", "message": "Client connected: MacBook Pro M3", "timestamp": time.Now().Add(-5 * time.Minute)},
		{"level": "warning", "message": "High channel utilization on 2.4GHz", "timestamp": time.Now().Add(-15 * time.Minute)},
		{"level": "info", "message": "Mesh optimization completed", "timestamp": time.Now().Add(-30 * time.Minute)},
	}

	if level != "" {
		filtered := []map[string]interface{}{}
		for _, l := range logs {
			if l["level"] == level {
				filtered = append(filtered, l)
			}
		}
		logs = filtered
	}

	if len(logs) > count {
		logs = logs[:count]
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":      logs,
		"total":     len(logs),
		"timestamp": time.Now(),
	})
}

// ===== WEBSOCKET HANDLER =====

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	// Add read safety/keepalive
	conn.SetReadLimit(1 << 20) // 1 MB
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(appData string) error {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Track connection
	wsMu.Lock()
	wsConnections = append(wsConnections, conn)
	total := len(wsConnections)
	wsMu.Unlock()
	log.Printf("WebSocket client connected. Total: %d", total)

	// Send initial payload
	initialData := map[string]interface{}{
		"type":      "initial",
		"devices":   devices,
		"clients":   clients,
		"topology":  meshTopology,
		"timestamp": time.Now(),
	}
	if err := conn.WriteJSON(initialData); err != nil {
		log.Printf("Error sending initial data: %v", err)
		_ = conn.Close()
		return
	}

	// Writer ping loop (keeps proxies/NAT happy)
	done := make(chan struct{})
	go func(c *websocket.Conn) {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := c.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(10*time.Second)); err != nil {
					_ = c.Close()
					return
				}
			case <-done:
				return
			}
		}
	}(conn)

	// Read loop (client may not send; this just detects close/errors)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			// remove connection
			wsMu.Lock()
			for i, c := range wsConnections {
				if c == conn {
					wsConnections = append(wsConnections[:i], wsConnections[i+1:]...)
					break
				}
			}
			total = len(wsConnections)
			wsMu.Unlock()
			close(done)
			_ = conn.Close()
			log.Printf("WebSocket client disconnected. Total: %d", total)
			return
		}
	}
}

// ===== BACKGROUND TASKS =====

func startMetricsUpdater() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		updateDeviceMetrics()
		updateClientMetrics()

		broadcastMessage(map[string]interface{}{
			"type":      "metrics_update",
			"timestamp": time.Now(),
			// Optionally attach metrics payload here
		})
	}
}

func startWebSocketBroadcaster() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		wsMu.Lock()
		cc := len(wsConnections)
		wsMu.Unlock()
		broadcastMessage(map[string]interface{}{
			"type":              "heartbeat",
			"timestamp":         time.Now(),
			"connected_clients": cc,
		})
	}
}

// ===== WEBSOCKET HELPERS =====

func broadcastDeviceUpdate(device Device) {
	message := map[string]interface{}{
		"type":      "device_update",
		"device":    device,
		"timestamp": time.Now(),
	}
	broadcastMessage(message)
}

func broadcastMessage(message map[string]interface{}) {
	wsMu.Lock()
	defer wsMu.Unlock()

	active := wsConnections[:0]
	for _, conn := range wsConnections {
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteJSON(message); err != nil {
			_ = conn.Close()
			continue
		}
		active = append(active, conn)
	}
	wsConnections = active
}

// ===== UTILITY FUNCTIONS =====

func calculateHealthScore() int {
	onlineDevices := 0
	for _, device := range devices {
		if device.Status == "Online" {
			onlineDevices++
		}
	}
	if len(devices) == 0 {
		return 0
	}
	return (onlineDevices * 100) / len(devices)
}

func calculatePerformanceMetrics() PerformanceMetrics {
	return PerformanceMetrics{
		AverageThroughput: 847.5,
		AverageLatency:    3.2,
		TotalClients:      len(clients),
	}
}

func updateDeviceMetrics() {
	for i := range devices {
		if devices[i].Status == "Online" {
			devices[i].Metrics.CPUUsage = 20.0 + float64(i)*5.0
			devices[i].Metrics.MemoryUsage = 40.0 + float64(i)*3.0
			devices[i].Metrics.Temperature = 35.0 + float64(i)*2.0
			devices[i].Metrics.LastUpdated = time.Now()
		}
	}
}

func updateClientMetrics() {
	for i := range clients {
		clients[i].ClientMetrics.LastUpdated = time.Now()
		clients[i].LastActivity = time.Now()
	}
}

// ===== DEFAULT DATA =====

func getDefaultDevices() []Device {
	return []Device{
		{
			MAC:       "AA:BB:CC:00:00:01",
			Role:      "Controller",
			Vendor:    "OpenSync",
			Model:     "EasyMesh-R6-Pro",
			IPAddress: "192.168.1.1",
			Status:    "Online",
			LastSeen:  time.Now(),
			Uptime:    "7d 3h 42m",
			Capabilities: Capability{
				WiFi7Support:   true,
				MaxMeshLinks:   8,
				Firmware:       "v6.2.1-easymesh-r6",
				SerialNumber:   "ESM001R6PRO",
				SupportedBands: []string{"2.4GHz", "5GHz", "6GHz"},
			},
			Metrics: DeviceMetrics{
				CPUUsage:         32.5,
				MemoryUsage:      58.2,
				Temperature:      45.8,
				PowerConsumption: 25.4,
				LastUpdated:      time.Now(),
			},
			SecurityProfile: SecurityProfile{
				ProfileName:    "Enterprise-Grade",
				AuthMethod:     "WPA3-SAE",
				EncryptionType: "AES-256",
				SecurityLevel:  "High",
			},
			Location: Location{
				Building:    "Main House",
				Floor:       "1st Floor",
				Room:        "Network Closet",
				Description: "Primary controller",
				Position3D:  Point3D{X: 0.0, Y: 0.0, Z: 0.8},
			},
		},
		{
			MAC:       "AA:BB:CC:00:00:02",
			Role:      "Agent",
			Vendor:    "Plume",
			Model:     "SuperPod-R6",
			IPAddress: "192.168.1.10",
			Status:    "Online",
			LastSeen:  time.Now(),
			Uptime:    "6d 12h 18m",
			Capabilities: Capability{
				WiFi7Support:   true,
				MaxMeshLinks:   4,
				Firmware:       "v3.1.2-plume-r6",
				SerialNumber:   "PLM002SP6",
				SupportedBands: []string{"5GHz", "6GHz"},
			},
			Metrics: DeviceMetrics{
				CPUUsage:         28.3,
				MemoryUsage:      42.8,
				Temperature:      38.2,
				PowerConsumption: 18.7,
				LastUpdated:      time.Now(),
			},
			SecurityProfile: SecurityProfile{
				ProfileName:    "Consumer-Premium",
				AuthMethod:     "WPA3-SAE",
				EncryptionType: "AES-256",
				SecurityLevel:  "High",
			},
			Location: Location{
				Building:    "Main House",
				Floor:       "1st Floor",
				Room:        "Living Room",
				Description: "Wall-mounted agent",
				Position3D:  Point3D{X: 5.0, Y: 0.0, Z: 1.5},
			},
		},
		{
			MAC:       "AA:BB:CC:00:00:03",
			Role:      "Agent",
			Vendor:    "Google",
			Model:     "Nest Wifi Pro 6E R6",
			IPAddress: "192.168.1.11",
			Status:    "Online",
			LastSeen:  time.Now(),
			Uptime:    "5d 8h 26m",
			Capabilities: Capability{
				WiFi7Support:   false,
				MaxMeshLinks:   6,
				Firmware:       "v1.9.3-nest-r6",
				SerialNumber:   "NST003P6E",
				SupportedBands: []string{"2.4GHz", "5GHz", "6GHz"},
			},
			Metrics: DeviceMetrics{
				CPUUsage:         35.7,
				MemoryUsage:      48.9,
				Temperature:      42.1,
				PowerConsumption: 22.3,
				LastUpdated:      time.Now(),
			},
			SecurityProfile: SecurityProfile{
				ProfileName:    "Standard",
				AuthMethod:     "WPA3-SAE",
				EncryptionType: "AES-256",
				SecurityLevel:  "Medium",
			},
			Location: Location{
				Building:    "Main House",
				Floor:       "2nd Floor",
				Room:        "Master Bedroom",
				Description: "Bedside placement",
				Position3D:  Point3D{X: 8.0, Y: 4.0, Z: 4.2},
			},
		},
	}
}

func getSampleClients() []Client {
	return []Client{
		{
			MAC:            "44:85:00:12:34:56",
			Hostname:       "MacBook Pro M3",
			IPAddress:      "192.168.1.101",
			ConnectedAP:    "AA:BB:CC:00:00:01",
			ConnectedBSSID: "AA:BB:CC:00:00:03",
			ConnectionTime: time.Now().Add(-2 * time.Hour),
			DeviceType:     "laptop",
			Manufacturer:   "Apple Inc.",
			LastActivity:   time.Now(),
			ClientMetrics: ClientMetrics{
				RSSI:        -42,
				SNR:         56,
				TxRate:      1201,
				RxRate:      1201,
				Latency:     2.1,
				DataUsage:   10737418240,
				LastUpdated: time.Now(),
			},
			Location: ClientLocation{
				EstimatedPosition: Point3D{X: 2.5, Y: -1.0, Z: 1.2},
				ConnectedAP:       "AA:BB:CC:00:00:01",
				LastUpdate:        time.Now(),
				Accuracy:          3.2,
			},
		},
		{
			MAC:            "8C:85:90:AB:CD:EF",
			Hostname:       "iPhone 15 Pro Max",
			IPAddress:      "192.168.1.102",
			ConnectedAP:    "AA:BB:CC:00:00:02",
			ConnectedBSSID: "AA:BB:CC:00:00:05",
			ConnectionTime: time.Now().Add(-3 * time.Hour),
			DeviceType:     "smartphone",
			Manufacturer:   "Apple Inc.",
			LastActivity:   time.Now(),
			ClientMetrics: ClientMetrics{
				RSSI:        -58,
				SNR:         41,
				TxRate:      867,
				RxRate:      867,
				Latency:     8.2,
				DataUsage:   2560000000,
				LastUpdated: time.Now(),
			},
			Location: ClientLocation{
				EstimatedPosition: Point3D{X: 5.2, Y: 0.8, Z: 1.4},
				ConnectedAP:       "AA:BB:CC:00:00:02",
				LastUpdate:        time.Now(),
				Accuracy:          2.8,
			},
		},
	}
}

func getDefaultSystemConfig() SystemConfig {
	return SystemConfig{
		ControllerSettings: ControllerSettings{
			AutoOptimization:   true,
			ChannelPlanning:    true,
			PowerManagement:    true,
			FirmwareManagement: true,
		},
		SecuritySettings: SecuritySettings{
			IntrusionDetection: true,
			AccessControl:      true,
			ThreatProtection:   true,
			AllowedMACs:        []string{},
			BlockedMACs:        []string{},
		},
	}
}

func generateMeshTopology() {
	meshTopology = MeshTopology{
		MeshID:        "EasyMesh-R6-Network-001",
		ControllerMAC: "AA:BB:CC:00:00:01",
		Nodes:         len(devices),
		Protocol:      "IEEE 1905.1 + Multi-AP R6",
		Version:       "R6",
		Performance:   calculatePerformanceMetrics(),
		LastUpdated:   time.Now(),
	}
}

