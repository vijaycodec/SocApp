// PATCH 47 Extension: AlienVault OTX Proxy
// Purpose: Proxy OTX threat intelligence data through backend to avoid CORS and keep API key secure
// Security: OTX API key stored server-side only (not exposed to frontend)

import { ApiResponse } from "../utils/ApiResponse.js";
import { ApiError } from "../utils/ApiError.js";
import redisClient from "../config/redisClient.js";

// AlienVault OTX API Configuration
const OTX_API_KEY = process.env.ALIEN_VAULT_OTX_API_KEY || '';
const OTX_BASE_URL = 'https://otx.alienvault.com/api/v1';

// Redis cache configuration
const CACHE_TTL = 900; // 15 minutes in seconds
const OTX_CACHE_KEY = 'global_threat_intelligence';

/**
 * Generate mock OTX data for development/testing
 */
function generateMockOTXData() {
  const mockThreats = [
    {
      id: 'mock-1',
      name: 'Malicious IP Scanner',
      type: 'Reconnaissance',
      severity: 'high',
      latitude: 37.7749,
      longitude: -122.4194,
      country: 'United States',
      ip: '192.0.2.1',
      description: 'Automated port scanning from suspicious source'
    },
    {
      id: 'mock-2',
      name: 'Botnet C&C Server',
      type: 'Malware',
      severity: 'critical',
      latitude: 51.5074,
      longitude: -0.1278,
      country: 'United Kingdom',
      ip: '198.51.100.50',
      description: 'Known command and control server for botnet operations'
    },
    {
      id: 'mock-3',
      name: 'Phishing Campaign',
      type: 'Phishing',
      severity: 'medium',
      latitude: 35.6762,
      longitude: 139.6503,
      country: 'Japan',
      ip: '203.0.113.100',
      description: 'Active phishing campaign targeting financial institutions'
    },
    {
      id: 'mock-4',
      name: 'DDoS Attacker',
      type: 'DDoS',
      severity: 'high',
      latitude: 52.5200,
      longitude: 13.4050,
      country: 'Germany',
      ip: '192.0.2.150',
      description: 'Participating in distributed denial of service attack'
    },
    {
      id: 'mock-5',
      name: 'Malware Distribution',
      type: 'Malware',
      severity: 'critical',
      latitude: 48.8566,
      longitude: 2.3522,
      country: 'France',
      ip: '198.51.100.200',
      description: 'Hosting and distributing ransomware payloads'
    },
    {
      id: 'mock-6',
      name: 'Credential Harvester',
      type: 'Credential Theft',
      severity: 'high',
      latitude: 55.7558,
      longitude: 37.6173,
      country: 'Russia',
      ip: '203.0.113.250',
      description: 'Collecting stolen credentials from compromised systems'
    },
    {
      id: 'mock-7',
      name: 'SQL Injection Scanner',
      type: 'Web Attack',
      severity: 'medium',
      latitude: 1.3521,
      longitude: 103.8198,
      country: 'Singapore',
      ip: '192.0.2.75',
      description: 'Automated SQL injection attack attempts'
    },
    {
      id: 'mock-8',
      name: 'Cryptominer',
      type: 'Cryptocurrency Mining',
      severity: 'medium',
      latitude: -33.8688,
      longitude: 151.2093,
      country: 'Australia',
      ip: '198.51.100.125',
      description: 'Unauthorized cryptocurrency mining activity'
    },
    {
      id: 'mock-9',
      name: 'APT Campaign',
      type: 'Advanced Persistent Threat',
      severity: 'critical',
      latitude: 39.9042,
      longitude: 116.4074,
      country: 'China',
      ip: '203.0.113.180',
      description: 'State-sponsored advanced persistent threat activity'
    },
    {
      id: 'mock-10',
      name: 'Spam Bot',
      type: 'Spam',
      severity: 'low',
      latitude: -23.5505,
      longitude: -46.6333,
      country: 'Brazil',
      ip: '192.0.2.220',
      description: 'Automated spam distribution network'
    },
    {
      id: 'mock-11',
      name: 'Zero-Day Exploit',
      type: 'Exploit',
      severity: 'critical',
      latitude: 28.6139,
      longitude: 77.2090,
      country: 'India',
      ip: '198.51.100.88',
      description: 'Actively exploiting unpatched vulnerability'
    }
  ];

  // Generate arcs (attack paths) between threats
  const mockArcs = [
    {
      startLat: 37.7749,
      startLng: -122.4194,
      endLat: 51.5074,
      endLng: -0.1278,
      color: '#ff4444',
      label: 'Scanner → C&C'
    },
    {
      startLat: 51.5074,
      startLng: -0.1278,
      endLat: 35.6762,
      endLng: 139.6503,
      color: '#ff8844',
      label: 'C&C → Phishing'
    },
    {
      startLat: 52.5200,
      startLng: 13.4050,
      endLat: 48.8566,
      endLng: 2.3522,
      color: '#ff4444',
      label: 'DDoS → Malware'
    },
    {
      startLat: 55.7558,
      startLng: 37.6173,
      endLat: 1.3521,
      endLng: 103.8198,
      color: '#ff8844',
      label: 'Credential → SQLi'
    },
    {
      startLat: -33.8688,
      startLng: 151.2093,
      endLat: 39.9042,
      endLng: 116.4074,
      color: '#ffaa44',
      label: 'Cryptominer → APT'
    },
    {
      startLat: -23.5505,
      startLng: -46.6333,
      endLat: 28.6139,
      endLng: 77.2090,
      color: '#ff4444',
      label: 'Spam → Exploit'
    },
    {
      startLat: 37.7749,
      startLng: -122.4194,
      endLat: 28.6139,
      endLng: 77.2090,
      color: '#ff4444',
      label: 'Scanner → Exploit'
    },
    {
      startLat: 51.5074,
      startLng: -0.1278,
      endLat: 55.7558,
      endLng: 37.6173,
      color: '#ff8844',
      label: 'C&C → Credential'
    },
    {
      startLat: 48.8566,
      startLng: 2.3522,
      endLat: -23.5505,
      endLng: -46.6333,
      color: '#ff4444',
      label: 'Malware → Spam'
    },
    {
      startLat: 35.6762,
      startLng: 139.6503,
      endLat: 52.5200,
      endLng: 13.4050,
      color: '#ffaa44',
      label: 'Phishing → DDoS'
    },
    {
      startLat: 39.9042,
      startLng: 116.4074,
      endLat: -33.8688,
      endLng: 151.2093,
      color: '#ff4444',
      label: 'APT → Cryptominer'
    },
    {
      startLat: 1.3521,
      startLng: 103.8198,
      endLat: 48.8566,
      endLng: 2.3522,
      color: '#ff8844',
      label: 'SQLi → Malware'
    },
    {
      startLat: 28.6139,
      startLng: 77.2090,
      endLat: 37.7749,
      endLng: -122.4194,
      color: '#ff4444',
      label: 'Exploit → Scanner'
    },
    {
      startLat: 55.7558,
      startLng: 37.6173,
      endLat: 39.9042,
      endLng: 116.4074,
      color: '#ff4444',
      label: 'Credential → APT'
    },
    {
      startLat: -23.5505,
      startLng: -46.6333,
      endLat: 35.6762,
      endLng: 139.6503,
      color: '#ffaa44',
      label: 'Spam → Phishing'
    },
    {
      startLat: 52.5200,
      startLng: 13.4050,
      endLat: 1.3521,
      endLng: 103.8198,
      color: '#ff8844',
      label: 'DDoS → SQLi'
    },
    {
      startLat: -33.8688,
      startLng: 151.2093,
      endLat: 51.5074,
      endLng: -0.1278,
      color: '#ff4444',
      label: 'Cryptominer → C&C'
    }
  ];

  return {
    success: true,
    source: 'mock',
    message: 'Mock OTX data (API key not configured)',
    threats: mockThreats,
    arcs: mockArcs,
    count: mockThreats.length
  };
}

/**
 * Fetch real OTX threat intelligence data
 */
async function fetchOTXData() {
  if (!OTX_API_KEY || OTX_API_KEY === '') {
    console.warn('[OTX Proxy] No API key configured, using mock data');
    return generateMockOTXData();
  }

  try {
    // Fetch pulse data from OTX
    const response = await fetch(`${OTX_BASE_URL}/pulses/subscribed`, {
      headers: {
        'X-OTX-API-KEY': OTX_API_KEY,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });

    if (!response.ok) {
      throw new Error(`OTX API returned ${response.status}`);
    }

    const data = await response.json();

    // Transform OTX data to our format
    const threats = [];
    const arcs = [];

    // Process pulses (limit to recent 50)
    const pulses = data.results?.slice(0, 50) || [];

    for (const pulse of pulses) {
      if (pulse.indicators?.length > 0) {
        // Extract IP indicators
        const ipIndicators = pulse.indicators.filter(ind => ind.type === 'IPv4' || ind.type === 'IPv6');

        for (const indicator of ipIndicators.slice(0, 3)) { // Limit IPs per pulse
          threats.push({
            id: indicator.id || `otx-${Date.now()}-${Math.random()}`,
            name: pulse.name || 'Unknown Threat',
            type: pulse.tags?.[0] || 'Unknown',
            severity: pulse.TLP || 'medium',
            ip: indicator.indicator,
            description: pulse.description || 'No description available',
            created: pulse.created
          });
        }
      }
    }

    // Generate arcs between threats (visualization)
    for (let i = 0; i < threats.length - 1 && i < 20; i++) {
      arcs.push({
        source: threats[i].ip,
        target: threats[i + 1].ip,
        label: `${threats[i].name} → ${threats[i + 1].name}`.substring(0, 50)
      });
    }

    return {
      success: true,
      source: 'otx',
      message: 'Real OTX data retrieved',
      threats: threats.slice(0, 30), // Limit to 30 threats
      arcs: arcs.slice(0, 20), // Limit to 20 arcs
      count: threats.length
    };

  } catch (error) {
    console.error('[OTX Proxy] Failed to fetch real OTX data:', error.message);
    console.warn('[OTX Proxy] Falling back to mock data');
    return generateMockOTXData();
  }
}

/**
 * GET /api/otx-proxy
 * Proxy OTX threat intelligence data through backend
 */
export const getOTXData = async (req, res) => {
  try {
    // Check Redis cache first
    try {
      const cachedData = await redisClient.get(OTX_CACHE_KEY);
      if (cachedData) {
        console.log('✅ [THREAT INTELLIGENCE] Cache HIT - Data fetched from Redis (15 min cache)');
        res.setHeader('X-Cache', 'HIT');
        const parsed = JSON.parse(cachedData);
        return res.status(200).json(
          new ApiResponse(200, { ...parsed, cached: true }, "OTX data retrieved from cache")
        );
      }
      console.log('❌ [THREAT INTELLIGENCE] Cache MISS - Fetching from OTX API...');
      res.setHeader('X-Cache', 'MISS');
    } catch (cacheError) {
      console.warn('⚠️ [THREAT INTELLIGENCE] Redis cache check failed, continuing without cache');
    }

    // Fetch fresh OTX data
    console.log('[OTX Proxy] Fetching fresh OTX data...');
    const otxData = await fetchOTXData();

    // Set Redis cache
    try {
      await redisClient.set(OTX_CACHE_KEY, JSON.stringify(otxData), {
        EX: CACHE_TTL,
        NX: true
      });
      console.log('💾 [THREAT INTELLIGENCE] Data cached in Redis for 15 minutes');
      console.log('   Threats cached:', otxData.count || otxData.threats?.length || 0);
    } catch (cacheError) {
      console.warn('⚠️ [THREAT INTELLIGENCE] Redis cache set failed, continuing without cache');
    }

    return res.status(200).json(
      new ApiResponse(200, otxData, "OTX data retrieved successfully")
    );

  } catch (error) {
    console.error('[OTX Proxy] Error:', error);

    if (error instanceof ApiError) {
      return res.status(error.statusCode).json(
        new ApiResponse(error.statusCode, null, error.message)
      );
    }

    // Fallback to mock data on error
    const mockData = generateMockOTXData();
    return res.status(200).json(
      new ApiResponse(200, mockData, "OTX service unavailable, returning mock data")
    );
  }
};

/**
 * POST /api/otx-proxy/clear-cache
 * Clear OTX cache
 */
export const clearOTXCache = async (req, res) => {
  try {
    await redisClient.del(OTX_CACHE_KEY);

    console.log('🗑️ [THREAT INTELLIGENCE] Redis cache cleared');

    return res.status(200).json(
      new ApiResponse(200, { cleared: true }, "OTX cache cleared successfully")
    );

  } catch (error) {
    console.error('[OTX Proxy] Cache clear error:', error);

    return res.status(500).json(
      new ApiResponse(500, null, "Failed to clear OTX cache")
    );
  }
};
