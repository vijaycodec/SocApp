import { getIpLocation, axiosInstance } from '../services/wazuhExtended.service.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { ApiError } from '../utils/ApiError.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import redisClient from '../config/redisClient.js';

const CACHE_TTL = 900; // 15 minutes in seconds

// Get alerts count (lightweight endpoint)
const getAlertsCount = asyncHandler(async (req, res) => {
  try {
    // Get credentials from client credentials (set by auth middleware)
    const indexerCreds = req.clientCreds?.indexerCredentials;
    const organizationId = req.clientCreds?.organizationId;

    if (!indexerCreds) {
      throw new ApiError(400, "Indexer credentials not found for this client");
    }

    const { host: INDEXER_HOST, username: INDEXER_USER, password: INDEXER_PASS } = indexerCreds;

    // Get time range parameters (hours for relative, or absolute from/to timestamps)
    const { hours, from, to } = req.query;

    // Check cache
    const cacheKey = `alerts_count:${organizationId}:${hours || 'all'}:${from || ''}:${to || ''}`;
    try {
      const cachedData = await redisClient.get(cacheKey);
      if (cachedData) {
        console.log('✅ [ALERTS COUNT] Cache HIT - Data fetched from Redis (15 min cache)');
        console.log('   Cache Key:', cacheKey);
        res.setHeader('X-Cache', 'HIT');
        return res.status(200).json(
          new ApiResponse(200, JSON.parse(cachedData), "Alert count fetched successfully")
        );
      }
      console.log('❌ [ALERTS COUNT] Cache MISS - Fetching from Indexer API...');
      console.log('   Cache Key:', cacheKey);
      res.setHeader('X-Cache', 'MISS');
    } catch (cacheError) {
      console.warn('⚠️ [ALERTS COUNT] Redis cache check failed, continuing without cache');
    }

    const authString = `${INDEXER_USER}:${INDEXER_PASS}`;
    const authEncoded = Buffer.from(authString).toString("base64");

    // Build time filter
    let timeFilter = {};
    if (from && to) {
      // Absolute time range
      timeFilter = {
        gte: from,
        lte: to
      };
    } else if (hours) {
      // Relative time range (e.g., last 24 hours)
      const hoursAgo = parseInt(hours) || 24;
      const now = new Date();
      const startTime = new Date(now.getTime() - hoursAgo * 60 * 60 * 1000);
      timeFilter = {
        gte: startTime.toISOString(),
        lte: now.toISOString()
      };
    }

    // Build query with both severity and time filters
    const queryFilters = [
      {
        range: {
          "rule.level": {
            gte: 8,
          },
        },
      }
    ];

    // Add time filter if provided
    if (Object.keys(timeFilter).length > 0) {
      queryFilters.push({
        range: {
          "@timestamp": timeFilter
        }
      });
    }

    // Count query - only get the count, no documents
    const countQuery = {
      query: {
        bool: {
          must: queryFilters
        }
      },
      size: 0,  // Don't return any documents, just the count
      track_total_hits: true
    };

    const countResponse = await axiosInstance.post(
      `${INDEXER_HOST}/wazuh-alerts*/_search`,
      countQuery,
      {
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Basic ${authEncoded}`,
        },
      }
    );

    const totalCount = countResponse.data.hits?.total?.value || 0;
    const responseData = { count: totalCount };

    // Set cache
    try {
      await redisClient.set(cacheKey, JSON.stringify(responseData), {
        EX: CACHE_TTL,
        NX: true
      });
      console.log('💾 [ALERTS COUNT] Data cached in Redis for 15 minutes');
    } catch (cacheError) {
      console.warn('⚠️ [ALERTS COUNT] Redis cache set failed, continuing without cache');
    }

    return res.status(200).json(
      new ApiResponse(200, responseData, "Alert count fetched successfully")
    );
  } catch (error) {
    console.error("Alerts count route error:", error.message);
    throw new ApiError(500, error.message || "Failed to fetch alert count");
  }
});

// Get alerts
const getAlerts = asyncHandler(async (req, res) => {
  try {
    // Get credentials from client credentials (set by auth middleware)
    const indexerCreds = req.clientCreds?.indexerCredentials;
    const organizationId = req.clientCreds?.organizationId;

    if (!indexerCreds) {
      throw new ApiError(400, "Indexer credentials not found for this client");
    }

    const { host: INDEXER_HOST, username: INDEXER_USER, password: INDEXER_PASS } = indexerCreds;

    // Get time range parameters (hours for relative, or absolute from/to timestamps)
    const { hours } = req.query;
    const timeFrom = req.query.from;
    const timeTo = req.query.to;
    const paginationSize = parseInt(req.query.limit) || 1000;

    // Check cache
    const cacheKey = `alerts:${organizationId}:${hours || 'all'}:${timeFrom || ''}:${timeTo || ''}:${paginationSize}:${req.query.search_after || 'none'}`;
    try {
      const cachedData = await redisClient.get(cacheKey);
      if (cachedData) {
        console.log('✅ [ALERTS] Cache HIT - Data fetched from Redis (15 min cache)');
        console.log('   Cache Key:', cacheKey);
        res.setHeader('X-Cache', 'HIT');
        return res.status(200).json(
          new ApiResponse(200, JSON.parse(cachedData), "Alerts fetched successfully")
        );
      }
      console.log('❌ [ALERTS] Cache MISS - Fetching from Indexer API...');
      console.log('   Cache Key:', cacheKey);
      res.setHeader('X-Cache', 'MISS');
    } catch (cacheError) {
      console.warn('⚠️ [ALERTS] Redis cache check failed, continuing without cache');
    }

    const authString = `${INDEXER_USER}:${INDEXER_PASS}`;
    const authEncoded = Buffer.from(authString).toString("base64");

    // Build time filter
    let timeFilter = {};
    if (timeFrom && timeTo) {
      // Absolute time range
      timeFilter = {
        gte: timeFrom,
        lte: timeTo
      };
    } else if (hours) {
      // Relative time range (e.g., last 24 hours)
      const hoursAgo = parseInt(hours) || 24;
      const now = new Date();
      const startTime = new Date(now.getTime() - hoursAgo * 60 * 60 * 1000);
      timeFilter = {
        gte: startTime.toISOString(),
        lte: now.toISOString()
      };
    }

    // Build query with both severity and time filters
    const queryFilters = [
      {
        range: {
          "rule.level": {
            gte: 8,
          },
        },
      }
    ];

    // Add time filter if provided
    if (Object.keys(timeFilter).length > 0) {
      queryFilters.push({
        range: {
          "@timestamp": timeFilter
        }
      });
    }

    const searchAfter = req.query.search_after ? JSON.parse(req.query.search_after) : null;

    const alertsQuery = {
      query: {
        bool: {
          must: queryFilters
        }
      },
      // Sort by timestamp DESC and _id for consistent pagination
      sort: [
        { "@timestamp": { order: "desc" } },
        { "_id": { order: "desc" } }
      ],
      size: paginationSize,  // Number of results to return (batch size)
      track_total_hits: true  // Track total hits for pagination
    };

    // Add search_after for deep pagination (avoids 10k limit)
    if (searchAfter) {
      alertsQuery.search_after = searchAfter;
    }

    const alertsResponse = await axiosInstance.post(
      `${INDEXER_HOST}/wazuh-alerts*/_search`,
      alertsQuery,
      {
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Basic ${authEncoded}`,
        },
      }
    );

    const hits = alertsResponse.data.hits?.hits || [];
    const totalCount = alertsResponse.data.hits?.total?.value || 0;

    const alerts = [];
    const processedIPs = new Set();

    for (const hit of hits) {
      const source = hit._source || {};
      const srcip = source.data?.srcip;

      let location = null;
      if (srcip && !processedIPs.has(srcip)) {
        processedIPs.add(srcip);
        try {
          location = await getIpLocation(srcip);
        } catch (error) {
          console.log(`Failed to get location for IP ${srcip}:`, error.message);
        }
      }

      // Return complete alert JSON with all fields
      alerts.push({
        alert_id: hit._id,
        // Include commonly used fields at top level for backward compatibility
        severity: source.rule?.level,
        alert_description: source.rule?.description,
        time: source["@timestamp"],
        host_name: source.predecoder?.hostname,
        agent_name: source.agent?.name,
        agent_id: source.agent?.id,
        rule_groups: (source.rule?.groups || []).join(", "),
        srcip: srcip,
        location: location,
        // Include the complete alert data
        ...source
      });
    }

    // Get sort values from the last hit for search_after pagination
    const lastHit = hits.length > 0 ? hits[hits.length - 1] : null;
    const nextSearchAfter = lastHit?.sort || null;

    const alertsData = {
      alerts,
      total: totalCount,
      limit: paginationSize,
      returned: alerts.length,
      search_after: nextSearchAfter  // For next batch pagination
    };

    // Set cache
    try {
      await redisClient.set(cacheKey, JSON.stringify(alertsData), {
        EX: CACHE_TTL,
        NX: true
      });
      console.log('💾 [ALERTS] Data cached in Redis for 15 minutes');
      console.log('   Total alerts cached:', alertsData.alerts.length);
    } catch (cacheError) {
      console.warn('⚠️ [ALERTS] Redis cache set failed, continuing without cache');
    }

    return res.status(200).json(
      new ApiResponse(200, alertsData, "Alerts fetched successfully")
    );
  } catch (error) {
    console.error("Alerts route error:", error.message);
    throw new ApiError(500, error.message || "Failed to fetch alerts");
  }
});

// Get total events count (all events, no severity filter) - for client dashboard
const getTotalEventsCount = asyncHandler(async (req, res) => {
  try {
    const indexerCreds = req.clientCreds?.indexerCredentials;
    const organizationId = req.clientCreds?.organizationId;

    if (!indexerCreds) {
      throw new ApiError(400, "Indexer credentials not found for this client");
    }

    const { host: INDEXER_HOST, username: INDEXER_USER, password: INDEXER_PASS } = indexerCreds;

    // Get optional time range parameters
    const { hours, from, to } = req.query;

    // Check cache
    const cacheKey = `total_events_count:${organizationId}:${hours || 'all'}:${from || ''}:${to || ''}`;
    try {
      const cachedData = await redisClient.get(cacheKey);
      if (cachedData) {
        console.log('✅ [TOTAL EVENTS COUNT] Cache HIT - Data fetched from Redis (15 min cache)');
        res.setHeader('X-Cache', 'HIT');
        return res.status(200).json(
          new ApiResponse(200, JSON.parse(cachedData), "Total events count fetched successfully")
        );
      }
      console.log('❌ [TOTAL EVENTS COUNT] Cache MISS - Fetching from Indexer API...');
      res.setHeader('X-Cache', 'MISS');
    } catch (cacheError) {
      console.warn('⚠️ [TOTAL EVENTS COUNT] Redis cache check failed, continuing without cache');
    }

    const authString = `${INDEXER_USER}:${INDEXER_PASS}`;
    const authEncoded = Buffer.from(authString).toString("base64");

    // Build query - match_all or with time filter
    let query = { match_all: {} };

    // Add time filter if provided
    if (from && to) {
      query = {
        range: {
          "@timestamp": {
            gte: from,
            lte: to
          }
        }
      };
    } else if (hours) {
      const hoursAgo = parseInt(hours) || 24;
      const now = new Date();
      const startTime = new Date(now.getTime() - hoursAgo * 60 * 60 * 1000);
      query = {
        range: {
          "@timestamp": {
            gte: startTime.toISOString(),
            lte: now.toISOString()
          }
        }
      };
    }

    // Use _count endpoint for efficiency
    const countResponse = await axiosInstance.post(
      `${INDEXER_HOST}/wazuh-alerts-*/_count`,
      { query },
      {
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Basic ${authEncoded}`,
        },
      }
    );

    const totalCount = countResponse.data.count || 0;
    const responseData = { count: totalCount };

    // Set cache
    try {
      await redisClient.set(cacheKey, JSON.stringify(responseData), {
        EX: CACHE_TTL,
        NX: true
      });
      console.log('💾 [TOTAL EVENTS COUNT] Data cached in Redis for 15 minutes');
    } catch (cacheError) {
      console.warn('⚠️ [TOTAL EVENTS COUNT] Redis cache set failed, continuing without cache');
    }

    return res.status(200).json(
      new ApiResponse(200, responseData, "Total events count fetched successfully")
    );
  } catch (error) {
    console.error("Total events count route error:", error.message);
    throw new ApiError(500, error.message || "Failed to fetch total events count");
  }
});

// Get total logs count (from wazuh-archives-*) - for client dashboard
const getTotalLogsCount = asyncHandler(async (req, res) => {
  try {
    const indexerCreds = req.clientCreds?.indexerCredentials;
    const organizationId = req.clientCreds?.organizationId;

    if (!indexerCreds) {
      throw new ApiError(400, "Indexer credentials not found for this client");
    }

    const { host: INDEXER_HOST, username: INDEXER_USER, password: INDEXER_PASS } = indexerCreds;

    // Get optional time range parameters
    const { hours, from, to } = req.query;

    // Check cache
    const cacheKey = `total_logs_count:${organizationId}:${hours || 'all'}:${from || ''}:${to || ''}`;
    try {
      const cachedData = await redisClient.get(cacheKey);
      if (cachedData) {
        console.log('✅ [TOTAL LOGS COUNT] Cache HIT - Data fetched from Redis (15 min cache)');
        res.setHeader('X-Cache', 'HIT');
        return res.status(200).json(
          new ApiResponse(200, JSON.parse(cachedData), "Total logs count fetched successfully")
        );
      }
      console.log('❌ [TOTAL LOGS COUNT] Cache MISS - Fetching from Indexer API...');
      res.setHeader('X-Cache', 'MISS');
    } catch (cacheError) {
      console.warn('⚠️ [TOTAL LOGS COUNT] Redis cache check failed, continuing without cache');
    }

    const authString = `${INDEXER_USER}:${INDEXER_PASS}`;
    const authEncoded = Buffer.from(authString).toString("base64");

    // Build query - match_all or with time filter
    let query = { match_all: {} };

    // Add time filter if provided
    if (from && to) {
      query = {
        range: {
          "@timestamp": {
            gte: from,
            lte: to
          }
        }
      };
    } else if (hours) {
      const hoursAgo = parseInt(hours) || 24;
      const now = new Date();
      const startTime = new Date(now.getTime() - hoursAgo * 60 * 60 * 1000);
      query = {
        range: {
          "@timestamp": {
            gte: startTime.toISOString(),
            lte: now.toISOString()
          }
        }
      };
    }

    // Use _count endpoint for wazuh-archives-* index
    const countResponse = await axiosInstance.post(
      `${INDEXER_HOST}/wazuh-archives-*/_count`,
      { query },
      {
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Basic ${authEncoded}`,
        },
      }
    );

    const totalCount = countResponse.data.count || 0;
    const responseData = { count: totalCount };

    // Set cache
    try {
      await redisClient.set(cacheKey, JSON.stringify(responseData), {
        EX: CACHE_TTL,
        NX: true
      });
      console.log('💾 [TOTAL LOGS COUNT] Data cached in Redis for 15 minutes');
    } catch (cacheError) {
      console.warn('⚠️ [TOTAL LOGS COUNT] Redis cache set failed, continuing without cache');
    }

    return res.status(200).json(
      new ApiResponse(200, responseData, "Total logs count fetched successfully")
    );
  } catch (error) {
    console.error("Total logs count route error:", error.message);
    throw new ApiError(500, error.message || "Failed to fetch total logs count");
  }
});

// Get events count by agent (machine-wise) - for client dashboard
const getEventsCountByAgent = asyncHandler(async (req, res) => {
  try {
    const indexerCreds = req.clientCreds?.indexerCredentials;
    const organizationId = req.clientCreds?.organizationId;

    if (!indexerCreds) {
      throw new ApiError(400, "Indexer credentials not found for this client");
    }

    const { host: INDEXER_HOST, username: INDEXER_USER, password: INDEXER_PASS } = indexerCreds;

    // Get optional time range parameters
    const { hours, from, to, limit = 100 } = req.query;

    // Check cache
    const cacheKey = `events_count_by_agent:${organizationId}:${hours || 'all'}:${from || ''}:${to || ''}:${limit}`;
    try {
      const cachedData = await redisClient.get(cacheKey);
      if (cachedData) {
        console.log('✅ [EVENTS BY AGENT] Cache HIT - Data fetched from Redis (15 min cache)');
        res.setHeader('X-Cache', 'HIT');
        return res.status(200).json(
          new ApiResponse(200, JSON.parse(cachedData), "Events count by agent fetched successfully")
        );
      }
      console.log('❌ [EVENTS BY AGENT] Cache MISS - Fetching from Indexer API...');
      res.setHeader('X-Cache', 'MISS');
    } catch (cacheError) {
      console.warn('⚠️ [EVENTS BY AGENT] Redis cache check failed, continuing without cache');
    }

    const authString = `${INDEXER_USER}:${INDEXER_PASS}`;
    const authEncoded = Buffer.from(authString).toString("base64");

    // Build time filter
    let timeFilter = null;
    if (from && to) {
      timeFilter = {
        range: {
          "@timestamp": {
            gte: from,
            lte: to
          }
        }
      };
    } else if (hours) {
      const hoursAgo = parseInt(hours) || 24;
      const now = new Date();
      const startTime = new Date(now.getTime() - hoursAgo * 60 * 60 * 1000);
      timeFilter = {
        range: {
          "@timestamp": {
            gte: startTime.toISOString(),
            lte: now.toISOString()
          }
        }
      };
    }

    // Build aggregation query
    const aggQuery = {
      size: 0,
      query: timeFilter ? timeFilter : { match_all: {} },
      aggs: {
        events_per_agent: {
          terms: {
            field: "agent.id",
            size: parseInt(limit) || 100
          },
          aggs: {
            agent_name: {
              terms: {
                field: "agent.name",
                size: 1
              }
            },
            agent_ip: {
              terms: {
                field: "agent.ip",
                size: 1
              }
            }
          }
        }
      }
    };

    const aggResponse = await axiosInstance.post(
      `${INDEXER_HOST}/wazuh-alerts-*/_search`,
      aggQuery,
      {
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Basic ${authEncoded}`,
        },
      }
    );

    // Parse aggregation results
    const buckets = aggResponse.data.aggregations?.events_per_agent?.buckets || [];
    const agentEvents = buckets.map(bucket => ({
      agent_id: bucket.key,
      agent_name: bucket.agent_name?.buckets?.[0]?.key || 'Unknown',
      agent_ip: bucket.agent_ip?.buckets?.[0]?.key || 'N/A',
      event_count: bucket.doc_count
    }));

    const responseData = {
      agents: agentEvents,
      total_agents: agentEvents.length,
      total_events: agentEvents.reduce((sum, agent) => sum + agent.event_count, 0)
    };

    // Set cache
    try {
      await redisClient.set(cacheKey, JSON.stringify(responseData), {
        EX: CACHE_TTL,
        NX: true
      });
      console.log('💾 [EVENTS BY AGENT] Data cached in Redis for 15 minutes');
    } catch (cacheError) {
      console.warn('⚠️ [EVENTS BY AGENT] Redis cache set failed, continuing without cache');
    }

    return res.status(200).json(
      new ApiResponse(200, responseData, "Events count by agent fetched successfully")
    );
  } catch (error) {
    console.error("Events count by agent route error:", error.message);
    throw new ApiError(500, error.message || "Failed to fetch events count by agent");
  }
});

export {
  getAlerts,
  getAlertsCount,
  getTotalEventsCount,
  getTotalLogsCount,
  getEventsCountByAgent
};