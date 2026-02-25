import { ApiResponse } from '../utils/ApiResponse.js';
import { ApiError } from '../utils/ApiError.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { getRulesService, getRuleFilesService, getRuleGroupsService, getRuleFileContentService, saveRuleFileService, deleteRuleFileService } from '../services/wazuhService.js';
import redisClient from '../config/redisClient.js';

const CACHE_TTL = 900; // 15 minutes

/**
 * GET /wazuh/rules
 * Fetch Wazuh rules with optional filters:
 *   ?rule_ids=1002,1003  - filter by specific IDs (comma-separated)
 *   ?level=8             - filter by minimum level (0-16)
 *   ?group=web           - filter by rule group
 *   ?filename=0020-syslog_rules.xml - filter by file
 *   ?status=enabled|disabled|all
 *   ?search=ssh          - text search
 *   ?offset=0&limit=500  - pagination
 */
export const getRules = asyncHandler(async (req, res) => {
  const wazuhCreds = req.clientCreds?.wazuhCredentials;
  const organizationId = req.clientCreds?.organizationId;

  if (!wazuhCreds) {
    throw new ApiError(400, 'Wazuh credentials not found for this client');
  }

  const { rule_ids, level, group, filename, status, search, offset = 0, limit = 500 } = req.query;

  const cacheKey = `rules:${organizationId}:${rule_ids || ''}:${level || ''}:${group || ''}:${filename || ''}:${status || ''}:${search || ''}:${offset}:${limit}`;

  try {
    const cached = await redisClient.get(cacheKey);
    if (cached) {
      console.log('[RULES] Cache HIT');
      res.setHeader('X-Cache', 'HIT');
      return res.status(200).json(new ApiResponse(200, JSON.parse(cached), 'Rules fetched successfully'));
    }
    console.log(' [RULES] Cache MISS - fetching from Wazuh API...');
    res.setHeader('X-Cache', 'MISS');
  } catch {
    console.warn(' [RULES] Redis unavailable, continuing without cache');
  }

  const data = await getRulesService(wazuhCreds, { rule_ids, level, group, filename, status, search, offset, limit });

  try {
    await redisClient.setEx(cacheKey, CACHE_TTL, JSON.stringify(data));
  } catch {
    console.warn(' [RULES] Failed to set cache');
  }

  return res.status(200).json(new ApiResponse(200, data, 'Rules fetched successfully'));
});

/**
 * GET /wazuh/rules/files
 * List rule XML files on the Wazuh manager
 *   ?offset=0&limit=500&search=syslog&status=enabled&filename=0020*
 */
export const getRuleFiles = asyncHandler(async (req, res) => {
  const wazuhCreds = req.clientCreds?.wazuhCredentials;
  const organizationId = req.clientCreds?.organizationId;

  if (!wazuhCreds) {
    throw new ApiError(400, 'Wazuh credentials not found for this client');
  }

  const { offset = 0, limit = 500, search, status, filename } = req.query;

  const cacheKey = `rules_files:${organizationId}:${offset}:${limit}:${search || ''}:${status || ''}:${filename || ''}`;

  try {
    const cached = await redisClient.get(cacheKey);
    if (cached) {
      console.log(' [RULES FILES] Cache HIT');
      res.setHeader('X-Cache', 'HIT');
      return res.status(200).json(new ApiResponse(200, JSON.parse(cached), 'Rule files fetched successfully'));
    }
    console.log(' [RULES FILES] Cache MISS - fetching from API...');
    res.setHeader('X-Cache', 'MISS');
  } catch {
    console.warn(' [RULES FILES] Redis unavailable, continuing without cache');
  }

  const data = await getRuleFilesService(wazuhCreds, { offset, limit, search, status, filename });

  try {
    await redisClient.setEx(cacheKey, CACHE_TTL, JSON.stringify(data));
  } catch {
    console.warn(' [RULES FILES] Failed to set cache');
  }

  return res.status(200).json(new ApiResponse(200, data, 'Rule files fetched successfully'));
});

/**
 * GET /wazuh/rules/groups
 * List all rule groups available on the Wazuh manager
 *   ?offset=0&limit=500&search=web
 */
export const getRuleGroups = asyncHandler(async (req, res) => {
  const wazuhCreds = req.clientCreds?.wazuhCredentials;
  const organizationId = req.clientCreds?.organizationId;

  if (!wazuhCreds) {
    throw new ApiError(400, 'Wazuh credentials not found for this client');
  }

  const { offset = 0, limit = 500, search } = req.query;

  const cacheKey = `rules_groups:${organizationId}:${offset}:${limit}:${search || ''}`;

  try {
    const cached = await redisClient.get(cacheKey);
    if (cached) {
      console.log('✅ [RULES GROUPS] Cache HIT');
      res.setHeader('X-Cache', 'HIT');
      return res.status(200).json(new ApiResponse(200, JSON.parse(cached), 'Rule groups fetched successfully'));
    }
    console.log('❌ [RULES GROUPS] Cache MISS - fetching from Wazuh API...');
    res.setHeader('X-Cache', 'MISS');
  } catch {
    console.warn('⚠️ [RULES GROUPS] Redis unavailable, continuing without cache');
  }

  const data = await getRuleGroupsService(wazuhCreds, { offset, limit, search });

  try {
    await redisClient.setEx(cacheKey, CACHE_TTL, JSON.stringify(data));
  } catch {
    console.warn('⚠️ [RULES GROUPS] Failed to set cache');
  }

  return res.status(200).json(new ApiResponse(200, data, 'Rule groups fetched successfully'));
});

/**
 * GET /wazuh/rules/files/:filename/content
 * Fetch raw XML content of a specific rule file from the Wazuh manager
 */
export const getRuleFileContent = asyncHandler(async (req, res) => {
  const wazuhCreds = req.clientCreds?.wazuhCredentials;
  const organizationId = req.clientCreds?.organizationId;

  if (!wazuhCreds) {
    throw new ApiError(400, 'Wazuh credentials not found for this client');
  }

  const { filename } = req.params;
  if (!filename) {
    throw new ApiError(400, 'Filename is required');
  }

  const cacheKey = `rules_file_content:${organizationId}:${filename}`;

  try {
    const cached = await redisClient.get(cacheKey);
    if (cached) {
      console.log(`✅ [RULE FILE CONTENT] Cache HIT: ${filename}`);
      res.setHeader('X-Cache', 'HIT');
      return res.status(200).json(new ApiResponse(200, { filename, content: cached }, 'Rule file content fetched successfully'));
    }
    console.log(`❌ [RULE FILE CONTENT] Cache MISS: ${filename}`);
    res.setHeader('X-Cache', 'MISS');
  } catch {
    console.warn('⚠️ [RULE FILE CONTENT] Redis unavailable, continuing without cache');
  }

  const xmlContent = await getRuleFileContentService(wazuhCreds, filename);

  try {
    await redisClient.setEx(cacheKey, CACHE_TTL, xmlContent);
  } catch {
    console.warn('⚠️ [RULE FILE CONTENT] Failed to set cache');
  }

  return res.status(200).json(new ApiResponse(200, { filename, content: xmlContent }, 'Rule file content fetched successfully'));
});

/**
 * PUT /wazuh/rules/files/:filename
 * Create or overwrite a custom rule file on the Wazuh manager.
 * Body (JSON): { "content": "<xml>...</xml>" }
 */
export const saveRuleFile = asyncHandler(async (req, res) => {
  const wazuhCreds = req.clientCreds?.wazuhCredentials;

  if (!wazuhCreds) {
    throw new ApiError(400, 'Wazuh credentials not found for this client');
  }

  const { filename } = req.params;
  if (!filename) {
    throw new ApiError(400, 'Filename is required');
  }

  const xmlContent = req.body?.content;
  if (!xmlContent || typeof xmlContent !== 'string') {
    throw new ApiError(400, 'XML content is required in body.content');
  }

  const data = await saveRuleFileService(wazuhCreds, filename, xmlContent);

  // Bust all rules-related caches so the next fetch gets fresh data from Wazuh
  try {
    const organizationId = req.clientCreds?.organizationId;
    const patterns = [
      `rules_file_content:${organizationId}:${filename}`,
      // Use KEYS for pattern matching (DEL does not support globs)
    ];
    await redisClient.del(patterns);

    // Bust rules list, files list, and groups caches
    for (const prefix of ['rules', 'rules_files', 'rules_groups']) {
      const keys = await redisClient.keys(`${prefix}:${organizationId}:*`);
      if (keys.length > 0) await redisClient.del(keys);
    }
  } catch { /* cache bust is best-effort */ }

  return res.status(200).json(new ApiResponse(200, data, 'Rule file saved successfully'));
});

/**
 * DELETE /wazuh/rules/files/:filename
 * Delete a custom rule file from the Wazuh manager.
 */
export const deleteRuleFile = asyncHandler(async (req, res) => {
  const wazuhCreds = req.clientCreds?.wazuhCredentials;

  if (!wazuhCreds) {
    throw new ApiError(400, 'Wazuh credentials not found for this client');
  }

  const { filename } = req.params;
  if (!filename) {
    throw new ApiError(400, 'Filename is required');
  }

  const data = await deleteRuleFileService(wazuhCreds, filename);

  try {
    const organizationId = req.clientCreds?.organizationId;
    await redisClient.del(`rules_file_content:${organizationId}:${filename}`);
    for (const prefix of ['rules', 'rules_files', 'rules_groups']) {
      const keys = await redisClient.keys(`${prefix}:${organizationId}:*`);
      if (keys.length > 0) await redisClient.del(keys);
    }
  } catch { /* cache bust is best-effort */ }

  return res.status(200).json(new ApiResponse(200, data, 'Rule file deleted successfully'));
});
