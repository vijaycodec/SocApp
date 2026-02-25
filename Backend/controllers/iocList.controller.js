import { ApiResponse } from '../utils/ApiResponse.js';
import { ApiError } from '../utils/ApiError.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {
  getCdbListFilesService,
  getCdbListFileContentService,
  saveCdbListFileService,
  deleteCdbListFileService,
} from '../services/wazuhService.js';
import redisClient from '../config/redisClient.js';

const CACHE_TTL = 900; // 15 minutes

/**
 * GET /wazuh/lists/files
 * List all CDB list files on the Wazuh manager
 */
export const getCdbListFiles = asyncHandler(async (req, res) => {
  const wazuhCreds = req.clientCreds?.wazuhCredentials;
  const organizationId = req.clientCreds?.organizationId;

  if (!wazuhCreds) {
    throw new ApiError(400, 'Wazuh credentials not found for this client');
  }

  const { offset = 0, limit = 500, search, filename } = req.query;

  const cacheKey = `ioc_files:${organizationId}:${offset}:${limit}:${search || ''}:${filename || ''}`;

  try {
    const cached = await redisClient.get(cacheKey);
    if (cached) {
      console.log('[IOC FILES] Cache HIT');
      res.setHeader('X-Cache', 'HIT');
      return res.status(200).json(new ApiResponse(200, JSON.parse(cached), 'IOC list files fetched successfully'));
    }
    console.log('[IOC FILES] Cache MISS - fetching from Wazuh API...');
    res.setHeader('X-Cache', 'MISS');
  } catch {
    console.warn('[IOC FILES] Redis unavailable, continuing without cache');
  }

  const data = await getCdbListFilesService(wazuhCreds, { offset, limit, search, filename });

  try {
    await redisClient.setEx(cacheKey, CACHE_TTL, JSON.stringify(data));
  } catch {
    console.warn('[IOC FILES] Failed to set cache');
  }

  return res.status(200).json(new ApiResponse(200, data, 'IOC list files fetched successfully'));
});

/**
 * GET /wazuh/lists/files/:filename/content
 * Fetch raw content of a specific CDB list file
 */
export const getCdbListFileContent = asyncHandler(async (req, res) => {
  const wazuhCreds = req.clientCreds?.wazuhCredentials;
  const organizationId = req.clientCreds?.organizationId;

  if (!wazuhCreds) {
    throw new ApiError(400, 'Wazuh credentials not found for this client');
  }

  const { filename } = req.params;
  if (!filename) {
    throw new ApiError(400, 'Filename is required');
  }

  const cacheKey = `ioc_content:${organizationId}:${filename}`;

  try {
    const cached = await redisClient.get(cacheKey);
    if (cached) {
      console.log(`[IOC CONTENT] Cache HIT: ${filename}`);
      res.setHeader('X-Cache', 'HIT');
      return res.status(200).json(new ApiResponse(200, { filename, content: cached }, 'IOC list content fetched successfully'));
    }
    console.log(`[IOC CONTENT] Cache MISS: ${filename}`);
    res.setHeader('X-Cache', 'MISS');
  } catch {
    console.warn('[IOC CONTENT] Redis unavailable, continuing without cache');
  }

  const content = await getCdbListFileContentService(wazuhCreds, filename);

  try {
    await redisClient.setEx(cacheKey, CACHE_TTL, content);
  } catch {
    console.warn('[IOC CONTENT] Failed to set cache');
  }

  return res.status(200).json(new ApiResponse(200, { filename, content }, 'IOC list content fetched successfully'));
});

/**
 * PUT /wazuh/lists/files/:filename
 * Create or overwrite a CDB list file
 * Body (JSON): { "content": "key1:value1\nkey2:value2" }
 */
export const saveCdbListFile = asyncHandler(async (req, res) => {
  const wazuhCreds = req.clientCreds?.wazuhCredentials;

  if (!wazuhCreds) {
    throw new ApiError(400, 'Wazuh credentials not found for this client');
  }

  const { filename } = req.params;
  if (!filename) {
    throw new ApiError(400, 'Filename is required');
  }

  const content = req.body?.content;
  if (content === undefined || content === null || typeof content !== 'string') {
    throw new ApiError(400, 'Content is required in body.content');
  }

  const data = await saveCdbListFileService(wazuhCreds, filename, content);

  // Bust related caches
  try {
    const organizationId = req.clientCreds?.organizationId;
    await redisClient.del(`ioc_content:${organizationId}:${filename}`);
    const keys = await redisClient.keys(`ioc_files:${organizationId}:*`);
    if (keys.length > 0) await redisClient.del(keys);
  } catch { /* cache bust is best-effort */ }

  return res.status(200).json(new ApiResponse(200, data, 'IOC list saved successfully'));
});

/**
 * DELETE /wazuh/lists/files/:filename
 * Delete a CDB list file from the Wazuh manager
 */
export const deleteCdbListFile = asyncHandler(async (req, res) => {
  const wazuhCreds = req.clientCreds?.wazuhCredentials;

  if (!wazuhCreds) {
    throw new ApiError(400, 'Wazuh credentials not found for this client');
  }

  const { filename } = req.params;
  if (!filename) {
    throw new ApiError(400, 'Filename is required');
  }

  const data = await deleteCdbListFileService(wazuhCreds, filename);

  try {
    const organizationId = req.clientCreds?.organizationId;
    await redisClient.del(`ioc_content:${organizationId}:${filename}`);
    const keys = await redisClient.keys(`ioc_files:${organizationId}:*`);
    if (keys.length > 0) await redisClient.del(keys);
  } catch { /* cache bust is best-effort */ }

  return res.status(200).json(new ApiResponse(200, data, 'IOC list deleted successfully'));
});
