import express from 'express';
import {
  createSop,
  getAllSops,
  getSopById,
  updateSop,
  deleteSop,
  generateSopReport,
  downloadSopReport
} from '../controllers/sop.controller.js';
import { authenticateToken } from '../middlewares/auth.middleware.js';
import { authorizePermissions } from '../middlewares/authorization.middleware.js';

const router = express.Router();

router.use(authenticateToken);

// CRUD Routes
router.post('/', authorizePermissions(['sops:create']), createSop);
router.get('/', authorizePermissions(['sops:read']), getAllSops);
router.get('/:id', authorizePermissions(['sops:read']), getSopById);
router.put('/:id', authorizePermissions(['sops:update']), updateSop);
router.delete('/:id', authorizePermissions(['sops:delete']), deleteSop);

// Report Generation & Download
router.post('/:id/generate-report', authorizePermissions(['sops:create']), generateSopReport);
router.get('/:id/download', authorizePermissions(['sops:read']), downloadSopReport);

export default router;
