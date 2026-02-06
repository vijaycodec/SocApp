import { ApiResponse } from '../utils/ApiResponse.js';
import { ApiError } from '../utils/ApiError.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import puppeteer from 'puppeteer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import Sop from '../models/sop.model.js';
import { generateSopHtmlReport } from '../templates/sopReportTemplate.html.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create SOP
const createSop = asyncHandler(async (req, res) => {
  const { sop_name, title, description, status } = req.body;
  const userId = req.user?._id || req.user?.id;

  if (!sop_name || !title || !description) {
    throw new ApiError(400, "SOP name, title, and description are required");
  }

  const sopDoc = new Sop({
    sop_name,
    title,
    description,
    status: status || 'draft',
    created_by: userId
  });

  await sopDoc.save();
  await sopDoc.populate('created_by', 'username full_name email');

  return res.status(201).json(
    new ApiResponse(201, { sop: sopDoc }, "SOP created successfully")
  );
});

// Get all SOPs (List)
const getAllSops = asyncHandler(async (req, res) => {
  const sops = await Sop.findActive()
    .populate('created_by', 'username full_name email')
    .populate('updated_by', 'username full_name email')
    .sort({ createdAt: -1 });

  return res.status(200).json(
    new ApiResponse(200, { sops, total: sops.length }, "SOPs fetched successfully")
  );
});

// Get single SOP (Show)
const getSopById = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const sop = await Sop.findById(id)
    .populate('created_by', 'username full_name email')
    .populate('updated_by', 'username full_name email');

  if (!sop || sop.is_deleted) {
    throw new ApiError(404, "SOP not found");
  }

  return res.status(200).json(
    new ApiResponse(200, { sop }, "SOP fetched successfully")
  );
});

// Update SOP (Edit)
const updateSop = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { sop_name, title, description, status } = req.body;
  const userId = req.user?._id || req.user?.id;

  const sop = await Sop.findById(id);

  if (!sop || sop.is_deleted) {
    throw new ApiError(404, "SOP not found");
  }

  if (sop_name) sop.sop_name = sop_name;
  if (title) sop.title = title;
  if (description) sop.description = description;
  if (status) sop.status = status;
  sop.updated_by = userId;

  await sop.save();
  await sop.populate('created_by', 'username full_name email');
  await sop.populate('updated_by', 'username full_name email');

  return res.status(200).json(
    new ApiResponse(200, { sop }, "SOP updated successfully")
  );
});

// Soft Delete SOP
const deleteSop = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const userId = req.user?._id || req.user?.id;

  const sop = await Sop.findById(id);

  if (!sop) {
    throw new ApiError(404, "SOP not found");
  }

  if (sop.is_deleted) {
    throw new ApiError(410, "SOP has already been deleted");
  }

  await sop.softDelete(userId);

  return res.status(200).json(
    new ApiResponse(200, { id: sop._id }, "SOP deleted successfully")
  );
});

// Generate PDF Report
const generateSopReport = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const sop = await Sop.findById(id)
    .populate('created_by', 'username full_name email');

  if (!sop || sop.is_deleted) {
    throw new ApiError(404, "SOP not found");
  }

  console.log(`Generating PDF report for SOP: ${sop.sop_name}`);

  const htmlReport = generateSopHtmlReport(sop);

  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--no-first-run',
      '--no-zygote',
      '--disable-gpu',
      '--disable-software-rasterizer'
    ],
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined
  });

  const page = await browser.newPage();
  await page.setContent(htmlReport, { waitUntil: 'networkidle0' });

  const pdfBuffer = await page.pdf({
    format: 'A4',
    printBackground: true,
    preferCSSPageSize: true,
    margin: { top: '10mm', right: '10mm', bottom: '10mm', left: '10mm' }
  });

  await browser.close();
  console.log('PDF generated successfully');

  const sanitizedSopName = sop.sop_name.replace(/[^a-zA-Z0-9]/g, '_');
  const timestamp = Date.now();
  const filename = `${sanitizedSopName}_${timestamp}.pdf`;

  const storageDir = path.join(__dirname, '..', 'storage', 'Sops', 'report');
  if (!fs.existsSync(storageDir)) {
    fs.mkdirSync(storageDir, { recursive: true });
    console.log(`Created directory: ${storageDir}`);
  }

  const filePath = path.join(storageDir, filename);
  fs.writeFileSync(filePath, pdfBuffer);
  console.log(`PDF saved to: ${filePath}`);

  const fileStats = fs.statSync(filePath);

  sop.file_path = filePath;
  sop.file_name = filename;
  sop.file_size = fileStats.size;
  sop.report_generated_at = new Date();
  await sop.save();

  return res.status(200).json(
    new ApiResponse(200, {
      sop: {
        _id: sop._id,
        sop_name: sop.sop_name,
        title: sop.title,
        file_name: sop.file_name,
        file_size: sop.file_size,
        report_generated_at: sop.report_generated_at
      }
    }, "Report generated successfully")
  );
});

// Download SOP Report
const downloadSopReport = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const sop = await Sop.findById(id);

  if (!sop || sop.is_deleted) {
    throw new ApiError(404, "SOP not found");
  }

  if (!sop.file_path || !sop.file_name) {
    throw new ApiError(404, "Report has not been generated yet. Please generate the report first.");
  }

  if (!fs.existsSync(sop.file_path)) {
    throw new ApiError(404, "Report file not found on server. Please regenerate the report.");
  }

  console.log(`Downloading SOP report: ${sop.file_name}`);

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${sop.file_name}"`);
  res.setHeader('Cache-Control', 'no-cache');

  res.download(sop.file_path, sop.file_name, (err) => {
    if (err) {
      console.error('Error sending file:', err.message);
      if (!res.headersSent) {
        return res.status(500).json({ success: false, message: "Error sending file" });
      }
    }
  });
});

export {
  createSop,
  getAllSops,
  getSopById,
  updateSop,
  deleteSop,
  generateSopReport,
  downloadSopReport
};
