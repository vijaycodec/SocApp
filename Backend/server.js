import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import https from "https";
import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import database from "./config/database.js";
import redisClient from "./config/redisClient.js";
import routes from "./routes/index.js";
import {
  globalErrorHandler,
  notFoundHandler,
} from "./middlewares/errorHandler.middleware.js";
import redis from "redis";

// ES modules don't have __dirname, so we need to create it
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const ENABLE_HTTPS = process.env.ENABLE_HTTPS === 'true';
const NODE_ENV = process.env.NODE_ENV || 'development';

// PATCH 52: Disable X-Powered-By header (CWE-200 Fix)
// Remove backend technology disclosure
app.disable('x-powered-by');

// SECURITY: Trust proxy - backend is behind OpenLiteSpeed reverse proxy
app.set('trust proxy', 1);

// Security Middleware
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// PATCH 46: Configure X-XSS-Protection for audit compliance (CWE-693)
// Modern helmet sets X-XSS-Protection: 0 because the header is deprecated and
// can introduce vulnerabilities. However, for security audit compliance, we
// override it to 1; mode=block as recommended by the auditor.
// Note: Modern browsers ignore this header. CSP is the modern replacement.
app.use((req, res, next) => {
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// PATCH 17: Environment-specific CORS configuration
// Production: HTTPS only | Development: HTTP allowed for localhost
const allowedOrigins = NODE_ENV === 'production'
  ? [
      // Production: HTTPS only
      process.env.CORS_ORIGIN,
      "https://localhost:3000",
      "https://localhost:3001",
    ].filter(Boolean)
  : [
      // Development: Allow HTTP for localhost
      "http://localhost:3000",
      "http://localhost:3001",
      "http://localhost:3333",
      "http://127.0.0.1:3000",
      "http://127.0.0.1:3001",
      "http://127.0.0.1:3333",
      "http://[::1]:3000",
      "http://[::1]:3001",
      process.env.CORS_ORIGIN
    ].filter(Boolean);

const corsOptions = {
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps, Postman, curl)
    if (!origin) {
      return callback(null, true);
    }

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      const msg = 'CORS policy: Access from the specified origin is not allowed.';
      console.warn(`🚫 CORS blocked request from: ${origin}`);
      callback(new Error(msg), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-CSRF-Token',
    'Accept',
    'Cache-Control',
    'Pragma',
    'Expires',
    'If-None-Match',
    'If-Modified-Since'
  ],
  exposedHeaders: ['X-CSRF-Token', 'Content-Type', 'Cache-Control'],
  maxAge: 86400, // Cache preflight requests for 24 hours
  optionsSuccessStatus: 200,
  preflightContinue: false
};

app.use(cors(corsOptions));

// Request Parsing
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Logging
if (process.env.NODE_ENV !== "test") {
  app.use(morgan("combined"));
}

// Explicit OPTIONS handler for all routes
app.options('*', cors(corsOptions));

// API Routes
app.use("/api", routes);

// Health Check
app.get("/health", (req, res) => {
  res.status(200).json({ success: true, message: "Server is healthy" });
});

// Root Endpoint
app.get("/", (req, res) => {
  res.json({ success: true, message: "Welcome to the SOC Dashboard API" });
});

// Error Handling
app.use(notFoundHandler);
app.use(globalErrorHandler);

// Function to start HTTPS server
const startHTTPSServer = async () => {
  try {
    // Load SSL certificate and key
    const sslKeyPath = process.env.SSL_KEY_PATH || path.join(__dirname, 'certs', 'server.key');
    const sslCertPath = process.env.SSL_CERT_PATH || path.join(__dirname, 'certs', 'server.cert');
    const sslCaPath = process.env.SSL_CA_PATH; // Optional CA bundle

    // Check if SSL files exist
    if (!fs.existsSync(sslKeyPath) || !fs.existsSync(sslCertPath)) {
      console.error('❌ SSL certificate files not found!');
      console.error(`   Expected key: ${sslKeyPath}`);
      console.error(`   Expected cert: ${sslCertPath}`);
      console.error('   Falling back to HTTP...');
      console.error('   See SSL_SETUP_GUIDE.md for SSL setup instructions.');
      await startHTTPServer();
      return;
    }

    const httpsOptions = {
      key: fs.readFileSync(sslKeyPath),
      cert: fs.readFileSync(sslCertPath),
      minVersion: 'TLSv1.2', // Enforce minimum TLS 1.2
      maxVersion: 'TLSv1.3', // Allow up to TLS 1.3
      ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
      ...(sslCaPath && fs.existsSync(sslCaPath) && { ca: fs.readFileSync(sslCaPath) })
    };

    await database.connect();

    const httpsServer = https.createServer(httpsOptions, app);

    httpsServer.listen(PORT, '0.0.0.0', () => {
      console.log(`🔒 HTTPS Server is running securely at https://0.0.0.0:${PORT}`);
      console.log(`🌐 Available at https://localhost:${PORT}`);
      console.log(`   Environment: ${NODE_ENV}`);
      console.log(`   SSL Certificate: ${sslCertPath}`);
    });

    httpsServer.on('error', async (error) => {
      console.error('❌ HTTPS Server error:', error.message);
      console.error('   Falling back to HTTP...');
      await startHTTPServer();
    });

  } catch (error) {
    console.error('❌ Failed to start HTTPS server:', error.message);
    console.error('   Falling back to HTTP...');
    await startHTTPServer();
  }
};


// // Redis client setup
// const redisClient = redis.createClient({
//   url: process.env.REDIS_URL 
// });

// redisClient.on('error', (err) => console.error('Redis Client Error', err));

// (async () => {
//   await redisClient.connect();
//   console.log(' Redis connected successfully');
// })();

// Function to start HTTP server (development/fallback)
const startHTTPServer = async () => {
  try {
    // Try to connect to database, but don't fail if it's not available
    try {
      await database.connect();
      console.log('✅ Database connected successfully');
    } catch (dbError) {
      console.error('⚠️  WARNING: Database connection failed:', dbError.message);
      console.error('   Server will start anyway, but database-dependent features will not work.');
      console.error('   Please ensure MongoDB is running at:', process.env.MONGODB_URI);
    }

    const httpServer = http.createServer(app);

    // PATCH 16: Security - Listen on localhost only for production behind reverse proxy
    // Development can use 0.0.0.0 for easier access, production should be 127.0.0.1
    const listenAddress = NODE_ENV === 'production' ? '127.0.0.1' : '0.0.0.0';

    httpServer.listen(PORT, listenAddress, () => {
      if (NODE_ENV === 'production') {
        if (!ENABLE_HTTPS) {
          console.warn('⚠️  WARNING: Running HTTP in production is insecure!');
          console.warn('   Please enable HTTPS by setting ENABLE_HTTPS=true in .env');
          console.warn('   and providing valid SSL certificates.');
          console.warn('   See SSL_SETUP_GUIDE.md for instructions.');
        }
        console.log('🚀 ===================================');
        console.log('🚀 SOC DASHBOARD BACKEND STARTED (PRODUCTION)');
        console.log('🚀 ===================================');
        console.log(`🌐 HTTP Server: http://127.0.0.1:${PORT}`);
        console.log(`🔒 Backend is local-only and accessible via reverse proxy only`);
        console.log(`📍 Environment: ${NODE_ENV}`);
        console.log(`🔐 HTTPS Enabled: ${ENABLE_HTTPS}`);
        console.log('🚀 ===================================');
      } else {
        console.log('🚀 ===================================');
        console.log('🚀 SOC DASHBOARD BACKEND STARTED (DEVELOPMENT)');
        console.log('🚀 ===================================');
        console.log(`🌐 HTTP Server: http://0.0.0.0:${PORT}`);
        console.log(`🌐 Local Access: http://localhost:${PORT}`);
        console.log(`📍 Environment: ${NODE_ENV}`);
        console.log(`🔐 HTTPS Enabled: ${ENABLE_HTTPS}`);
        console.log(`🌍 CORS Origins: localhost:3000, ${process.env.CORS_ORIGIN || 'none'}`);
        console.log('🚀 ===================================');
      }
    });

    httpServer.on('error', (error) => {
      console.error('❌ HTTP Server error:', error.message);
      if (error.code === 'EADDRINUSE') {
        console.error(`   Port ${PORT} is already in use.`);
        console.error('   Please stop the other process or change PORT in .env');
      }
      process.exit(1);
    });

  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
};

// Start the server
const startServer = async () => {
  if (ENABLE_HTTPS && NODE_ENV === 'production') {
    await startHTTPSServer();
  } else {
    await startHTTPServer();
  }
};

startServer();

export default app;
