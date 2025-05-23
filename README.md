Comprehensive Development Guide: Yatri GPS Employee Tracking Backend
Introduction
This document serves as the comprehensive development guide for the backend system of the Yatri Mobile GPS-based Employee Tracking and Management System. It details the system architecture, database design, API specifications, implementation guidelines, and a stagewise development plan, drawing inspiration from the structure of the Flying Chital Logistics Management System and adhering to the specific requirements outlined in the provided documents and UI mockups. The primary goal is to provide a complete blueprint for developers to build a robust, scalable, and maintainable backend using Node.js and PostgreSQL, specifically employing a direct SQL query approach (poolQuery) instead of an ORM.
This guide covers:
Backend Codebase Structure: Defines the organization of directories and files.
Database Schema Design: Outlines the tables, columns, relationships, and constraints.
PoolQuery Implementation: Explains the non-ORM approach for database interactions.
UI to API Mapping: Connects provided UI screens to specific backend API endpoints.
API Documentation: Details every API endpoint, including request/response formats and purpose.
Stagewise Development Plan: Breaks down the entire development process into manageable stages and tasks.
Backend Codebase Structure for Yatri Mobile GPS Employee Tracking System
This document outlines the backend codebase structure for the Yatri Mobile GPS-based employee tracking system, inspired by the Flying Chital Logistics Management System architecture but adapted for the specific requirements of this project.
Directory Structure Overview
/yatri-tracking-backend/
├── .env                      # Environment configuration variables
├── .eslintrc.js              # ESLint configuration for code quality
├── .gitignore                # Git ignore rules
├── package.json              # Project metadata and dependencies
├── README.md                 # Project documentation
├── logs/                     # Application logs directory
│   ├── combined.log          # Combined application logs
│   └── error.log             # Error-specific logs
└── src/                      # Source code directory
    ├── app.js                # Express application setup
    ├── server.js             # Server initialization
    ├── config/               # Configuration files
    │   ├── index.js          # Central configuration exports
    │   ├── database.js       # Database connection configuration
    │   ├── logger.js         # Logging configuration
    │   └── constants.js      # Application constants
    ├── middlewares/          # Request middleware
    │   ├── auth.middleware.js        # Authentication middleware
    │   ├── error.middleware.js       # Error handling middleware
    │   ├── validation.middleware.js  # Request validation middleware
    │   └── logger.middleware.js      # Request logging middleware
    ├── utils/                # Utility functions
    │   ├── database.js       # Database utility functions (poolQuery)
    │   ├── geofence.js       # Geofence calculation utilities
    │   ├── logger.js         # Logging utility
    │   ├── response.js       # Response formatting utility
    │   ├── jwt.js            # JWT token utilities
    │   ├── validation.js     # Input validation utilities
    │   └── helpers.js        # General helper functions
    ├── routes/               # API route definitions
    │   ├── index.js          # Route aggregation and export
    │   ├── auth.routes.js    # Authentication routes
    │   ├── users.routes.js   # User management routes
    │   ├── attendance.routes.js      # Attendance routes
    │   ├── geofence.routes.js        # Geofence routes
    │   ├── checkpoint.routes.js      # Checkpoint routes
    │   ├── patrol.routes.js          # Patrol routes
    │   ├── task.routes.js            # Task management routes
    │   ├── alert.routes.js           # Alert routes
    │   ├── report.routes.js          # Report routes
    │   └── admin.routes.js           # Admin routes
    ├── controllers/          # API route controllers
    │   ├── auth.controller.js        # Authentication controller
    │   ├── user.controller.js        # User management controller
    │   ├── attendance.controller.js  # Attendance controller
    │   ├── geofence.controller.js    # Geofence controller
    │   ├── checkpoint.controller.js  # Checkpoint controller
    │   ├── patrol.controller.js      # Patrol controller
    │   ├── task.controller.js        # Task management controller
    │   ├── alert.controller.js       # Alert controller
    │   ├── report.controller.js      # Report controller
    │   └── admin.controller.js       # Admin controller
    ├── models/               # Data models and database operations
    │   ├── auth.model.js            # Authentication model
    │   ├── user.model.js            # User model
    │   ├── organization.model.js    # Organization model
    │   ├── department.model.js      # Department model
    │   ├── role.model.js            # Role model
    │   ├── site.model.js            # Site model
    │   ├── shift.model.js           # Shift model
    │   ├── attendance.model.js      # Attendance model
    │   ├── geofence.model.js        # Geofence model
    │   ├── checkpoint.model.js      # Checkpoint model
    │   ├── patrol.model.js          # Patrol model
    │   ├── task.model.js            # Task model
    │   ├── alert.model.js           # Alert model
    │   └── report.model.js          # Report model
    ├── services/             # Business logic services
    │   ├── auth.service.js          # Authentication service
    │   ├── user.service.js          # User management service
    │   ├── attendance.service.js    # Attendance service
    │   ├── geofence.service.js      # Geofence service
    │   ├── location.service.js      # Location tracking service
    │   ├── checkpoint.service.js    # Checkpoint service
    │   ├── patrol.service.js        # Patrol service
    │   ├── task.service.js          # Task management service
    │   ├── alert.service.js         # Alert service
    │   ├── notification.service.js  # Notification service
    │   ├── report.service.js        # Report service
    │   └── admin.service.js         # Admin service
    ├── database/             # Database management
    │   ├── tables.js               # Table names and field definitions
    │   ├── queries/               # SQL query templates
    │   │   ├── auth.queries.js     # Authentication queries
    │   │   ├── user.queries.js     # User queries
    │   │   ├── attendance.queries.js # Attendance queries
    │   │   └── ...                 # Other module queries
    │   └── migrations/            # Database migration files
    └── integrations/         # External integrations
        ├── firebase.js            # Firebase integration (FCM)
        ├── sms.js                 # SMS gateway integration
        ├── email.js               # Email service integration
        └── storage.js             # File storage integration
Core Components
1. Database Utilities (Non-ORM Approach)
Following the Flying Chital approach, we'll use a direct poolQuery pattern instead of an ORM. This will be implemented in utils/database.js:
javascript
// src/utils/database.js
const { Pool } = require('pg');
const config = require('../config');
const logger = require('./logger');

const pool = new Pool({
  user: config.database.user,
  host: config.database.host,
  database: config.database.name,
  password: config.database.password,
  port: config.database.port,
  ssl: config.database.ssl ? { rejectUnauthorized: false } : false
});

// Log database connection events
pool.on('connect', () => {
  logger.info('Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  logger.error('PostgreSQL pool error:', err);
});

// The poolQuery utility function
const poolQuery = {
  query: (text, params) => {
    logger.debug('Executing query:', { text, params });
    return pool.query(text, params)
      .then(res => {
        logger.debug('Query result:', { rowCount: res.rowCount });
        return res;
      })
      .catch(err => {
        logger.error('Query error:', err);
        throw err;
      });
  },
  
  // Transaction support
  transaction: async (callback) => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }
};

module.exports = {
  pool,
  poolQuery
};
2. Table Names and Field Definitions
To maintain consistency across the application, we'll define table names and field definitions in a central location:
javascript
// src/database/tables.js
const tableNames = {
  users: {
    name: 'users',
    fields: [
      'id', 'org_id', 'department_id', 'role_id', 'email', 'password',
      'first_name', 'last_name', 'phone', 'profile_image', 'employee_id',
      'status', 'last_login', 'fcm_token', 'settings', 'created_at',
      'updated_at', 'deleted_at'
    ]
  },
  organizations: {
    name: 'organizations',
    fields: [
      'id', 'name', 'address', 'contact_person', 'contact_email',
      'contact_phone', 'logo_url', 'settings', 'created_at',
      'updated_at', 'deleted_at'
    ]
  },
  // Define other tables similarly
};

module.exports = tableNames;
3. Model Implementation
Models will handle database operations using the poolQuery approach:
javascript
// src/models/user.model.js
const { poolQuery } = require('../utils/database');
const tableNames = require('../database/tables');
const logger = require('../utils/logger');
const userQueries = require('../database/queries/user.queries');

const getUsers = (filters = {}, pagination = { page: 1, limit: 10 }) =>
  new Promise((resolve, reject) => {
    try {
      let conditionsStatement = [],
        conditionValues = [],
        projections = tableNames.users.fields;
      
      // Build conditions based on filters
      if (filters.orgId) {
        conditionValues.push(filters.orgId);
        conditionsStatement.push(`org_id = $${conditionValues.length}`);
      }
      
      if (filters.departmentId) {
        conditionValues.push(filters.departmentId);
        conditionsStatement.push(`department_id = $${conditionValues.length}`);
      }
      
      if (filters.status) {
        conditionValues.push(filters.status);
        conditionsStatement.push(`status = $${conditionValues.length}`);
      }
      
      // Always exclude deleted records
      conditionsStatement.push(`deleted_at IS NULL`);
      
      // Build pagination
      const offset = (pagination.page - 1) * pagination.limit;
      conditionValues.push(pagination.limit);
      conditionValues.push(offset);
      
      // Build query
      let sqlQuery = `
        SELECT ${projections.join(', ')} 
        FROM ${tableNames.users.name} 
        ${conditionsStatement.length > 0 ? 'WHERE ' + conditionsStatement.join(' AND ') : ''}
        ORDER BY id DESC
        LIMIT $${conditionValues.length - 1} OFFSET $${conditionValues.length}
      `;
      
      // Count query for pagination
      let countQuery = `
        SELECT COUNT(*) as total
        FROM ${tableNames.users.name}
        ${conditionsStatement.length > 0 ? 'WHERE ' + conditionsStatement.join(' AND ') : ''}
      `;
      
      // Execute queries
      Promise.all([
        poolQuery.query(sqlQuery, conditionValues),
        poolQuery.query(countQuery, conditionValues.slice(0, -2))
      ])
        .then(([dataResult, countResult]) => {
          resolve({
            data: dataResult.rows,
            pagination: {
              total: parseInt(countResult.rows[0].total),
              page: pagination.page,
              limit: pagination.limit
            }
          });
        })
        .catch(reject);
    } catch (error) {
      logger.error('Error in getUsers:', error);
      reject(error);
    }
  });

const getUserById = (id, orgId) =>
  new Promise((resolve, reject) => {
    if (!id || !orgId) {
      reject({ message: "id or orgId is missing" });
    }

    let conditionsStatement = [],
      conditionValues = [],
      projections = tableNames.users.fields;

    conditionValues.push(id);
    conditionsStatement.push(`id = $${conditionValues.length}`);
    
    conditionValues.push(orgId);
    conditionsStatement.push(`org_id = $${conditionValues.length}`);
    
    conditionsStatement.push(`deleted_at IS NULL`);

    let sqlQuery = `
      SELECT ${projections.join(', ')} 
      FROM ${tableNames.users.name} 
      WHERE ${conditionsStatement.join(' AND ')}
    `;

    return poolQuery
      .query(sqlQuery, conditionValues)
      .then(({ rows, rowCount }) => {
        if (rows && rows.length > 0) {
          return resolve({ data: rows[0], count: rowCount });
        }
        return reject({ message: "no data found" });
      })
      .catch(reject);
  });

// Additional model functions for CRUD operations
const createUser = (userData, orgId) => {
  // Implementation
};

const updateUser = (id, userData, orgId) => {
  // Implementation
};

const deleteUser = (id, orgId) => {
  // Implementation using soft delete
};

module.exports = {
  getUsers,
  getUserById,
  createUser,
  updateUser,
  deleteUser
};
4. SQL Query Templates
To keep SQL queries organized and maintainable, we'll store them in separate files:
javascript
// src/database/queries/user.queries.js
module.exports = {
  getUserById: `
    SELECT * FROM users 
    WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
  `,
  
  getUserByEmail: `
    SELECT * FROM users 
    WHERE email = $1 AND org_id = $2 AND deleted_at IS NULL
  `,
  
  createUser: `
    INSERT INTO users (
      org_id, department_id, role_id, email, password, first_name, last_name,
      phone, employee_id, status, created_at, updated_at
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW()
    ) RETURNING *
  `,
  
  updateUser: `
    UPDATE users SET
      department_id = COALESCE($3, department_id),
      role_id = COALESCE($4, role_id),
      email = COALESCE($5, email),
      first_name = COALESCE($6, first_name),
      last_name = COALESCE($7, last_name),
      phone = COALESCE($8, phone),
      profile_image = COALESCE($9, profile_image),
      employee_id = COALESCE($10, employee_id),
      status = COALESCE($11, status),
      updated_at = NOW()
    WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
    RETURNING *
  `,
  
  deleteUser: `
    UPDATE users SET
      deleted_at = NOW(),
      updated_at = NOW()
    WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
  `
};
5. Controller Implementation
Controllers will handle HTTP requests and responses:
javascript
// src/controllers/user.controller.js
const userModel = require('../models/user.model');
const { successResponse, errorResponse } = require('../utils/response');
const logger = require('../utils/logger');
const { validateUserCreate, validateUserUpdate } = require('../utils/validation');

const getUsers = async (req, res) => {
  try {
    const { page = 1, limit = 10, departmentId, status } = req.query;
    const orgId = req.user.orgId;
    
    const filters = {
      orgId,
      departmentId: departmentId ? parseInt(departmentId) : undefined,
      status
    };
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit)
    };
    
    const users = await userModel.getUsers(filters, pagination);
    return successResponse(res, users);
  } catch (error) {
    logger.error('Error in getUsers controller:', error);
    return errorResponse(res, error.message);
  }
};

const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    const orgId = req.user.orgId;
    
    const user = await userModel.getUserById(id, orgId);
    return successResponse(res, user);
  } catch (error) {
    logger.error('Error in getUserById controller:', error);
    return errorResponse(res, error.message);
  }
};

const createUser = async (req, res) => {
  try {
    const { body } = req;
    const orgId = req.user.orgId;
    
    // Validate input
    const validationResult = validateUserCreate(body);
    if (!validationResult.valid) {
      return errorResponse(res, validationResult.errors, 400);
    }
    
    const user = await userModel.createUser(body, orgId);
    return successResponse(res, user, 201);
  } catch (error) {
    logger.error('Error in createUser controller:', error);
    return errorResponse(res, error.message);
  }
};

const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { body } = req;
    const orgId = req.user.orgId;
    
    // Validate input
    const validationResult = validateUserUpdate(body);
    if (!validationResult.valid) {
      return errorResponse(res, validationResult.errors, 400);
    }
    
    const user = await userModel.updateUser(id, body, orgId);
    return successResponse(res, user);
  } catch (error) {
    logger.error('Error in updateUser controller:', error);
    return errorResponse(res, error.message);
  }
};

const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    const orgId = req.user.orgId;
    
    await userModel.deleteUser(id, orgId);
    return successResponse(res, { message: 'User deleted successfully' });
  } catch (error) {
    logger.error('Error in deleteUser controller:', error);
    return errorResponse(res, error.message);
  }
};

module.exports = {
  getUsers,
  getUserById,
  createUser,
  updateUser,
  deleteUser
};
6. Route Implementation
Routes will define API endpoints and connect them to controllers:
javascript
// src/routes/user.routes.js
const express = require('express');
const router = express.Router();
const userController = require('../controllers/user.controller');
const authMiddleware = require('../middlewares/auth.middleware');

// Apply authentication middleware to all routes
router.use(authMiddleware.authenticate);

// User routes
router.get('/', authMiddleware.authorize(['admin', 'manager']), userController.getUsers);
router.get('/:id', userController.getUserById);
router.post('/', authMiddleware.authorize(['admin']), userController.createUser);
router.put('/:id', authMiddleware.authorize(['admin']), userController.updateUser);
router.delete('/:id', authMiddleware.authorize(['admin']), userController.deleteUser);

module.exports = router;
7. Service Implementation
Services will contain business logic:
javascript
// src/services/geofence.service.js
const geofenceModel = require('../models/geofence.model');
const logger = require('../utils/logger');

const validateLocation = async (userId, latitude, longitude, orgId) => {
  try {
    // Get user's assigned geofences
    const userGeofences = await geofenceModel.getUserGeofences(userId, orgId);
    
    if (!userGeofences || userGeofences.length === 0) {
      return { valid: true, message: 'No geofences assigned' };
    }
    
    // Check each geofence
    for (const geofence of userGeofences) {
      const isInside = await isPointInGeofence(latitude, longitude, geofence);
      
      // If this is an exclusion geofence and user is inside, it's a violation
      if (geofence.type === 'exclusion' && isInside) {
        await geofenceModel.recordViolation({
          userId,
          geofenceId: geofence.id,
          latitude,
          longitude,
          type: 'entry',
          orgId
        });
        
        return { 
          valid: false, 
          message: `Geofence violation: entered exclusion zone "${geofence.name}"`,
          geofence
        };
      }
      
      // If this is an inclusion geofence and user is outside, it's a violation
      if (geofence.type === 'inclusion' && !isInside) {
        await geofenceModel.recordViolation({
          userId,
          geofenceId: geofence.id,
          latitude,
          longitude,
          type: 'exit',
          orgId
        });
        
        return { 
          valid: false, 
          message: `Geofence violation: exited inclusion zone "${geofence.name}"`,
          geofence
        };
      }
    }
    
    return { valid: true, message: 'Location is valid' };
  } catch (error) {
    logger.error('Error in validateLocation service:', error);
    throw error;
  }
};

const isPointInGeofence = async (latitude, longitude, geofence) => {
  try {
    if (geofence.shape === 'circle') {
      // Calculate distance using Haversine formula
      const centerLat = geofence.coordinates.center.latitude;
      const centerLng = geofence.coordinates.center.longitude;
      const radius = geofence.coordinates.radius;
      
      const distance = calculateDistance(latitude, longitude, centerLat, centerLng);
      return distance <= radius;
    } else if (geofence.shape === 'polygon') {
      // Check if point is inside polygon
      return isPointInPolygon(latitude, longitude, geofence.coordinates.points);
    }
    
    return false;
  } catch (error) {
    logger.error('Error in isPointInGeofence service:', error);
    throw error;
  }
};

// Helper functions for geofence calculations
const calculateDistance = (lat1, lng1, lat2, lng2) => {
  // Haversine formula implementation
};

const isPointInPolygon = (latitude, longitude, points) => {
  // Point-in-polygon algorithm implementation
};

module.exports = {
  validateLocation,
  isPointInGeofence
};
8. Middleware Implementation
Middlewares will handle cross-cutting concerns:
javascript
// src/middlewares/auth.middleware.js
const jwt = require('jsonwebtoken');
const config = require('../config');
const { errorResponse } = require('../utils/response');
const logger = require('../utils/logger');
const userModel = require('../models/user.model');

const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return errorResponse(res, 'Authentication required', 401);
    }
    
    const decoded = jwt.verify(token, config.jwt.secret);
    
    // Get user from database to ensure they still exist and are active
    const user = await userModel.getUserById(decoded.id, decoded.orgId);
    
    if (!user || user.data.status !== 'active') {
      return errorResponse(res, 'User not found or inactive', 401);
    }
    
    // Attach user info to request
    req.user = {
      id: decoded.id,
      orgId: decoded.orgId,
      role: decoded.role,
      email: decoded.email
    };
    
    next();
  } catch (error) {
    logger.error('Authentication error:', error);
    return errorResponse(res, 'Invalid or expired token', 401);
  }
};

const authorize = (roles = []) => {
  return (req, res, next) => {
    if (!req.user) {
      return errorResponse(res, 'Authentication required', 401);
    }
    
    if (roles.length && !roles.includes(req.user.role)) {
      return errorResponse(res, 'Insufficient permissions', 403);
    }
    
    next();
  };
};

module.exports = {
  authenticate,
  authorize
};
9. Response Utility
For consistent API responses:
javascript
// src/utils/response.js
const successResponse = (res, data, statusCode = 200) => {
  return res.status(statusCode).json({
    success: true,
    data
  });
};

const errorResponse = (res, message, statusCode = 400) => {
  return res.status(statusCode).json({
    success: false,
    error: message
  });
};

module.exports = {
  successResponse,
  errorResponse
};
10. Main Application Setup
javascript
// src/app.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const config = require('./config');
const routes = require('./routes');
const loggerMiddleware = require('./middlewares/logger.middleware');
const errorMiddleware = require('./middlewares/error.middleware');

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(loggerMiddleware);

// Routes
app.use('/api', routes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date() });
});

// Error handling
app.use(errorMiddleware);

module.exports = app;
11. Server Initialization
javascript
// src/server.js
const app = require('./app');
const config = require('./config');
const logger = require('./utils/logger');

const PORT = config.port || 3000;

const server = app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  logger.error('Unhandled Rejection:', err);
  // Close server & exit process
  server.close(() => process.exit(1));
});

module.exports = server;
Module-Specific Implementations
Authentication Module
javascript
// src/models/auth.model.js
const { poolQuery } = require('../utils/database');
const tableNames = require('../database/tables');
const bcrypt = require('bcrypt');
const logger = require('../utils/logger');
const authQueries = require('../database/queries/auth.queries');

const login = async (email, password, orgId) => {
  try {
    // Get user by email and organization
    const { rows } = await poolQuery.query(authQueries.getUserByEmail, [email, orgId]);
    
    if (!rows || rows.length === 0) {
      throw new Error('Invalid credentials');
    }
    
    const user = rows[0];
    
    // Check if user is active
    if (user.status !== 'active') {
      throw new Error('User account is not active');
    }
    
    // Compare password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }
    
    // Update last login
    await poolQuery.query(authQueries.updateLastLogin, [user.id, orgId]);
    
    // Return user without password
    delete user.password;
    return user;
  } catch (error) {
    logger.error('Error in login model:', error);
    throw error;
  }
};

module.exports = {
  login
};
Attendance Module
javascript
// src/models/attendance.model.js
const { poolQuery } = require('../utils/database');
const tableNames = require('../database/tables');
const logger = require('../utils/logger');
const attendanceQueries = require('../database/queries/attendance.queries');

const checkIn = async (data) => {
  try {
    const { userId, latitude, longitude, siteId, shiftId, photoUrl, deviceInfo, orgId } = data;
    
    // Check if user already checked in today
    const { rows: existingCheckins } = await poolQuery.query(
      attendanceQueries.getActiveCheckin,
      [userId, orgId]
    );
    
    if (existingCheckins && existingCheckins.length > 0) {
      throw new Error('User already checked in');
    }
    
    // Record check-in
    const { rows } = await poolQuery.query(
      attendanceQueries.createAttendance,
      [
        userId,
        'check-in',
        new Date(),
        latitude,
        longitude,
        siteId,
        shiftId,
        photoUrl,
        JSON.stringify(deviceInfo || {}),
        orgId
      ]
    );
    
    // Also record in attendance_logs
    await poolQuery.query(
      attendanceQueries.createAttendanceLog,
      [
        userId,
        shiftId,
        siteId,
        new Date(),
        'check-in',
        orgId,
        JSON.stringify({ latitude, longitude, photoUrl })
      ]
    );
    
    return rows[0];
  } catch (error) {
    logger.error('Error in checkIn model:', error);
    throw error;
  }
};

const checkOut = async (data) => {
  try {
    const { userId, latitude, longitude, photoUrl, deviceInfo, orgId } = data;
    
    // Get active check-in
    const { rows: activeCheckins } = await poolQuery.query(
      attendanceQueries.getActiveCheckin,
      [userId, orgId]
    );
    
    if (!activeCheckins || activeCheckins.length === 0) {
      throw new Error('No active check-in found');
    }
    
    const activeCheckin = activeCheckins[0];
    
    // Record check-out
    const { rows } = await poolQuery.query(
      attendanceQueries.createAttendance,
      [
        userId,
        'check-out',
        new Date(),
        latitude,
        longitude,
        activeCheckin.site_id,
        activeCheckin.shift_id,
        photoUrl,
        JSON.stringify(deviceInfo || {}),
        orgId
      ]
    );
    
    // Also record in attendance_logs
    await poolQuery.query(
      attendanceQueries.createAttendanceLog,
      [
        userId,
        activeCheckin.shift_id,
        activeCheckin.site_id,
        new Date(),
        'check-out',
        orgId,
        JSON.stringify({ latitude, longitude, photoUrl })
      ]
    );
    
    return rows[0];
  } catch (error) {
    logger.error('Error in checkOut model:', error);
    throw error;
  }
};

module.exports = {
  checkIn,
  checkOut
  // Other attendance-related functions
};
Geofence Module
javascript
// src/models/geofence.model.js
const { poolQuery } = require('../utils/database');
const tableNames = require('../database/tables');
const logger = require('../utils/logger');
const geofenceQueries = require('../database/queries/geofence.queries');

const getGeofences = async (filters, pagination, orgId) => {
  try {
    let conditionsStatement = [],
      conditionValues = [],
      projections = tableNames.geofences.fields;
    
    // Build conditions based on filters
    conditionValues.push(orgId);
    conditionsStatement.push(`org_id = $${conditionValues.length}`);
    
    if (filters.siteId) {
      conditionValues.push(filters.siteId);
      conditionsStatement.push(`site_id = $${conditionValues.length}`);
    }
    
    if (filters.isActive !== undefined) {
      conditionValues.push(filters.isActive);
      conditionsStatement.push(`is_active = $${conditionValues.length}`);
    }
    
    // Always exclude deleted records
    conditionsStatement.push(`deleted_at IS NULL`);
    
    // Build pagination
    const offset = (pagination.page - 1) * pagination.limit;
    conditionValues.push(pagination.limit);
    conditionValues.push(offset);
    
    // Build query
    let sqlQuery = `
      SELECT ${projections.join(', ')} 
      FROM ${tableNames.geofences.name} 
      WHERE ${conditionsStatement.join(' AND ')}
      ORDER BY id DESC
      LIMIT $${conditionValues.length - 1} OFFSET $${conditionValues.length}
    `;
    
    // Count query for pagination
    let countQuery = `
      SELECT COUNT(*) as total
      FROM ${tableNames.geofences.name}
      WHERE ${conditionsStatement.join(' AND ')}
    `;
    
    // Execute queries
    const [dataResult, countResult] = await Promise.all([
      poolQuery.query(sqlQuery, conditionValues),
      poolQuery.query(countQuery, conditionValues.slice(0, -2))
    ]);
    
    return {
      data: dataResult.rows,
      pagination: {
        total: parseInt(countResult.rows[0].total),
        page: pagination.page,
        limit: pagination.limit
      }
    };
  } catch (error) {
    logger.error('Error in getGeofences model:', error);
    throw error;
  }
};

const getUserGeofences = async (userId, orgId) => {
  try {
    // Get user's department and role
    const { rows: userRows } = await poolQuery.query(
      geofenceQueries.getUserDetails,
      [userId, orgId]
    );
    
    if (!userRows || userRows.length === 0) {
      throw new Error('User not found');
    }
    
    const user = userRows[0];
    
    // Get geofences assigned to user's department, role, or directly to user
    const { rows } = await poolQuery.query(
      geofenceQueries.getUserGeofences,
      [orgId, user.department_id, user.role_id, userId]
    );
    
    return rows;
  } catch (error) {
    logger.error('Error in getUserGeofences model:', error);
    throw error;
  }
};

const recordViolation = async (violationData) => {
  try {
    const { userId, geofenceId, latitude, longitude, type, orgId } = violationData;
    
    // Record violation
    const { rows } = await poolQuery.query(
      geofenceQueries.createGeofenceViolation,
      [userId, geofenceId, new Date(), latitude, longitude, type, orgId]
    );
    
    return rows[0];
  } catch (error) {
    logger.error('Error in recordViolation model:', error);
    throw error;
  }
};

module.exports = {
  getGeofences,
  getUserGeofences,
  recordViolation
  // Other geofence-related functions
};
Key Design Principles
1. Separation of Concerns
The codebase structure follows a clear separation of concerns:
Routes: Define API endpoints and handle request routing
Controllers: Handle HTTP requests and responses
Services: Contain business logic
Models: Handle database operations
Middlewares: Handle cross-cutting concerns
Utils: Provide utility functions
2. Non-ORM Database Access
Following the Flying Chital approach, we use direct SQL queries with a poolQuery pattern instead of an ORM:
SQL queries are defined in separate files for better organization
The poolQuery utility provides a consistent interface for database operations
Transaction support is included for operations that require atomicity
3. Error Handling
Comprehensive error handling is implemented throughout the codebase:
Try-catch blocks in async functions
Centralized error middleware for consistent error responses
Detailed error logging
4. Logging
A robust logging system is implemented:
Different log levels (debug, info, warn, error)
Request logging middleware
Structured logging for better analysis
5. Configuration Management
Configuration is centralized and environment-based:
Environment variables for sensitive information
Default values for non-sensitive configuration
Configuration validation on startup
6. Security
Security best practices are followed:
JWT-based authentication
Role-based authorization
Password hashing
Input validation
Helmet for HTTP security headers
CORS configuration
7. Scalability
The codebase is designed for scalability:
Modular structure for easy extension
Separation of business logic from data access
Efficient database queries with pagination
Connection pooling for database access
Conclusion
This backend codebase structure provides a solid foundation for the Yatri Mobile GPS-based employee tracking system. It follows industry best practices and is inspired by the Flying Chital Logistics Management System architecture, but adapted for the specific requirements of this project.
The non-ORM approach with poolQuery provides direct control over database operations while maintaining a clean and organized codebase. The modular structure allows for easy extension and maintenance as the project evolves.
Database Schema Design for Yatri Mobile GPS Employee Tracking System
This document outlines the database schema design for the Yatri Mobile GPS-based employee tracking system, based on the requirements analysis and UI/API mapping.
Schema Overview
The database schema follows a relational model with clear entity relationships to support all the required functionality of the GPS-based employee tracking system. The schema is designed to be efficient, normalized, and scalable.
Core Tables
Organizations Table
sql
CREATE TABLE organizations (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  address TEXT,
  contact_person VARCHAR(255),
  contact_email VARCHAR(255),
  contact_phone VARCHAR(20),
  logo_url TEXT,
  settings JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores information about client organizations using the system.
Sites Table
sql
CREATE TABLE sites (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  name VARCHAR(255) NOT NULL,
  address TEXT,
  latitude NUMERIC(10, 8),
  longitude NUMERIC(11, 8),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores information about different sites/locations within an organization.
Departments Table
sql
CREATE TABLE departments (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores information about departments within an organization.
Roles Table
sql
CREATE TABLE roles (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  permissions JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores information about user roles and their permissions.
Users Table
sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  department_id INTEGER REFERENCES departments(id),
  role_id INTEGER NOT NULL REFERENCES roles(id),
  email VARCHAR(255) UNIQUE,
  password VARCHAR(255) NOT NULL,
  first_name VARCHAR(255) NOT NULL,
  last_name VARCHAR(255) NOT NULL,
  phone VARCHAR(20),
  profile_image TEXT,
  employee_id VARCHAR(50),
  status VARCHAR(20) DEFAULT 'active',
  last_login TIMESTAMP WITH TIME ZONE,
  fcm_token TEXT,
  settings JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores information about users/employees in the system.
Admin Assignments Table
sql
CREATE TABLE admin_assignments (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  role_id INTEGER NOT NULL REFERENCES roles(id),
  department_id INTEGER REFERENCES departments(id),
  site_id INTEGER REFERENCES sites(id),
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  status VARCHAR(20) DEFAULT 'active',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table implements the hierarchical admin structure as specified in the stakeholder requirements.
Shifts Table
sql
CREATE TABLE shifts (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  name VARCHAR(255) NOT NULL,
  start_time TIME NOT NULL,
  end_time TIME NOT NULL,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores information about work shifts.
User Shifts Table
sql
CREATE TABLE user_shifts (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  shift_id INTEGER NOT NULL REFERENCES shifts(id),
  site_id INTEGER NOT NULL REFERENCES sites(id),
  start_date DATE NOT NULL,
  end_date DATE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table associates users with their assigned shifts.
Attendance Tracking
Attendances Table
sql
CREATE TABLE attendances (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  type VARCHAR(20) NOT NULL, -- check-in, check-out
  timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
  latitude NUMERIC(10, 8) NOT NULL,
  longitude NUMERIC(11, 8) NOT NULL,
  accuracy NUMERIC(10, 2),
  site_id INTEGER REFERENCES sites(id),
  shift_id INTEGER REFERENCES shifts(id),
  photo_url TEXT,
  device_info JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table records attendance check-ins and check-outs.
Attendance Logs Table
sql
CREATE TABLE attendance_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  shift_id INTEGER NOT NULL REFERENCES shifts(id),
  site_id INTEGER NOT NULL REFERENCES sites(id),
  log_time TIMESTAMP WITH TIME ZONE NOT NULL,
  type VARCHAR(20) NOT NULL, -- check-in, check-out, break-start, break-end
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table provides a detailed log of all attendance-related events.
Geofencing
Geofences Table
sql
CREATE TABLE geofences (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  site_id INTEGER REFERENCES sites(id),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  type VARCHAR(20) NOT NULL, -- polygon, circle
  coordinates JSONB NOT NULL, -- For polygon: array of lat/lng points, For circle: center point and radius
  color VARCHAR(20),
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores geofence definitions.
Geofence Assignments Table
sql
CREATE TABLE geofence_assignments (
  id SERIAL PRIMARY KEY,
  geofence_id INTEGER NOT NULL REFERENCES geofences(id),
  department_id INTEGER REFERENCES departments(id),
  role_id INTEGER REFERENCES roles(id),
  user_id INTEGER REFERENCES users(id),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table associates geofences with departments, roles, or specific users.
Geofence Violations Table
sql
CREATE TABLE geofence_violations (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  geofence_id INTEGER NOT NULL REFERENCES geofences(id),
  violation_time TIMESTAMP WITH TIME ZONE NOT NULL,
  latitude NUMERIC(10, 8) NOT NULL,
  longitude NUMERIC(11, 8) NOT NULL,
  accuracy NUMERIC(10, 2),
  type VARCHAR(20) NOT NULL, -- exit, entry, dwell
  status VARCHAR(20) DEFAULT 'pending', -- pending, reviewed, resolved
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table records geofence violations.
Checkpoints and Patrols
Checkpoints Table
sql
CREATE TABLE checkpoints (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  site_id INTEGER REFERENCES sites(id),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  latitude NUMERIC(10, 8) NOT NULL,
  longitude NUMERIC(11, 8) NOT NULL,
  qr_code TEXT,
  barcode TEXT,
  nfc_id TEXT,
  geofence_id INTEGER REFERENCES geofences(id),
  radius NUMERIC(10, 2) DEFAULT 10.0, -- meters
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores checkpoint definitions.
Patrol Routes Table
sql
CREATE TABLE patrol_routes (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  site_id INTEGER REFERENCES sites(id),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  estimated_duration INTEGER, -- minutes
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table defines patrol routes.
Route Checkpoints Table
sql
CREATE TABLE route_checkpoints (
  id SERIAL PRIMARY KEY,
  route_id INTEGER NOT NULL REFERENCES patrol_routes(id),
  checkpoint_id INTEGER NOT NULL REFERENCES checkpoints(id),
  sequence_number INTEGER NOT NULL,
  estimated_time INTEGER, -- minutes from start
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table associates checkpoints with patrol routes in a specific sequence.
Patrol Assignments Table
sql
CREATE TABLE patrol_assignments (
  id SERIAL PRIMARY KEY,
  route_id INTEGER NOT NULL REFERENCES patrol_routes(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  scheduled_start TIMESTAMP WITH TIME ZONE NOT NULL,
  scheduled_end TIMESTAMP WITH TIME ZONE,
  actual_start TIMESTAMP WITH TIME ZONE,
  actual_end TIMESTAMP WITH TIME ZONE,
  status VARCHAR(20) DEFAULT 'scheduled', -- scheduled, in-progress, completed, missed
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table assigns patrol routes to users.
Checkpoint Scans Table
sql
CREATE TABLE checkpoint_scans (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  checkpoint_id INTEGER NOT NULL REFERENCES checkpoints(id),
  patrol_assignment_id INTEGER REFERENCES patrol_assignments(id),
  scan_time TIMESTAMP WITH TIME ZONE NOT NULL,
  latitude NUMERIC(10, 8) NOT NULL,
  longitude NUMERIC(11, 8) NOT NULL,
  accuracy NUMERIC(10, 2),
  scan_method VARCHAR(20) NOT NULL, -- qr, barcode, nfc, manual
  photo_url TEXT,
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table records checkpoint scans during patrols.
Task Management
Tasks Table
sql
CREATE TABLE tasks (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  site_id INTEGER REFERENCES sites(id),
  title VARCHAR(255) NOT NULL,
  description TEXT,
  priority VARCHAR(20) DEFAULT 'medium', -- low, medium, high, urgent
  due_date TIMESTAMP WITH TIME ZONE,
  status VARCHAR(20) DEFAULT 'pending', -- pending, in-progress, completed, cancelled
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores task definitions.
Task Assignments Table
sql
CREATE TABLE task_assignments (
  id SERIAL PRIMARY KEY,
  task_id INTEGER NOT NULL REFERENCES tasks(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  assigned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMP WITH TIME ZONE,
  status VARCHAR(20) DEFAULT 'assigned', -- assigned, in-progress, completed, rejected
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table assigns tasks to users.
Alerts and Notifications
Alerts Table
sql
CREATE TABLE alerts (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  site_id INTEGER REFERENCES sites(id),
  user_id INTEGER REFERENCES users(id),
  type VARCHAR(50) NOT NULL, -- emergency, geofence-violation, missed-checkpoint, alertness-check, system
  severity VARCHAR(20) NOT NULL, -- low, medium, high, critical
  title VARCHAR(255) NOT NULL,
  message TEXT,
  latitude NUMERIC(10, 8),
  longitude NUMERIC(11, 8),
  status VARCHAR(20) DEFAULT 'active', -- active, acknowledged, resolved
  acknowledged_by INTEGER REFERENCES users(id),
  acknowledged_at TIMESTAMP WITH TIME ZONE,
  resolved_by INTEGER REFERENCES users(id),
  resolved_at TIMESTAMP WITH TIME ZONE,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores alerts generated by the system.
Alert Settings Table
sql
CREATE TABLE alert_settings (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  alert_type VARCHAR(50) NOT NULL,
  is_enabled BOOLEAN DEFAULT true,
  notification_channels JSONB DEFAULT '["app"]', -- app, email, sms
  escalation_time INTEGER, -- minutes before escalation
  escalation_users JSONB, -- array of user IDs for escalation
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores alert configuration settings.
Alertness Checks Table
sql
CREATE TABLE alertness_checks (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  scheduled_time TIMESTAMP WITH TIME ZONE NOT NULL,
  response_time TIMESTAMP WITH TIME ZONE,
  status VARCHAR(20) DEFAULT 'scheduled', -- scheduled, responded, missed
  check_type VARCHAR(20) NOT NULL, -- button, captcha, photo
  response_data JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table manages alertness verification checks.
Location Tracking
Location Logs Table
sql
CREATE TABLE location_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  latitude NUMERIC(10, 8) NOT NULL,
  longitude NUMERIC(11, 8) NOT NULL,
  accuracy NUMERIC(10, 2),
  altitude NUMERIC(10, 2),
  speed NUMERIC(10, 2),
  heading NUMERIC(10, 2),
  activity_type VARCHAR(50), -- still, walking, running, vehicle
  battery_level NUMERIC(5, 2),
  timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
This table logs user location data.
Location Settings Table
sql
CREATE TABLE location_settings (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  tracking_interval INTEGER DEFAULT 300, -- seconds
  high_accuracy BOOLEAN DEFAULT false,
  background_tracking BOOLEAN DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores location tracking settings for users.
Reports and Analytics
Reports Table
sql
CREATE TABLE reports (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  name VARCHAR(255) NOT NULL,
  type VARCHAR(50) NOT NULL, -- attendance, geofence, patrol, task, alert
  parameters JSONB DEFAULT '{}',
  schedule VARCHAR(50), -- daily, weekly, monthly, none
  recipients JSONB, -- array of email addresses
  last_generated TIMESTAMP WITH TIME ZONE,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores report definitions.
Report Exports Table
sql
CREATE TABLE report_exports (
  id SERIAL PRIMARY KEY,
  report_id INTEGER NOT NULL REFERENCES reports(id),
  file_url TEXT NOT NULL,
  file_type VARCHAR(20) NOT NULL, -- pdf, csv, excel
  generated_by INTEGER NOT NULL REFERENCES users(id),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE
);
This table stores exported report files.
Entity Relationship Diagram
+---------------+       +---------------+       +---------------+
| organizations |<------| sites         |<------| geofences     |
+---------------+       +---------------+       +---------------+
       ^                      ^                       ^
       |                      |                       |
       v                      v                       v
+---------------+       +---------------+       +---------------+
| departments   |<------| users         |<------| geofence_     |
+---------------+       +---------------+       | violations    |
       ^                      ^                 +---------------+
       |                      |                       ^
       v                      v                       |
+---------------+       +---------------+       +---------------+
| roles         |<------| attendances   |       | checkpoints   |
+---------------+       +---------------+       +---------------+
                                                      ^
                                                      |
                                                      v
+---------------+       +---------------+       +---------------+
| patrol_routes |<------| route_        |<------| checkpoint_   |
+---------------+       | checkpoints   |       | scans         |
       ^                +---------------+       +---------------+
       |                                              ^
       v                                              |
+---------------+       +---------------+       +---------------+
| patrol_       |<------| tasks         |<------| alerts        |
| assignments   |       +---------------+       +---------------+
+---------------+               ^                     ^
                               |                      |
                               v                      v
                        +---------------+       +---------------+
                        | task_         |       | alertness_    |
                        | assignments   |       | checks        |
                        +---------------+       +---------------+
Indexes
To optimize query performance, the following indexes should be created:
sql
-- Users indexes
CREATE INDEX idx_users_org_id ON users(org_id);
CREATE INDEX idx_users_department_id ON users(department_id);
CREATE INDEX idx_users_role_id ON users(role_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_employee_id ON users(employee_id);

-- Attendance indexes
CREATE INDEX idx_attendances_user_id ON attendances(user_id);
CREATE INDEX idx_attendances_timestamp ON attendances(timestamp);
CREATE INDEX idx_attendances_site_id ON attendances(site_id);

-- Geofence indexes
CREATE INDEX idx_geofences_org_id ON geofences(org_id);
CREATE INDEX idx_geofences_site_id ON geofences(site_id);

-- Geofence violations indexes
CREATE INDEX idx_geofence_violations_user_id ON geofence_violations(user_id);
CREATE INDEX idx_geofence_violations_geofence_id ON geofence_violations(geofence_id);
CREATE INDEX idx_geofence_violations_violation_time ON geofence_violations(violation_time);

-- Checkpoint indexes
CREATE INDEX idx_checkpoints_org_id ON checkpoints(org_id);
CREATE INDEX idx_checkpoints_site_id ON checkpoints(site_id);

-- Checkpoint scans indexes
CREATE INDEX idx_checkpoint_scans_user_id ON checkpoint_scans(user_id);
CREATE INDEX idx_checkpoint_scans_checkpoint_id ON checkpoint_scans(checkpoint_id);
CREATE INDEX idx_checkpoint_scans_scan_time ON checkpoint_scans(scan_time);

-- Location logs indexes
CREATE INDEX idx_location_logs_user_id ON location_logs(user_id);
CREATE INDEX idx_location_logs_timestamp ON location_logs(timestamp);

-- Alerts indexes
CREATE INDEX idx_alerts_org_id ON alerts(org_id);
CREATE INDEX idx_alerts_user_id ON alerts(user_id);
CREATE INDEX idx_alerts_created_at ON alerts(created_at);
CREATE INDEX idx_alerts_status ON alerts(status);
Database Functions and Triggers
Update Timestamp Function
sql
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
Update Timestamp Triggers
sql
-- Example for users table
CREATE TRIGGER update_users_timestamp
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

-- Similar triggers for all tables with updated_at column
Geofence Validation Function
sql
CREATE OR REPLACE FUNCTION is_point_in_geofence(
  point_lat NUMERIC,
  point_lng NUMERIC,
  geofence_id INTEGER
)
RETURNS BOOLEAN AS $$
DECLARE
  geofence_type VARCHAR;
  geofence_coords JSONB;
  center_lat NUMERIC;
  center_lng NUMERIC;
  radius NUMERIC;
  result BOOLEAN;
BEGIN
  -- Get geofence data
  SELECT type, coordinates INTO geofence_type, geofence_coords
  FROM geofences
  WHERE id = geofence_id;
  
  -- Check geofence type
  IF geofence_type = 'circle' THEN
    -- For circular geofence
    center_lat := (geofence_coords->>'lat')::NUMERIC;
    center_lng := (geofence_coords->>'lng')::NUMERIC;
    radius := (geofence_coords->>'radius')::NUMERIC;
    
    -- Calculate distance using Haversine formula
    -- (simplified implementation - actual function would be more complex)
    result := (
      6371000 * 2 * ASIN(
        SQRT(
          POWER(SIN((point_lat - center_lat) * PI() / 180 / 2), 2) +
          COS(point_lat * PI() / 180) * COS(center_lat * PI() / 180) *
          POWER(SIN((point_lng - center_lng) * PI() / 180 / 2), 2)
        )
      )
    ) <= radius;
    
  ELSIF geofence_type = 'polygon' THEN
    -- For polygon geofence
    -- (simplified implementation - actual function would use PostGIS)
    -- This would require PostGIS extension
    -- result := ST_Contains(ST_GeomFromGeoJSON(geofence_coords), ST_Point(point_lng, point_lat));
    result := true; -- Placeholder
  ELSE
    result := false;
  END IF;
  
  RETURN result;
END;
$$ LANGUAGE plpgsql;
Database Views
Active Employees View
sql
CREATE OR REPLACE VIEW active_employees AS
SELECT 
  u.id,
  u.first_name,
  u.last_name,
  u.employee_id,
  d.name AS department,
  r.name AS role,
  s.name AS site,
  a.type AS last_action,
  a.timestamp AS last_action_time,
  l.latitude,
  l.longitude,
  l.timestamp AS last_location_time
FROM 
  users u
LEFT JOIN departments d ON u.department_id = d.id
LEFT JOIN roles r ON u.role_id = r.id
LEFT JOIN sites s ON (
  SELECT site_id FROM user_shifts 
  WHERE user_id = u.id 
  AND current_date BETWEEN start_date AND COALESCE(end_date, current_date)
  LIMIT 1
) = s.id
LEFT JOIN (
  SELECT DISTINCT ON (user_id) user_id, type, timestamp
  FROM attendances
  ORDER BY user_id, timestamp DESC
) a ON u.id = a.user_id
LEFT JOIN (
  SELECT DISTINCT ON (user_id) user_id, latitude, longitude, timestamp
  FROM location_logs
  WHERE timestamp > NOW() - INTERVAL '1 hour'
  ORDER BY user_id, timestamp DESC
) l ON u.id = l.user_id
WHERE 
  u.status = 'active'
  AND u.deleted_at IS NULL
  AND (a.type IS NULL OR a.type != 'check-out' OR a.timestamp > NOW() - INTERVAL '12 hours');
Attendance Summary View
sql
CREATE OR REPLACE VIEW attendance_summary AS
SELECT 
  u.id AS user_id,
  u.first_name,
  u.last_name,
  u.employee_id,
  d.name AS department,
  s.name AS site,
  DATE(a_in.timestamp) AS date,
  a_in.timestamp AS check_in_time,
  a_out.timestamp AS check_out_time,
  EXTRACT(EPOCH FROM (a_out.timestamp - a_in.timestamp))/3600 AS hours_worked
FROM 
  users u
LEFT JOIN departments d ON u.department_id = d.id
LEFT JOIN (
  SELECT DISTINCT ON (user_id, DATE(timestamp)) user_id, timestamp, site_id
  FROM attendances
  WHERE type = 'check-in'
  ORDER BY user_id, DATE(timestamp), timestamp ASC
) a_in ON u.id = a_in.user_id
LEFT JOIN sites s ON a_in.site_id = s.id
LEFT JOIN (
  SELECT DISTINCT ON (user_id, DATE(timestamp)) user_id, timestamp
  FROM attendances
  WHERE type = 'check-out'
  ORDER BY user_id, DATE(timestamp), timestamp DESC
) a_out ON u.id = a_out.user_id AND DATE(a_in.timestamp) = DATE(a_out.timestamp)
WHERE 
  a_in.timestamp IS NOT NULL;
Conclusion
This database schema design provides a comprehensive foundation for the Yatri Mobile GPS-based employee tracking system. It supports all the required functionality identified in the requirements analysis and UI/API mapping, including:
User and organization management
Hierarchical admin structure
Attendance tracking
Geofencing and violation monitoring
Checkpoint and patrol management
Task assignment and tracking
Alerts and notifications
Location tracking
Alertness monitoring
Reporting and analytics
The schema is designed to be efficient, normalized, and scalable, with appropriate indexes and relationships to ensure optimal performance.
PoolQuery and Non-ORM Implementation Guide for Yatri Backend
This document details the implementation approach using the poolQuery utility and a non-ORM (Object-Relational Mapper) strategy for database interactions within each backend module of the Yatri Mobile GPS Employee Tracking System. This approach, inspired by the Flying Chital system, provides direct control over SQL queries while maintaining an organized codebase.
1. Core Concept: The poolQuery Utility
All database interactions will be channeled through the poolQuery utility defined in src/utils/database.js. This utility provides two main functions:
poolQuery.query(sqlString, paramsArray): Executes a parameterized SQL query against the PostgreSQL connection pool. It handles logging and basic error handling.
poolQuery.transaction(async (client) => { ... }): Manages database transactions, providing a client object for executing multiple queries within a single transaction. It automatically handles BEGIN, COMMIT, and ROLLBACK.
javascript
// Example usage in a model function
const { poolQuery } = require("../utils/database");

const getUserById = (id, orgId) => {
  const sql = "SELECT * FROM users WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL";
  return poolQuery.query(sql, [id, orgId])
    .then(result => {
      if (result.rows.length === 0) {
        throw new Error("User not found");
      }
      return result.rows[0]; // Return the user data
    });
};
2. Model Layer Responsibility (src/models/)
The src/models/ directory contains the Data Access Layer (DAL). Each file (e.g., user.model.js, attendance.model.js) is responsible for:
Encapsulating Database Logic: Grouping all database operations related to a specific entity or feature (e.g., Users, Attendance).
Executing Queries: Using poolQuery.query or poolQuery.transaction to interact with the database.
Handling Parameters: Safely passing parameters to SQL queries using parameterized queries ($1, $2, etc.) to prevent SQL injection.
Returning Data: Returning raw or minimally processed data from the database to the service layer. Complex data transformations or business logic should not reside in the models.
3. SQL Query Management (src/database/queries/)
To keep model files clean and SQL queries maintainable:
Store Queries Separately: Complex or reusable SQL queries should be defined as strings or template literals in dedicated files within src/database/queries/ (e.g., user.queries.js).
Import Queries: Import these query strings into the corresponding model files.
Dynamic Queries: For queries that change significantly based on filters or parameters (like list endpoints with dynamic WHERE clauses), construct the SQL string dynamically within the model function, ensuring proper parameterization.
javascript
// src/database/queries/user.queries.js
module.exports = {
  FIND_BY_ID: "SELECT * FROM users WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL",
  FIND_BY_EMAIL: "SELECT * FROM users WHERE email = $1 AND org_id = $2 AND deleted_at IS NULL",
  // ... other queries
};

// src/models/user.model.js
const { poolQuery } = require("../utils/database");
const userQueries = require("../database/queries/user.queries");

const getUserById = (id, orgId) => {
  return poolQuery.query(userQueries.FIND_BY_ID, [id, orgId])
    .then(result => {
      // ... handling
    });
};
4. Implementing CRUD Operations (Example: Users Module)
Here’s how standard CRUD operations would be implemented in src/models/user.model.js using poolQuery:
Create (INSERT)
javascript
const createUser = (userData) => {
  const { org_id, department_id, role_id, email, hashedPassword, first_name, last_name, phone, employee_id, status } = userData;
  const sql = `
    INSERT INTO users (org_id, department_id, role_id, email, password, first_name, last_name, phone, employee_id, status, created_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
    RETURNING id, email, first_name, last_name, role_id, status; // Return only necessary fields
  `;
  const params = [org_id, department_id, role_id, email, hashedPassword, first_name, last_name, phone, employee_id, status || 'active'];
  return poolQuery.query(sql, params).then(result => result.rows[0]);
};
(Note: Password hashing happens in the service/controller before calling the model)
Read (SELECT - Single)
javascript
const getUserById = (id, orgId) => {
  const sql = userQueries.FIND_BY_ID; // Using query from separate file
  return poolQuery.query(sql, [id, orgId])
    .then(result => {
      if (result.rowCount === 0) return null;
      delete result.rows[0].password; // Never return password hash
      return result.rows[0];
    });
};
Read (SELECT - List with Filters/Pagination)
javascript
const getUsers = (filters = {}, pagination = { page: 1, limit: 10 }) => {
  let sql = "SELECT id, email, first_name, last_name, role_id, status FROM users";
  let countSql = "SELECT COUNT(*) as total FROM users";
  let whereClauses = ["deleted_at IS NULL"];
  let params = [];
  let paramIndex = 1;

  // Add filters dynamically
  if (filters.orgId) {
    whereClauses.push(`org_id = $${paramIndex++}`);
    params.push(filters.orgId);
  }
  if (filters.departmentId) {
    whereClauses.push(`department_id = $${paramIndex++}`);
    params.push(filters.departmentId);
  }
  if (filters.status) {
    whereClauses.push(`status = $${paramIndex++}`);
    params.push(filters.status);
  }
  // ... other filters

  if (whereClauses.length > 0) {
    const whereString = ` WHERE ${whereClauses.join(" AND ")}`;
    sql += whereString;
    countSql += whereString;
  }

  sql += ` ORDER BY created_at DESC`;

  // Add pagination
  const limit = parseInt(pagination.limit);
  const offset = (parseInt(pagination.page) - 1) * limit;
  sql += ` LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
  params.push(limit, offset);

  // Execute both queries
  return Promise.all([
    poolQuery.query(sql, params),
    poolQuery.query(countSql, params.slice(0, paramIndex - 3)) // Exclude limit/offset params for count
  ]).then(([dataResult, countResult]) => ({
    data: dataResult.rows,
    pagination: {
      total: parseInt(countResult.rows[0].total),
      page: parseInt(pagination.page),
      limit: limit,
      totalPages: Math.ceil(parseInt(countResult.rows[0].total) / limit)
    }
  }));
};
Update (UPDATE)
javascript
const updateUser = (id, orgId, updateData) => {
  let setClauses = [];
  let params = [id, orgId];
  let paramIndex = 3;

  // Dynamically build SET clauses for provided fields
  Object.keys(updateData).forEach(key => {
    // Ensure only valid columns are updated (prevent injection)
    const validColumns = ['department_id', 'role_id', 'first_name', 'last_name', 'phone', 'status', 'profile_image', 'employee_id'];
    if (validColumns.includes(key)) {
      setClauses.push(`${key} = $${paramIndex++}`);
      params.push(updateData[key]);
    }
  });

  if (setClauses.length === 0) {
    return Promise.reject(new Error("No valid fields provided for update"));
  }

  setClauses.push(`updated_at = NOW()`);

  const sql = `
    UPDATE users
    SET ${setClauses.join(", ")}
    WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
    RETURNING id, email, first_name, last_name, role_id, status;
  `;

  return poolQuery.query(sql, params).then(result => {
    if (result.rowCount === 0) throw new Error("User not found or no changes made");
    return result.rows[0];
  });
};
Delete (Soft Delete - UPDATE)
javascript
const deleteUser = (id, orgId) => {
  const sql = `
    UPDATE users
    SET deleted_at = NOW(), updated_at = NOW(), status = 'inactive'
    WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;
  `;
  return poolQuery.query(sql, [id, orgId]).then(result => {
    if (result.rowCount === 0) throw new Error("User not found");
    return { message: "User deactivated successfully" };
  });
};
5. Transaction Handling
For operations requiring multiple database steps that must succeed or fail together (atomicity), use poolQuery.transaction:
javascript
const createRouteWithCheckpoints = (routeData, checkpointData) => {
  return poolQuery.transaction(async (client) => {
    // 1. Insert the patrol route
    const routeSql = "INSERT INTO patrol_routes (...) VALUES (...) RETURNING id";
    const routeResult = await client.query(routeSql, [/* route params */]);
    const routeId = routeResult.rows[0].id;

    // 2. Insert associated checkpoints
    const checkpointSql = "INSERT INTO route_checkpoints (route_id, checkpoint_id, sequence_number, ...) VALUES ($1, $2, $3, ...)";
    const checkpointPromises = checkpointData.map(cp => 
      client.query(checkpointSql, [routeId, cp.checkpoint_id, cp.sequence_number, /* other params */])
    );
    await Promise.all(checkpointPromises);

    // Return the created route ID or other relevant data
    return { routeId }; 
  });
};
6. Module-Specific Implementation Notes
Auth (auth.model.js): Focus on queries selecting users by email/username and updating last_login. Password comparison logic resides in the service/controller.
Attendance/Location (attendance.model.js, location.model.js): These models will handle frequent INSERT operations. Ensure location_logs table is optimized (consider partitioning if volume is extremely high). Use efficient queries for fetching active check-ins or recent locations.
Geofence (geofence.model.js): Queries will involve fetching geofence definitions and assignments. The actual point-in-polygon or distance calculations might happen in the geofence.service.js using data fetched by the model, or potentially using database functions (like the example is_point_in_geofence if using PostGIS or implementing complex SQL). Recording violations involves simple INSERTs.
Patrol/Checkpoint (patrol.model.js, checkpoint.model.js): Involves joins between routes, checkpoints, assignments, and scans. Use transactions when creating routes with checkpoints or recording scans that update assignment status.
Task (task.model.js): Standard CRUD operations, potentially with joins to fetch assignee details.
Alert/Alertness (alert.model.js, alertness.model.js): Primarily INSERT operations for new alerts/checks and UPDATE operations for status changes.
Report (report.model.js): This model might contain functions that execute complex aggregation queries (GROUP BY, SUM, COUNT, AVG) based on parameters passed from the service layer to generate report data.
Admin (Various Models): Standard CRUD operations for managing core entities like Organizations, Sites, Departments, Roles, Shifts.
7. Best Practices
Parameterization: ALWAYS use parameterized queries ($1, $2) to prevent SQL injection.
Error Handling: Models should throw errors on database issues or when expected data isn't found (e.g., trying to update a non-existent record). Services/controllers handle these errors.
Data Return: Return only necessary data from models. Avoid SELECT * where possible, especially if tables have many columns or sensitive data (like password hashes).
Consistency: Maintain consistent function naming and parameter patterns across all models (e.g., getById, getAll, create, update, delete).
Logging: Use the logger utility within model functions to log query execution and errors for debugging.
By following this non-ORM, poolQuery-based approach, the backend development will have fine-grained control over database interactions, potentially leading to better performance for complex queries, while maintaining a structured and maintainable codebase.
UI to API Mapping for Yatri Mobile GPS Employee Tracking System
This document maps each UI screen to its corresponding backend API endpoints and data requirements.
Authentication Screens
Login Screen
UI: Login Screen.jpg, Admin Login.jpg
APIs:
POST /api/auth/login - Authenticate user and return JWT token
Request Data: email/username, password
Response Data: JWT token, user details including role
User Profile and Settings
UI: user profile and settings screen.jpg
APIs:
GET /api/users/profile - Get user profile information
PUT /api/users/profile - Update user profile information
PUT /api/users/change-password - Change user password
Request Data: user profile details, new password
Response Data: updated user profile, success status
Employee Management
Employee Onboarding
UI: Employee Onboarding.jpg, Employee Onboarding(1).jpg, Onboard Employee.jpg
APIs:
POST /api/users - Create new employee
GET /api/departments - Get list of departments for dropdown
GET /api/roles - Get list of roles for dropdown
GET /api/shifts - Get list of shifts for dropdown
Request Data: employee details (name, email, phone, department, role, shift)
Response Data: created employee details, success status
Employee Management
UI: Employee Management.jpg, Employee management interface.jpg
APIs:
GET /api/users - Get list of employees with pagination and filters
GET /api/users/:id - Get specific employee details
PUT /api/users/:id - Update employee details
DELETE /api/users/:id - Deactivate/delete employee
Request Data: filter parameters, employee ID, updated employee details
Response Data: list of employees, specific employee details, update status
Attendance Management
Attendance Management
UI: Attendance Management.jpg, Attendance Management Screen.jpg
APIs:
GET /api/attendance - Get attendance records with filters
GET /api/attendance/summary - Get attendance summary statistics
PUT /api/attendance/:id - Update attendance record (for corrections)
Request Data: filter parameters (date range, employee, department)
Response Data: attendance records, summary statistics
Check-In Process
UI: Check-In Process Screen.jpg
APIs:
POST /api/attendance/check-in - Record employee check-in
GET /api/geofence/validate - Validate if check-in location is within geofence
Request Data: employee ID, timestamp, GPS coordinates, optional photo
Response Data: check-in status, validation result
Check-Out Process
UI: Check-out Process Screen.jpg
APIs:
POST /api/attendance/check-out - Record employee check-out
GET /api/geofence/validate - Validate if check-out location is within geofence
Request Data: employee ID, timestamp, GPS coordinates, optional photo
Response Data: check-out status, validation result
Geofence Management
Geofence Creation and Management
UI: Geofence Management Screen.jpg, Geofence creation and management Map view.jpg, Geofence creation and management List view.jpg
APIs:
GET /api/geofence - Get list of geofences
POST /api/geofence - Create new geofence
GET /api/geofence/:id - Get specific geofence details
PUT /api/geofence/:id - Update geofence
DELETE /api/geofence/:id - Delete geofence
Request Data: geofence name, coordinates (polygon points), radius (for circular), associated location
Response Data: created/updated geofence details, list of geofences
Geofence Violations
UI: Geofence Violations.jpg, Geofence Violations(1).jpg
APIs:
GET /api/geofence/violations - Get list of geofence violations
GET /api/geofence/violations/:id - Get specific violation details
PUT /api/geofence/violations/:id - Update violation status (reviewed, resolved)
Request Data: filter parameters (date range, employee, geofence)
Response Data: list of violations, specific violation details
Checkpoint Management
Checkpoints
UI: Checkpoints.jpg, Checkpoints Management.jpg
APIs:
GET /api/checkpoints - Get list of checkpoints
POST /api/checkpoints - Create new checkpoint
GET /api/checkpoints/:id - Get specific checkpoint details
PUT /api/checkpoints/:id - Update checkpoint
DELETE /api/checkpoints/:id - Delete checkpoint
Request Data: checkpoint name, location, QR/barcode data, associated geofence
Response Data: created/updated checkpoint details, list of checkpoints
Create Checkpoint
UI: Create Checkpoint.jpg, Create Checkpoint(1).jpg
APIs:
POST /api/checkpoints - Create new checkpoint
GET /api/locations - Get list of locations for dropdown
Request Data: checkpoint name, location, QR/barcode data, associated geofence
Response Data: created checkpoint details
QR/Barcode Scanner
UI: QR_barcode scanner interface.jpg
APIs:
POST /api/barcode/scan - Process scanned barcode/QR code
GET /api/barcode/location/:code - Get location details from barcode/QR code
Request Data: scanned code, timestamp, GPS coordinates
Response Data: scan result, associated checkpoint/location details
Patrol Management
Patrol Dashboard
UI: Patrol Dashboard.jpg
APIs:
GET /api/patrol/summary - Get patrol summary statistics
GET /api/patrol/active - Get active patrols
GET /api/patrol/schedule - Get patrol schedules
Request Data: filter parameters (date range, employee, location)
Response Data: patrol statistics, active patrols, scheduled patrols
Task Management
UI: Task Management.jpg, Task Management(1).jpg, Task management screen.jpg
APIs:
GET /api/tasks - Get list of tasks
POST /api/tasks - Create new task
GET /api/tasks/:id - Get specific task details
PUT /api/tasks/:id - Update task
DELETE /api/tasks/:id - Delete task
PUT /api/tasks/:id/status - Update task status
Request Data: task details, assignee, due date, priority, status
Response Data: created/updated task details, list of tasks
Monitoring and Alerts
Live Monitoring
UI: Live Monitoring Screen.jpg, Real-time monitoring dashboard.jpg
APIs:
GET /api/users/location - Get current location of all employees
GET /api/attendance/active - Get currently active employees
GET /api/geofence/status - Get geofence status for all employees
Request Data: filter parameters (department, role, location)
Response Data: employee locations, active status, geofence status
Alert Management
UI: Alert Management.jpg, Alert Management(1).jpg
APIs:
GET /api/alerts - Get list of alerts
PUT /api/alerts/:id - Update alert status
POST /api/alerts/settings - Configure alert settings
Request Data: filter parameters, alert ID, status update, settings configuration
Response Data: list of alerts, update status, settings status
Emergency Alert
UI: Emergency alert interface for field employees.jpg
APIs:
POST /api/alerts/emergency - Create emergency alert
GET /api/alerts/emergency/active - Get active emergency alerts
Request Data: employee ID, GPS coordinates, alert type, optional description
Response Data: alert creation status, list of active alerts
Alertness Monitoring
UI: Alertness Monitoring.jpg, Alertness verification interface.jpg, Monitoring guard alertness.jpg
APIs:
POST /api/alertness/verify - Submit alertness verification
GET /api/alertness/checks - Get scheduled alertness checks
GET /api/alertness/history - Get alertness verification history
Request Data: employee ID, verification type, timestamp, response data
Response Data: verification status, scheduled checks, verification history
Dashboards
Home Dashboard
UI: Home Dashboard Screen.jpg
APIs:
GET /api/dashboard/summary - Get dashboard summary statistics
GET /api/dashboard/recent-activity - Get recent activities
GET /api/alerts/recent - Get recent alerts
Request Data: filter parameters (time range)
Response Data: summary statistics, recent activities, recent alerts
Admin Dashboard
UI: Wrb Admin Dashboard.jpg, Design a comprehensive dashboard for administrators with___Navy blue (#2A3F54) header with company l.jpg
APIs:
GET /api/admin/dashboard/summary - Get admin dashboard summary
GET /api/admin/users/stats - Get user statistics
GET /api/admin/attendance/stats - Get attendance statistics
GET /api/admin/geofence/stats - Get geofence statistics
GET /api/admin/alerts/stats - Get alert statistics
Request Data: filter parameters (time range, department, location)
Response Data: summary statistics for all modules
Active Duty Monitoring
UI: Active duty monitoring screen.jpg
APIs:
GET /api/attendance/active - Get currently active employees
GET /api/users/location - Get current location of all employees
Request Data: filter parameters (department, role, location)
Response Data: active employees with location data
Reports and Analytics
Reports & Analytics
UI: Reports & Analytics.jpg
APIs:
GET /api/reports/attendance - Get attendance reports
GET /api/reports/geofence - Get geofence violation reports
GET /api/reports/alerts - Get alerts reports
GET /api/reports/tasks - Get task completion reports
POST /api/reports/export - Export reports to CSV/PDF
Request Data: report type, filter parameters, export format
Response Data: report data, export URL
Security Guard Specific
Specialized Interface for Security Guards
UI: Specialized interface for roving security guards.jpg
APIs:
GET /api/patrol/assignments - Get patrol assignments
POST /api/patrol/checkpoint - Record checkpoint visit
GET /api/patrol/route - Get patrol route
Request Data: guard ID, checkpoint ID, timestamp, GPS coordinates
Response Data: assignments, checkpoint recording status, route details
API Documentation for Yatri Mobile GPS Employee Tracking System
This document provides detailed specifications for all backend API endpoints required for the Yatri Mobile GPS-based employee tracking system. Each endpoint includes its purpose, request/response formats, and mapping to the corresponding UI screens.
1. Authentication Module (/api/auth)
1.1 User Login
Endpoint: POST /api/auth/login
Description: Authenticates a user (employee or admin) using email and password.
Request Body:
json
{
  "email": "user@example.com",
  "password": "password123"
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "token": "<jwt_token>",
    "user": {
      "id": 1,
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "role": "security_guard", // or "admin", "manager", etc.
      "org_id": 1,
      "profile_image": "url_to_image.jpg"
    }
  }
}
Error Responses:
400 Bad Request: Missing email or password.
401 Unauthorized: Invalid credentials or inactive user.
500 Internal Server Error: Server error.
UI Screens:
Login Screen.jpg
Admin Login.jpg
Create a professional admin login screen with___Navy blue (#2A3F54) header with _Admin Portal_ text .jpg
1.2 Forgot Password
Endpoint: POST /api/auth/forgot-password
Description: Initiates the password reset process for a user.
Request Body:
json
{
  "email": "user@example.com"
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "message": "Password reset instructions sent to your email."
  }
}
Error Responses:
400 Bad Request: Missing email.
404 Not Found: Email not found.
500 Internal Server Error: Server error.
UI Screens: (Implicitly needed for Login screens)
1.3 Reset Password
Endpoint: POST /api/auth/reset-password
Description: Resets the user's password using a reset token.
Request Body:
json
{
  "token": "<reset_token>",
  "new_password": "newSecurePassword123"
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "message": "Password reset successfully."
  }
}
Error Responses:
400 Bad Request: Missing token or new password, invalid token.
500 Internal Server Error: Server error.
UI Screens: (Implicitly needed for Login screens)
2. User Management Module (/api/users)
2.1 Get Current User Profile
Endpoint: GET /api/users/profile
Description: Retrieves the profile information of the currently authenticated user.
Authentication: Required (JWT Token)
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "id": 1,
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "phone": "1234567890",
    "employee_id": "EMP123",
    "role": "security_guard",
    "department": "Security",
    "site": "Site A",
    "profile_image": "url_to_image.jpg",
    "settings": {}
  }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
404 Not Found: User not found.
500 Internal Server Error: Server error.
UI Screens:
user profile and settings screen .jpg
2.2 Update Current User Profile
Endpoint: PUT /api/users/profile
Description: Updates the profile information of the currently authenticated user.
Authentication: Required (JWT Token)
Request Body:
json
{
  "first_name": "John",
  "last_name": "Doe",
  "phone": "9876543210",
  "profile_image": "new_url_to_image.jpg",
  "settings": { "notifications_enabled": true }
}
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated user profile data */ }
}
Error Responses:
400 Bad Request: Invalid input data.
401 Unauthorized: Invalid or missing token.
500 Internal Server Error: Server error.
UI Screens:
user profile and settings screen .jpg
2.3 Change Current User Password
Endpoint: PUT /api/users/change-password
Description: Changes the password for the currently authenticated user.
Authentication: Required (JWT Token)
Request Body:
json
{
  "current_password": "oldPassword123",
  "new_password": "newSecurePassword123"
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "message": "Password changed successfully."
  }
}
Error Responses:
400 Bad Request: Missing fields, incorrect current password.
401 Unauthorized: Invalid or missing token.
500 Internal Server Error: Server error.
UI Screens:
user profile and settings screen .jpg
2.4 Get List of Users (Admin/Manager)
Endpoint: GET /api/users
Description: Retrieves a list of users within the organization, with filtering and pagination.
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
page (number, optional, default: 1): Page number for pagination.
limit (number, optional, default: 10): Number of users per page.
departmentId (number, optional): Filter by department ID.
roleId (number, optional): Filter by role ID.
siteId (number, optional): Filter by site ID.
status (string, optional): Filter by status (e.g., 'active', 'inactive').
search (string, optional): Search by name or employee ID.
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { /* User object 1 */ },
    { /* User object 2 */ }
  ],
  "pagination": {
    "total": 100,
    "page": 1,
    "limit": 10,
    "totalPages": 10
  }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Employee Management.jpg
Employee management interface .jpg
2.5 Create New User (Admin)
Endpoint: POST /api/users
Description: Creates a new user (employee) within the organization.
Authentication: Required (JWT Token, Admin role)
Request Body:
json
{
  "email": "new.employee@example.com",
  "password": "defaultPassword123",
  "first_name": "New",
  "last_name": "Employee",
  "phone": "1122334455",
  "employee_id": "EMP456",
  "department_id": 2,
  "role_id": 3,
  "site_id": 1,
  "shift_id": 1
}
Success Response (201 Created):
json
{
  "success": true,
  "data": { /* Created user object */ }
}
Error Responses:
400 Bad Request: Missing required fields, invalid data, email already exists.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Employee Onboarding.jpg
Employee Onboarding(1).jpg
Onboard Employee.jpg
2.6 Get User Details (Admin/Manager)
Endpoint: GET /api/users/:id
Description: Retrieves detailed information for a specific user.
Authentication: Required (JWT Token, Admin/Manager role)
Path Parameters:
id (number): ID of the user to retrieve.
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Detailed user object */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: User not found.
500 Internal Server Error: Server error.
UI Screens:
Employee Management.jpg (When viewing details)
Employee management interface .jpg (When viewing details)
2.7 Update User Details (Admin)
Endpoint: PUT /api/users/:id
Description: Updates information for a specific user.
Authentication: Required (JWT Token, Admin role)
Path Parameters:
id (number): ID of the user to update.
Request Body: (Fields to update)
json
{
  "first_name": "Updated",
  "status": "inactive",
  "department_id": 3
}
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated user object */ }
}
Error Responses:
400 Bad Request: Invalid input data.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: User not found.
500 Internal Server Error: Server error.
UI Screens:
Employee Management.jpg (When editing)
Employee management interface .jpg (When editing)
2.8 Delete User (Admin)
Endpoint: DELETE /api/users/:id
Description: Deactivates (soft delete) a specific user.
Authentication: Required (JWT Token, Admin role)
Path Parameters:
id (number): ID of the user to delete.
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "message": "User deactivated successfully."
  }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: User not found.
500 Internal Server Error: Server error.
UI Screens:
Employee Management.jpg (Delete action)
Employee management interface .jpg (Delete action)
2.9 Get User Location History
Endpoint: GET /api/users/:id/location-history
Description: Retrieves the location history for a specific user within a time range.
Authentication: Required (JWT Token, Admin/Manager role)
Path Parameters:
id (number): ID of the user.
Query Parameters:
startTime (string, ISO 8601 format): Start of the time range.
endTime (string, ISO 8601 format): End of the time range.
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "latitude": 12.34, "longitude": 56.78, "timestamp": "...", "accuracy": 10.5 },
    { /* Location log 2 */ }
  ]
}
Error Responses:
400 Bad Request: Invalid time range.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: User not found.
500 Internal Server Error: Server error.
UI Screens:
Live Monitoring Screen.jpg (When viewing history)
Real-time monitoring dashboard .jpg (When viewing history)
3. Attendance Module (/api/attendance)
3.1 Check-In
Endpoint: POST /api/attendance/check-in
Description: Records an employee's check-in time and location.
Authentication: Required (JWT Token)
Request Body:
json
{
  "latitude": 12.345678,
  "longitude": 98.765432,
  "accuracy": 5.0,
  "photo_url": "optional_url_to_photo.jpg",
  "device_info": { /* Optional device details */ }
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "id": 101,
    "user_id": 1,
    "type": "check-in",
    "timestamp": "...",
    "message": "Check-in successful."
  }
}
Error Responses:
400 Bad Request: Missing location, already checked in, geofence violation (if configured).
401 Unauthorized: Invalid or missing token.
500 Internal Server Error: Server error.
UI Screens:
Check-In Process Screen.jpg
3.2 Check-Out
Endpoint: POST /api/attendance/check-out
Description: Records an employee's check-out time and location.
Authentication: Required (JWT Token)
Request Body:
json
{
  "latitude": 12.345678,
  "longitude": 98.765432,
  "accuracy": 5.0,
  "photo_url": "optional_url_to_photo.jpg",
  "device_info": { /* Optional device details */ }
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "id": 102,
    "user_id": 1,
    "type": "check-out",
    "timestamp": "...",
    "message": "Check-out successful."
  }
}
Error Responses:
400 Bad Request: Missing location, not checked in, geofence violation (if configured).
401 Unauthorized: Invalid or missing token.
500 Internal Server Error: Server error.
UI Screens:
Check-out Process Screen.jpg
3.3 Get Attendance Records (Admin/Manager)
Endpoint: GET /api/attendance
Description: Retrieves attendance records with filtering and pagination.
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
page (number, optional, default: 1): Page number.
limit (number, optional, default: 10): Records per page.
userId (number, optional): Filter by user ID.
departmentId (number, optional): Filter by department ID.
siteId (number, optional): Filter by site ID.
startDate (string, YYYY-MM-DD): Start date of the range.
endDate (string, YYYY-MM-DD): End date of the range.
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "id": 101, "user_id": 1, "type": "check-in", "timestamp": "...", "latitude": ..., "longitude": ... },
    { "id": 102, "user_id": 1, "type": "check-out", "timestamp": "...", "latitude": ..., "longitude": ... }
  ],
  "pagination": { /* Pagination details */ }
}
Error Responses:
400 Bad Request: Invalid date format or parameters.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Attendance Management.jpg
Attendance Management Screen.jpg
3.4 Get Attendance Summary (Admin/Manager)
Endpoint: GET /api/attendance/summary
Description: Retrieves summary statistics for attendance (e.g., present, absent, late).
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
date (string, YYYY-MM-DD): Date for the summary.
departmentId (number, optional): Filter by department.
siteId (number, optional): Filter by site.
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "date": "YYYY-MM-DD",
    "total_employees": 50,
    "present": 45,
    "absent": 5,
    "late": 3,
    "on_leave": 2
  }
}
Error Responses:
400 Bad Request: Invalid date format.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Attendance Management.jpg
Attendance Management Screen.jpg
Wrb Admin Dashboard.jpg
Design a comprehensive dashboard for administrators with___Navy blue (#2A3F54) header with company l.jpg
3.5 Get Currently Active Employees (Admin/Manager)
Endpoint: GET /api/attendance/active
Description: Retrieves a list of employees who are currently checked in.
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
departmentId (number, optional): Filter by department.
siteId (number, optional): Filter by site.
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "id": 1, "first_name": "John", "last_name": "Doe", "check_in_time": "...", "latitude": ..., "longitude": ... },
    { /* Active employee 2 */ }
  ]
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Live Monitoring Screen.jpg
Real-time monitoring dashboard .jpg
Active duty monitoring screen.jpg
4. Geofence Module (/api/geofence)
4.1 Get List of Geofences (Admin/Manager)
Endpoint: GET /api/geofence
Description: Retrieves a list of defined geofences.
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
page (number, optional, default: 1): Page number.
limit (number, optional, default: 10): Records per page.
siteId (number, optional): Filter by site.
isActive (boolean, optional): Filter by active status.
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "id": 1, "name": "Site A Perimeter", "type": "polygon", "coordinates": [...], "is_active": true },
    { /* Geofence 2 */ }
  ],
  "pagination": { /* Pagination details */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Geofence Management Screen.jpg
Geofence creation and management List view.jpg
Geofence creation and management Map view.jpg
4.2 Create Geofence (Admin)
Endpoint: POST /api/geofence
Description: Creates a new geofence.
Authentication: Required (JWT Token, Admin role)
Request Body:
json
{
  "name": "New Geofence Zone",
  "site_id": 1,
  "type": "polygon", // or "circle"
  "coordinates": { /* GeoJSON structure or center/radius */ },
  "description": "Optional description",
  "is_active": true
}
Success Response (201 Created):
json
{
  "success": true,
  "data": { /* Created geofence object */ }
}
Error Responses:
400 Bad Request: Missing required fields, invalid coordinates.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Geofence Management Screen.jpg
Geofence creation and management Map view.jpg
4.3 Get Geofence Details (Admin/Manager)
Endpoint: GET /api/geofence/:id
Description: Retrieves details for a specific geofence.
Authentication: Required (JWT Token, Admin/Manager role)
Path Parameters:
id (number): ID of the geofence.
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Detailed geofence object */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Geofence not found.
500 Internal Server Error: Server error.
UI Screens:
Geofence Management Screen.jpg (When viewing details)
Geofence creation and management Map view.jpg (When viewing details)
4.4 Update Geofence (Admin)
Endpoint: PUT /api/geofence/:id
Description: Updates a specific geofence.
Authentication: Required (JWT Token, Admin role)
Path Parameters:
id (number): ID of the geofence to update.
Request Body: (Fields to update)
json
{
  "name": "Updated Geofence Name",
  "is_active": false
}
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated geofence object */ }
}
Error Responses:
400 Bad Request: Invalid input data.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Geofence not found.
500 Internal Server Error: Server error.
UI Screens:
Geofence Management Screen.jpg (When editing)
Geofence creation and management Map view.jpg (When editing)
4.5 Delete Geofence (Admin)
Endpoint: DELETE /api/geofence/:id
Description: Deletes a specific geofence.
Authentication: Required (JWT Token, Admin role)
Path Parameters:
id (number): ID of the geofence to delete.
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "message": "Geofence deleted successfully."
  }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Geofence not found.
500 Internal Server Error: Server error.
UI Screens:
Geofence Management Screen.jpg (Delete action)
Geofence creation and management List view.jpg (Delete action)
4.6 Get Geofence Violations (Admin/Manager)
Endpoint: GET /api/geofence/violations
Description: Retrieves a list of geofence violations.
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
page (number, optional, default: 1): Page number.
limit (number, optional, default: 10): Records per page.
userId (number, optional): Filter by user ID.
geofenceId (number, optional): Filter by geofence ID.
startDate (string, YYYY-MM-DD): Start date.
endDate (string, YYYY-MM-DD): End date.
status (string, optional): Filter by status (e.g., 'pending', 'resolved').
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "id": 1, "user_id": 1, "geofence_id": 1, "violation_time": "...", "type": "exit", "status": "pending" },
    { /* Violation 2 */ }
  ],
  "pagination": { /* Pagination details */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Geofence Violations.jpg
Geofence Violations(1).jpg
4.7 Update Geofence Violation Status (Admin/Manager)
Endpoint: PUT /api/geofence/violations/:id
Description: Updates the status of a geofence violation (e.g., acknowledge, resolve).
Authentication: Required (JWT Token, Admin/Manager role)
Path Parameters:
id (number): ID of the violation.
Request Body:
json
{
  "status": "resolved",
  "notes": "Spoke with employee, resolved."
}
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated violation object */ }
}
Error Responses:
400 Bad Request: Invalid status.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Violation not found.
500 Internal Server Error: Server error.
UI Screens:
Geofence Violations.jpg (Action buttons)
Geofence Violations(1).jpg (Action buttons)
4.8 Validate Location Against Geofence
Endpoint: POST /api/geofence/validate
Description: Checks if given coordinates are within the user's assigned geofences. Used internally or for specific checks like check-in/out.
Authentication: Required (JWT Token)
Request Body:
json
{
  "latitude": 12.345678,
  "longitude": 98.765432
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "is_valid": true, // or false
    "message": "Location is within assigned geofences.", // or details of violation
    "violated_geofence": null // or geofence object if invalid
  }
}
Error Responses:
400 Bad Request: Missing coordinates.
401 Unauthorized: Invalid or missing token.
500 Internal Server Error: Server error.
UI Screens: (Used internally by Check-In/Check-Out flows)
5. Checkpoint Module (/api/checkpoints)
5.1 Get List of Checkpoints (Admin/Manager)
Endpoint: GET /api/checkpoints
Description: Retrieves a list of defined checkpoints.
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
page (number, optional, default: 1): Page number.
limit (number, optional, default: 10): Records per page.
siteId (number, optional): Filter by site.
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "id": 1, "name": "Main Gate", "latitude": ..., "longitude": ..., "qr_code": "..." },
    { /* Checkpoint 2 */ }
  ],
  "pagination": { /* Pagination details */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Checkpoints.jpg
Checkpoints Management .jpg
5.2 Create Checkpoint (Admin)
Endpoint: POST /api/checkpoints
Description: Creates a new checkpoint.
Authentication: Required (JWT Token, Admin role)
Request Body:
json
{
  "name": "Warehouse Entrance",
  "site_id": 1,
  "latitude": 12.345,
  "longitude": 98.765,
  "qr_code": "UNIQUE_QR_CODE_DATA",
  "barcode": "OPTIONAL_BARCODE_DATA",
  "nfc_id": "OPTIONAL_NFC_ID",
  "description": "Optional description"
}
Success Response (201 Created):
json
{
  "success": true,
  "data": { /* Created checkpoint object */ }
}
Error Responses:
400 Bad Request: Missing required fields, invalid coordinates.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Create Checkpoint.jpg
Create Checkpoint(1).jpg
5.3 Get Checkpoint Details (Admin/Manager)
Endpoint: GET /api/checkpoints/:id
Description: Retrieves details for a specific checkpoint.
Authentication: Required (JWT Token, Admin/Manager role)
Path Parameters:
id (number): ID of the checkpoint.
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Detailed checkpoint object */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Checkpoint not found.
500 Internal Server Error: Server error.
UI Screens:
Checkpoints.jpg (When viewing details)
Checkpoints Management .jpg (When viewing details)
5.4 Update Checkpoint (Admin)
Endpoint: PUT /api/checkpoints/:id
Description: Updates a specific checkpoint.
Authentication: Required (JWT Token, Admin role)
Path Parameters:
id (number): ID of the checkpoint to update.
Request Body: (Fields to update)
json
{
  "name": "Updated Checkpoint Name",
  "qr_code": "NEW_QR_CODE"
}
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated checkpoint object */ }
}
Error Responses:
400 Bad Request: Invalid input data.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Checkpoint not found.
500 Internal Server Error: Server error.
UI Screens:
Checkpoints.jpg (When editing)
Checkpoints Management .jpg (When editing)
5.5 Delete Checkpoint (Admin)
Endpoint: DELETE /api/checkpoints/:id
Description: Deletes a specific checkpoint.
Authentication: Required (JWT Token, Admin role)
Path Parameters:
id (number): ID of the checkpoint to delete.
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "message": "Checkpoint deleted successfully."
  }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Checkpoint not found.
500 Internal Server Error: Server error.
UI Screens:
Checkpoints.jpg (Delete action)
Checkpoints Management .jpg (Delete action)
5.6 Record Checkpoint Scan
Endpoint: POST /api/checkpoints/scan
Description: Records a checkpoint scan event (QR, Barcode, NFC, Manual).
Authentication: Required (JWT Token)
Request Body:
json
{
  "checkpoint_id": 1, // Required if scan_method is 'manual'
  "scan_data": "QR_CODE_DATA", // Required if scan_method is 'qr', 'barcode', 'nfc'
  "scan_method": "qr", // 'qr', 'barcode', 'nfc', 'manual'
  "latitude": 12.345,
  "longitude": 98.765,
  "accuracy": 10.0,
  "photo_url": "optional_url_to_photo.jpg",
  "notes": "Optional notes"
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "id": 201,
    "user_id": 1,
    "checkpoint_id": 1,
    "scan_time": "...",
    "message": "Checkpoint scan recorded successfully."
  }
}
Error Responses:
400 Bad Request: Missing required fields, invalid scan data, checkpoint not found, location validation failed.
401 Unauthorized: Invalid or missing token.
500 Internal Server Error: Server error.
UI Screens:
QR_barcode scanner interface .jpg
Specialized interface for roving security guards .jpg (Checkpoint scan action)
6. Patrol Module (/api/patrol)
6.1 Get Patrol Routes (Admin/Manager)
Endpoint: GET /api/patrol/routes
Description: Retrieves a list of defined patrol routes.
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
page (number, optional, default: 1): Page number.
limit (number, optional, default: 10): Records per page.
siteId (number, optional): Filter by site.
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "id": 1, "name": "Night Shift Route A", "site_id": 1, "estimated_duration": 60 },
    { /* Route 2 */ }
  ],
  "pagination": { /* Pagination details */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Patrol Dashboard.jpg (Route management section)
6.2 Create Patrol Route (Admin)
Endpoint: POST /api/patrol/routes
Description: Creates a new patrol route with associated checkpoints.
Authentication: Required (JWT Token, Admin role)
Request Body:
json
{
  "name": "Day Shift Route B",
  "site_id": 1,
  "description": "Covers building B perimeter",
  "estimated_duration": 45,
  "checkpoints": [
    { "checkpoint_id": 3, "sequence_number": 1, "estimated_time": 5 },
    { "checkpoint_id": 5, "sequence_number": 2, "estimated_time": 15 },
    { "checkpoint_id": 8, "sequence_number": 3, "estimated_time": 30 }
  ]
}
Success Response (201 Created):
json
{
  "success": true,
  "data": { /* Created route object with checkpoints */ }
}
Error Responses:
400 Bad Request: Missing required fields, invalid checkpoint data.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Patrol Dashboard.jpg (Route creation section)
6.3 Get Patrol Route Details (Admin/Manager)
Endpoint: GET /api/patrol/routes/:id
Description: Retrieves details for a specific patrol route, including its checkpoints.
Authentication: Required (JWT Token, Admin/Manager role)
Path Parameters:
id (number): ID of the route.
Success Response (200 OK):
json
{
  "success": true,
  "data": { 
    "id": 1, 
    "name": "Night Shift Route A", 
    /* other route fields */,
    "checkpoints": [
      { "checkpoint_id": 1, "name": "Main Gate", "sequence_number": 1, "estimated_time": 5 },
      { /* Checkpoint 2 */ }
    ]
  }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Route not found.
500 Internal Server Error: Server error.
UI Screens:
Patrol Dashboard.jpg (When viewing route details)
6.4 Update Patrol Route (Admin)
Endpoint: PUT /api/patrol/routes/:id
Description: Updates a specific patrol route and its checkpoints.
Authentication: Required (JWT Token, Admin role)
Path Parameters:
id (number): ID of the route to update.
Request Body: (Fields to update, including checkpoints array if changing)
json
{
  "name": "Updated Route Name",
  "checkpoints": [ /* Updated checkpoint sequence */ ]
}
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated route object */ }
}
Error Responses:
400 Bad Request: Invalid input data.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Route not found.
500 Internal Server Error: Server error.
UI Screens:
Patrol Dashboard.jpg (When editing route)
6.5 Delete Patrol Route (Admin)
Endpoint: DELETE /api/patrol/routes/:id
Description: Deletes a specific patrol route.
Authentication: Required (JWT Token, Admin role)
Path Parameters:
id (number): ID of the route to delete.
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "message": "Patrol route deleted successfully."
  }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Route not found.
500 Internal Server Error: Server error.
UI Screens:
Patrol Dashboard.jpg (Delete route action)
6.6 Get Patrol Assignments (Admin/Manager/Employee)
Endpoint: GET /api/patrol/assignments
Description: Retrieves patrol assignments. Admins/Managers can filter, employees see their own.
Authentication: Required (JWT Token)
Query Parameters (Admin/Manager only):
page (number, optional, default: 1): Page number.
limit (number, optional, default: 10): Records per page.
userId (number, optional): Filter by user ID.
routeId (number, optional): Filter by route ID.
siteId (number, optional): Filter by site ID.
startDate (string, YYYY-MM-DD): Start date.
endDate (string, YYYY-MM-DD): End date.
status (string, optional): Filter by status (e.g., 'scheduled', 'in-progress', 'completed').
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "id": 1, "route_id": 1, "user_id": 1, "scheduled_start": "...", "status": "scheduled" },
    { /* Assignment 2 */ }
  ],
  "pagination": { /* Pagination details, if applicable */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions (if trying to access others' data).
500 Internal Server Error: Server error.
UI Screens:
Patrol Dashboard.jpg
Specialized interface for roving security guards .jpg
6.7 Create Patrol Assignment (Admin/Manager)
Endpoint: POST /api/patrol/assignments
Description: Assigns a patrol route to a user for a specific time.
Authentication: Required (JWT Token, Admin/Manager role)
Request Body:
json
{
  "route_id": 1,
  "user_id": 5,
  "scheduled_start": "YYYY-MM-DDTHH:MM:SSZ",
  "scheduled_end": "YYYY-MM-DDTHH:MM:SSZ" // Optional
}
Success Response (201 Created):
json
{
  "success": true,
  "data": { /* Created assignment object */ }
}
Error Responses:
400 Bad Request: Missing required fields, invalid IDs or dates.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Route or user not found.
500 Internal Server Error: Server error.
UI Screens:
Patrol Dashboard.jpg (Assignment creation section)
6.8 Start Patrol
Endpoint: POST /api/patrol/assignments/:id/start
Description: Marks a patrol assignment as started by the assigned employee.
Authentication: Required (JWT Token)
Path Parameters:
id (number): ID of the patrol assignment.
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated assignment object with actual_start time and status 'in-progress' */ }
}
Error Responses:
400 Bad Request: Patrol already started or completed.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Not assigned to this patrol.
404 Not Found: Assignment not found.
500 Internal Server Error: Server error.
UI Screens:
Specialized interface for roving security guards .jpg (Start patrol action)
6.9 End Patrol
Endpoint: POST /api/patrol/assignments/:id/end
Description: Marks a patrol assignment as completed by the assigned employee.
Authentication: Required (JWT Token)
Path Parameters:
id (number): ID of the patrol assignment.
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated assignment object with actual_end time and status 'completed' */ }
}
Error Responses:
400 Bad Request: Patrol not started or already completed.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Not assigned to this patrol.
404 Not Found: Assignment not found.
500 Internal Server Error: Server error.
UI Screens:
Specialized interface for roving security guards .jpg (End patrol action)
6.10 Get Patrol Summary (Admin/Manager)
Endpoint: GET /api/patrol/summary
Description: Retrieves summary statistics for patrols (e.g., completed, missed, on-time).
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
startDate (string, YYYY-MM-DD): Start date.
endDate (string, YYYY-MM-DD): End date.
siteId (number, optional): Filter by site.
departmentId (number, optional): Filter by department.
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "total_scheduled": 100,
    "completed": 85,
    "missed": 10,
    "in_progress": 5,
    "completed_on_time": 75,
    "completed_late": 10
  }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Patrol Dashboard.jpg
Wrb Admin Dashboard.jpg
Design a comprehensive dashboard for administrators with___Navy blue (#2A3F54) header with company l.jpg
7. Task Management Module (/api/tasks)
7.1 Get List of Tasks (Admin/Manager/Employee)
Endpoint: GET /api/tasks
Description: Retrieves tasks. Admins/Managers see all/filtered, employees see assigned tasks.
Authentication: Required (JWT Token)
Query Parameters (Admin/Manager only):
page (number, optional, default: 1): Page number.
limit (number, optional, default: 10): Records per page.
assigneeId (number, optional): Filter by assignee user ID.
creatorId (number, optional): Filter by creator user ID.
siteId (number, optional): Filter by site ID.
status (string, optional): Filter by status (e.g., 'pending', 'in-progress', 'completed').
priority (string, optional): Filter by priority.
dueDateStart (string, YYYY-MM-DD): Filter by due date range start.
dueDateEnd (string, YYYY-MM-DD): Filter by due date range end.
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "id": 1, "title": "Check Fire Extinguishers", "status": "pending", "priority": "high", "due_date": "...", "assignee_id": 5 },
    { /* Task 2 */ }
  ],
  "pagination": { /* Pagination details, if applicable */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions (if trying to access others' data).
500 Internal Server Error: Server error.
UI Screens:
Task Management.jpg
Task Management(1).jpg
Task management screen .jpg
7.2 Create Task (Admin/Manager)
Endpoint: POST /api/tasks
Description: Creates a new task and optionally assigns it.
Authentication: Required (JWT Token, Admin/Manager role)
Request Body:
json
{
  "title": "Inspect Security Cameras",
  "description": "Check all cameras in Building C",
  "site_id": 1,
  "priority": "medium",
  "due_date": "YYYY-MM-DDTHH:MM:SSZ",
  "assignee_id": 5 // Optional
}
Success Response (201 Created):
json
{
  "success": true,
  "data": { /* Created task object, including assignment if assignee_id provided */ }
}
Error Responses:
400 Bad Request: Missing required fields, invalid IDs or dates.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Assignee user not found.
500 Internal Server Error: Server error.
UI Screens:
Task Management.jpg (Create task action)
Task Management(1).jpg (Create task action)
7.3 Get Task Details (Admin/Manager/Employee)
Endpoint: GET /api/tasks/:id
Description: Retrieves details for a specific task.
Authentication: Required (JWT Token)
Path Parameters:
id (number): ID of the task.
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Detailed task object, including assignment details */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Not authorized to view this task.
404 Not Found: Task not found.
500 Internal Server Error: Server error.
UI Screens:
Task Management.jpg (When viewing details)
Task Management(1).jpg (When viewing details)
Task management screen .jpg (When viewing details)
7.4 Update Task (Admin/Manager)
Endpoint: PUT /api/tasks/:id
Description: Updates details of a specific task.
Authentication: Required (JWT Token, Admin/Manager role)
Path Parameters:
id (number): ID of the task to update.
Request Body: (Fields to update)
json
{
  "title": "Updated Task Title",
  "priority": "high",
  "assignee_id": 6
}
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated task object */ }
}
Error Responses:
400 Bad Request: Invalid input data.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Task or assignee not found.
500 Internal Server Error: Server error.
UI Screens:
Task Management.jpg (When editing)
Task Management(1).jpg (When editing)
7.5 Delete Task (Admin/Manager)
Endpoint: DELETE /api/tasks/:id
Description: Deletes a specific task.
Authentication: Required (JWT Token, Admin/Manager role)
Path Parameters:
id (number): ID of the task to delete.
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "message": "Task deleted successfully."
  }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Task not found.
500 Internal Server Error: Server error.
UI Screens:
Task Management.jpg (Delete action)
Task Management(1).jpg (Delete action)
7.6 Update Task Status (Employee/Admin/Manager)
Endpoint: PUT /api/tasks/:id/status
Description: Updates the status of a task (e.g., start, complete).
Authentication: Required (JWT Token)
Path Parameters:
id (number): ID of the task.
Request Body:
json
{
  "status": "in-progress", // or "completed", "rejected"
  "notes": "Optional notes",
  "photo_url": "optional_completion_photo.jpg"
}
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated task assignment object */ }
}
Error Responses:
400 Bad Request: Invalid status transition.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Not authorized to update this task's status.
404 Not Found: Task or assignment not found.
500 Internal Server Error: Server error.
UI Screens:
Task Management.jpg (Status update actions)
Task Management(1).jpg (Status update actions)
Task management screen .jpg (Status update actions)
8. Alert Module (/api/alerts)
8.1 Get List of Alerts (Admin/Manager)
Endpoint: GET /api/alerts
Description: Retrieves a list of system and user-generated alerts.
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
page (number, optional, default: 1): Page number.
limit (number, optional, default: 10): Records per page.
userId (number, optional): Filter by user ID.
siteId (number, optional): Filter by site ID.
type (string, optional): Filter by alert type (e.g., 'emergency', 'geofence-violation').
severity (string, optional): Filter by severity.
status (string, optional): Filter by status (e.g., 'active', 'acknowledged', 'resolved').
startDate (string, YYYY-MM-DD): Start date.
endDate (string, YYYY-MM-DD): End date.
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "id": 1, "type": "emergency", "severity": "critical", "user_id": 1, "status": "active", "created_at": "..." },
    { /* Alert 2 */ }
  ],
  "pagination": { /* Pagination details */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Alert Management.jpg
Alert Management(1).jpg
8.2 Update Alert Status (Admin/Manager)
Endpoint: PUT /api/alerts/:id/status
Description: Updates the status of an alert (e.g., acknowledge, resolve).
Authentication: Required (JWT Token, Admin/Manager role)
Path Parameters:
id (number): ID of the alert.
Request Body:
json
{
  "status": "acknowledged", // or "resolved"
  "notes": "Optional notes about resolution"
}
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated alert object */ }
}
Error Responses:
400 Bad Request: Invalid status transition.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
404 Not Found: Alert not found.
500 Internal Server Error: Server error.
UI Screens:
Alert Management.jpg (Action buttons)
Alert Management(1).jpg (Action buttons)
8.3 Trigger Emergency Alert (Employee)
Endpoint: POST /api/alerts/emergency
Description: Allows an employee to trigger an emergency alert (SOS).
Authentication: Required (JWT Token)
Request Body:
json
{
  "latitude": 12.345,
  "longitude": 98.765,
  "accuracy": 5.0,
  "alert_type": "medical", // Optional, e.g., 'medical', 'security', 'fire'
  "description": "Optional description of emergency"
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "id": 10, // ID of the created alert
    "message": "Emergency alert triggered successfully. Help is on the way."
  }
}
Error Responses:
400 Bad Request: Missing location.
401 Unauthorized: Invalid or missing token.
500 Internal Server Error: Server error.
UI Screens:
Emergency alert interface for field employees .jpg
8.4 Get Alert Settings (Admin)
Endpoint: GET /api/alerts/settings
Description: Retrieves the current alert configuration settings.
Authentication: Required (JWT Token, Admin role)
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "alert_type": "geofence-violation", "is_enabled": true, "notification_channels": ["app", "email"], "escalation_time": 15 },
    { /* Setting 2 */ }
  ]
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Alert Management.jpg (Settings section)
Alert Management(1).jpg (Settings section)
8.5 Update Alert Settings (Admin)
Endpoint: PUT /api/alerts/settings
Description: Updates the alert configuration settings.
Authentication: Required (JWT Token, Admin role)
Request Body:
json
[
  { "alert_type": "geofence-violation", "is_enabled": false },
  { "alert_type": "emergency", "notification_channels": ["app", "email", "sms"], "escalation_time": 5 }
]
Success Response (200 OK):
json
{
  "success": true,
  "data": { /* Updated settings array */ }
}
Error Responses:
400 Bad Request: Invalid settings data.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Alert Management.jpg (Settings section)
Alert Management(1).jpg (Settings section)
9. Alertness Module (/api/alertness)
9.1 Get Alertness Checks (Employee)
Endpoint: GET /api/alertness/checks
Description: Retrieves pending alertness checks for the authenticated employee.
Authentication: Required (JWT Token)
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "id": 1, "scheduled_time": "...", "check_type": "button", "status": "scheduled" },
    { /* Check 2 */ }
  ]
}
Error Responses:
401 Unauthorized: Invalid or missing token.
500 Internal Server Error: Server error.
UI Screens:
Alertness Monitoring.jpg
Alertness verification interface.jpg
 Monitoring guard alertness .jpg
9.2 Respond to Alertness Check (Employee)
Endpoint: POST /api/alertness/checks/:id/respond
Description: Submits a response to a pending alertness check.
Authentication: Required (JWT Token)
Path Parameters:
id (number): ID of the alertness check.
Request Body:
json
{
  "response_data": { /* Data specific to check_type, e.g., photo URL, captcha answer */ }
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "message": "Alertness check response submitted successfully."
  }
}
Error Responses:
400 Bad Request: Check already responded to or expired.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Not the assigned user for this check.
404 Not Found: Check not found.
500 Internal Server Error: Server error.
UI Screens:
Alertness Monitoring.jpg
Alertness verification interface.jpg
 Monitoring guard alertness .jpg
9.3 Get Alertness History (Admin/Manager)
Endpoint: GET /api/alertness/history
Description: Retrieves the history of alertness checks and responses.
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
page (number, optional, default: 1): Page number.
limit (number, optional, default: 10): Records per page.
userId (number, optional): Filter by user ID.
siteId (number, optional): Filter by site ID.
startDate (string, YYYY-MM-DD): Start date.
endDate (string, YYYY-MM-DD): End date.
status (string, optional): Filter by status ('responded', 'missed').
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "id": 1, "user_id": 1, "scheduled_time": "...", "response_time": "...", "status": "responded" },
    { /* History record 2 */ }
  ],
  "pagination": { /* Pagination details */ }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Alertness Monitoring.jpg (History view)
10. Report Module (/api/reports)
10.1 Generate Report (Admin/Manager)
Endpoint: GET /api/reports/:type
Description: Generates a specific type of report (e.g., attendance, geofence violations).
Authentication: Required (JWT Token, Admin/Manager role)
Path Parameters:
type (string): Type of report ('attendance', 'geofence', 'patrol', 'task', 'alert').
Query Parameters: (Vary based on report type)
startDate, endDate, userId, departmentId, siteId, etc.
Success Response (200 OK):
json
{
  "success": true,
  "data": { 
    "report_type": "attendance",
    "generated_at": "...",
    "parameters": { /* Applied filters */ },
    "results": [ /* Report data array */ ]
  }
}
Error Responses:
400 Bad Request: Invalid report type or parameters.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Reports & Analytics.jpg
10.2 Export Report (Admin/Manager)
Endpoint: POST /api/reports/export
Description: Exports a generated report to a specified format (CSV, PDF).
Authentication: Required (JWT Token, Admin/Manager role)
Request Body:
json
{
  "report_type": "attendance",
  "format": "csv", // or "pdf"
  "parameters": { /* Filters used for the report */ }
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "export_id": 5, // ID for tracking export status
    "message": "Report export started. You will be notified when it is ready."
    // Alternatively, could return a direct download URL if generated synchronously
    // "download_url": "url_to_exported_file.csv"
  }
}
Error Responses:
400 Bad Request: Invalid report type, format, or parameters.
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error during export.
UI Screens:
Reports & Analytics.jpg (Export button)
11. Dashboard Module (/api/dashboard)
11.1 Get Dashboard Summary (Employee)
Endpoint: GET /api/dashboard/summary
Description: Retrieves summary data for the employee's dashboard.
Authentication: Required (JWT Token)
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "upcoming_shift": { /* Details of next shift */ },
    "pending_tasks": 3,
    "recent_alerts": [ /* Array of recent alerts relevant to user */ ],
    "last_check_in": "...",
    "current_status": "checked-in" // or "checked-out", "on-patrol"
  }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
500 Internal Server Error: Server error.
UI Screens:
Home Dashboard Screen.jpg
11.2 Get Admin Dashboard Summary (Admin/Manager)
Endpoint: GET /api/dashboard/admin/summary
Description: Retrieves summary data for the admin/manager dashboard.
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
siteId (number, optional): Filter by site.
dateRange (string, optional): e.g., 'today', 'week', 'month'.
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "active_employees": 45,
    "total_employees": 50,
    "sites_monitored": 3,
    "active_patrols": 5,
    "pending_tasks": 15,
    "active_alerts": {
      "critical": 1,
      "high": 3,
      "medium": 5,
      "low": 10
    },
    "geofence_violations_today": 2,
    "attendance_summary": { /* Today's attendance stats */ }
  }
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Wrb Admin Dashboard.jpg
Design a comprehensive dashboard for administrators with___Navy blue (#2A3F54) header with company l.jpg
12. Location Module (/api/location)
12.1 Update User Location
Endpoint: POST /api/location
Description: Receives and logs the current location of the authenticated user.
Authentication: Required (JWT Token)
Request Body:
json
{
  "latitude": 12.345678,
  "longitude": 98.765432,
  "accuracy": 5.0,
  "altitude": 100.0, // Optional
  "speed": 1.5, // Optional, meters per second
  "heading": 90.0, // Optional, degrees from North
  "activity_type": "walking", // Optional
  "battery_level": 85.5, // Optional
  "timestamp": "YYYY-MM-DDTHH:MM:SSZ" // Timestamp from device
}
Success Response (200 OK):
json
{
  "success": true,
  "data": {
    "message": "Location updated successfully."
    // Optionally return geofence status or required actions
    // "geofence_status": "inside", 
    // "required_action": "alertness_check"
  }
}
Error Responses:
400 Bad Request: Missing required location fields.
401 Unauthorized: Invalid or missing token.
500 Internal Server Error: Server error (e.g., database write failed).
UI Screens: (Used by the mobile app's background location service)
12.2 Get Live Locations (Admin/Manager)
Endpoint: GET /api/location/live
Description: Retrieves the last known location of active employees.
Authentication: Required (JWT Token, Admin/Manager role)
Query Parameters:
departmentId (number, optional): Filter by department.
siteId (number, optional): Filter by site.
userIds (string, optional): Comma-separated list of user IDs to track.
Success Response (200 OK):
json
{
  "success": true,
  "data": [
    { "user_id": 1, "first_name": "John", "last_name": "Doe", "latitude": ..., "longitude": ..., "timestamp": "...", "status": "active" },
    { /* Location data for user 2 */ }
  ]
}
Error Responses:
401 Unauthorized: Invalid or missing token.
403 Forbidden: Insufficient permissions.
500 Internal Server Error: Server error.
UI Screens:
Live Monitoring Screen.jpg
Real-time monitoring dashboard .jpg
Active duty monitoring screen.jpg
13. Admin Module (/api/admin)
(Includes endpoints for managing Organizations, Sites, Departments, Roles, Shifts - CRUD operations similar to Users, Geofences, Checkpoints)
13.1 Get Organizations (Super Admin)
Endpoint: GET /api/admin/organizations
13.2 Create Organization (Super Admin)
Endpoint: POST /api/admin/organizations
13.3 Get Sites (Admin)
Endpoint: GET /api/admin/sites
13.4 Create Site (Admin)
Endpoint: POST /api/admin/sites
13.5 Get Departments (Admin)
Endpoint: GET /api/admin/departments
13.6 Create Department (Admin)
Endpoint: POST /api/admin/departments
13.7 Get Roles (Admin)
Endpoint: GET /api/admin/roles
13.8 Create Role (Admin)
Endpoint: POST /api/admin/roles
13.9 Get Shifts (Admin)
Endpoint: GET /api/admin/shifts
13.10 Create Shift (Admin)
Endpoint: POST /api/admin/shifts
(Detailed specifications for these admin endpoints would follow the pattern established above, including request/response formats and UI mapping where applicable, often to sections within the main Admin Dashboard or dedicated management screens not explicitly shown but implied by the requirements.)
Conclusion
This API documentation provides a comprehensive guide for the backend development of the Yatri Mobile GPS Employee Tracking System. It covers all core functionalities derived from the requirements and UI screens, ensuring clear communication between frontend and backend development teams.
Stagewise Development Plan for Yatri GPS Employee Tracking Backend
This document outlines a detailed, step-by-step development plan for the Yatri Mobile GPS-based Employee Tracking System backend. The plan is organized into stages, with each stage broken down into small, actionable tasks that can be assigned to developers or AI assistants.
Stage 1: Project Setup and Core Infrastructure
Task 1.1: Initialize Project Structure
Create project directory structure following the defined architecture
Initialize Git repository
Create package.json with initial dependencies
Set up ESLint and Prettier for code quality
Create .env.example file with required environment variables
Task 1.2: Configure Core Utilities
Implement database.js with poolQuery utility
Create logger.js for application logging
Set up response.js for standardized API responses
Implement jwt.js for token generation and validation
Create validation.js for input validation utilities
Task 1.3: Set Up Express Application
Create app.js with Express configuration
Implement server.js for application startup
Set up basic middleware (CORS, body parsing, compression)
Create health check endpoint
Implement basic error handling middleware
Task 1.4: Database Connection
Create database configuration in config/database.js
Implement connection pooling setup
Create database initialization script
Set up database tables.js with field definitions
Test database connection
Task 1.5: Authentication Middleware
Implement auth.middleware.js for JWT verification
Create role-based authorization middleware
Set up error handling for authentication failures
Implement request logging middleware
Test authentication flow
Stage 2: Authentication Module
Task 2.1: Authentication Database Layer
Create auth.queries.js with SQL query templates
Implement auth.model.js with login function
Add password comparison logic
Create functions for token blacklisting (logout)
Implement password reset token functions
Task 2.2: Authentication Service Layer
Create auth.service.js with business logic
Implement login service with password validation
Add token generation logic
Create password reset request handling
Implement password reset confirmation logic
Task 2.3: Authentication Controller and Routes
Create auth.controller.js with request handlers
Implement login endpoint
Add forgot password endpoint
Create reset password endpoint
Implement logout endpoint
Task 2.4: Testing Authentication Module
Write unit tests for auth model functions
Create integration tests for authentication flow
Test password reset functionality
Verify token validation and expiration
Test authentication middleware
Stage 3: User Management Module
Task 3.1: User Database Layer
Create user.queries.js with SQL query templates
Implement user.model.js with CRUD operations
Add functions for user profile management
Create queries for filtering and pagination
Implement soft delete functionality
Task 3.2: User Service Layer
Create user.service.js with business logic
Implement user creation with validation
Add profile update logic
Create password change functionality
Implement user search and filtering
Task 3.3: User Controller and Routes
Create user.controller.js with request handlers
Implement user profile endpoints
Add user management endpoints (admin)
Create password change endpoint
Implement user search and filtering endpoints
Task 3.4: Testing User Module
Write unit tests for user model functions
Create integration tests for user management
Test profile update functionality
Verify search and filtering
Test authorization rules for different user roles
Stage 4: Attendance Module
Task 4.1: Attendance Database Layer
Create attendance.queries.js with SQL query templates
Implement attendance.model.js with check-in/out functions
Add functions for attendance history and reporting
Create queries for filtering and aggregation
Implement functions for active employee tracking
Task 4.2: Attendance Service Layer
Create attendance.service.js with business logic
Implement check-in validation with geofence verification
Add check-out logic with duration calculation
Create attendance summary generation
Implement active employee tracking logic
Task 4.3: Attendance Controller and Routes
Create attendance.controller.js with request handlers
Implement check-in endpoint
Add check-out endpoint
Create attendance history endpoints
Implement attendance summary endpoint
Task 4.4: Testing Attendance Module
Write unit tests for attendance model functions
Create integration tests for check-in/out flow
Test geofence validation during check-in
Verify attendance reporting functionality
Test active employee tracking
Stage 5: Geofence Module
Task 5.1: Geofence Database Layer
Create geofence.queries.js with SQL query templates
Implement geofence.model.js with CRUD operations
Add functions for geofence assignment
Create queries for geofence violations
Implement functions for location validation
Task 5.2: Geofence Service Layer
Create geofence.service.js with business logic
Implement point-in-polygon algorithm for polygon geofences
Add distance calculation for circular geofences
Create violation detection and recording logic
Implement geofence assignment management
Task 5.3: Geofence Controller and Routes
Create geofence.controller.js with request handlers
Implement geofence management endpoints
Add geofence validation endpoint
Create geofence violation endpoints
Implement geofence assignment endpoints
Task 5.4: Testing Geofence Module
Write unit tests for geofence model functions
Create integration tests for geofence validation
Test point-in-polygon algorithm with various shapes
Verify violation detection and recording
Test geofence assignment functionality
Stage 6: Checkpoint and Patrol Module
Task 6.1: Checkpoint Database Layer
Create checkpoint.queries.js with SQL query templates
Implement checkpoint.model.js with CRUD operations
Add functions for checkpoint scanning
Create queries for checkpoint history
Implement functions for QR/barcode validation
Task 6.2: Patrol Database Layer
Create patrol.queries.js with SQL query templates
Implement patrol.model.js with route management
Add functions for patrol assignments
Create queries for patrol status tracking
Implement functions for patrol completion analysis
Task 6.3: Checkpoint and Patrol Service Layer
Create checkpoint.service.js with business logic
Implement patrol.service.js with route management logic
Add checkpoint scanning validation
Create patrol assignment and tracking logic
Implement patrol completion and reporting
Task 6.4: Checkpoint and Patrol Controller and Routes
Create checkpoint.controller.js with request handlers
Implement patrol.controller.js with request handlers
Add checkpoint management endpoints
Create patrol route management endpoints
Implement patrol assignment and tracking endpoints
Task 6.5: Testing Checkpoint and Patrol Module
Write unit tests for checkpoint and patrol model functions
Create integration tests for checkpoint scanning
Test patrol route creation and assignment
Verify patrol tracking and completion
Test checkpoint sequence validation
Stage 7: Task Management Module
Task 7.1: Task Database Layer
Create task.queries.js with SQL query templates
Implement task.model.js with CRUD operations
Add functions for task assignment
Create queries for task filtering and status updates
Implement functions for task completion tracking
Task 7.2: Task Service Layer
Create task.service.js with business logic
Implement task creation and assignment logic
Add task status update validation
Create task filtering and sorting logic
Implement task notification preparation
Task 7.3: Task Controller and Routes
Create task.controller.js with request handlers
Implement task management endpoints
Add task assignment endpoints
Create task status update endpoints
Implement task filtering and search endpoints
Task 7.4: Testing Task Module
Write unit tests for task model functions
Create integration tests for task assignment
Test task status updates
Verify task filtering and search
Test authorization rules for task management
Stage 8: Alert and Alertness Module
Task 8.1: Alert Database Layer
Create alert.queries.js with SQL query templates
Implement alert.model.js with alert creation and management
Add functions for alert status updates
Create queries for alert filtering and reporting
Implement functions for alert settings management
Task 8.2: Alertness Database Layer
Create alertness.queries.js with SQL query templates
Implement alertness.model.js with check scheduling and response
Add functions for alertness history
Create queries for missed checks reporting
Implement functions for alertness settings management
Task 8.3: Alert and Alertness Service Layer
Create alert.service.js with business logic
Implement alertness.service.js with check validation
Add emergency alert handling logic
Create alertness check scheduling logic
Implement alert escalation logic
Task 8.4: Alert and Alertness Controller and Routes
Create alert.controller.js with request handlers
Implement alertness.controller.js with request handlers
Add alert management endpoints
Create alertness check endpoints
Implement emergency alert endpoint
Task 8.5: Testing Alert and Alertness Module
Write unit tests for alert and alertness model functions
Create integration tests for alert creation and management
Test alertness check responses
Verify emergency alert handling
Test alert escalation logic
Stage 9: Location Tracking Module
Task 9.1: Location Database Layer
Create location.queries.js with SQL query templates
Implement location.model.js with location logging
Add functions for location history retrieval
Create queries for current location tracking
Implement functions for location analytics
Task 9.2: Location Service Layer
Create location.service.js with business logic
Implement location update validation
Add geofence checking integration
Create location history analysis logic
Implement battery optimization suggestions
Task 9.3: Location Controller and Routes
Create location.controller.js with request handlers
Implement location update endpoint
Add live location tracking endpoint
Create location history endpoint
Implement location settings endpoint
Task 9.4: Testing Location Module
Write unit tests for location model functions
Create integration tests for location tracking
Test geofence integration
Verify location history retrieval
Test location analytics functions
Stage 10: Report Module
Task 10.1: Report Database Layer
Create report.queries.js with SQL query templates
Implement report.model.js with data aggregation functions
Add functions for attendance reporting
Create queries for geofence violation reporting
Implement functions for patrol completion reporting
Task 10.2: Report Service Layer
Create report.service.js with business logic
Implement report generation logic for different report types
Add CSV export functionality
Create PDF export functionality
Implement report scheduling logic
Task 10.3: Report Controller and Routes
Create report.controller.js with request handlers
Implement report generation endpoints
Add report export endpoints
Create report scheduling endpoints
Implement report template management endpoints
Task 10.4: Testing Report Module
Write unit tests for report model functions
Create integration tests for report generation
Test CSV and PDF export
Verify report data accuracy
Test report scheduling
Stage 11: Dashboard Module
Task 11.1: Dashboard Database Layer
Create dashboard.queries.js with SQL query templates
Implement dashboard.model.js with summary data functions
Add functions for employee dashboard data
Create queries for admin dashboard data
Implement functions for real-time metrics
Task 11.2: Dashboard Service Layer
Create dashboard.service.js with business logic
Implement employee dashboard data aggregation
Add admin dashboard summary generation
Create real-time metrics calculation
Implement dashboard data caching
Task 11.3: Dashboard Controller and Routes
Create dashboard.controller.js with request handlers
Implement employee dashboard endpoint
Add admin dashboard endpoint
Create real-time metrics endpoint
Implement dashboard settings endpoint
Task 11.4: Testing Dashboard Module
Write unit tests for dashboard model functions
Create integration tests for dashboard data retrieval
Test real-time metrics calculation
Verify dashboard data accuracy
Test dashboard performance under load
Stage 12: Admin Module
Task 12.1: Organization Management
Create organization.model.js with CRUD operations
Implement organization.service.js with business logic
Add organization.controller.js with request handlers
Create organization management endpoints
Implement organization settings management
Task 12.2: Site Management
Create site.model.js with CRUD operations
Implement site.service.js with business logic
Add site.controller.js with request handlers
Create site management endpoints
Implement site settings management
Task 12.3: Department and Role Management
Create department.model.js and role.model.js with CRUD operations
Implement corresponding service layers with business logic
Add controller layers with request handlers
Create management endpoints for both entities
Implement permission management for roles
Task 12.4: Shift Management
Create shift.model.js with CRUD operations
Implement shift.service.js with business logic
Add shift.controller.js with request handlers
Create shift management endpoints
Implement shift assignment functionality
Task 12.5: Testing Admin Module
Write unit tests for all admin model functions
Create integration tests for organization hierarchy
Test role and permission management
Verify site and department management
Test shift creation and assignment
Stage 13: Integration and Notification Services
Task 13.1: Firebase Integration
Set up Firebase configuration
Implement firebase.js integration service
Add FCM token management
Create notification sending functions
Implement topic subscription management
Task 13.2: SMS Integration
Set up SMS gateway configuration
Implement sms.js integration service
Add SMS sending functions
Create SMS template management
Implement SMS delivery tracking
Task 13.3: Email Integration
Set up email service configuration
Implement email.js integration service
Add email sending functions
Create email template management
Implement email delivery tracking
Task 13.4: Storage Integration
Set up file storage configuration
Implement storage.js integration service
Add file upload functions
Create file retrieval functions
Implement file permission management
Task 13.5: Testing Integration Services
Write unit tests for all integration services
Create integration tests for notification delivery
Test file upload and retrieval
Verify notification delivery across channels
Test notification preferences management
Stage 14: System Testing and Optimization
Task 14.1: End-to-End Testing
Create test scenarios covering core user journeys
Implement automated API tests for critical flows
Add performance tests for high-load endpoints
Create security tests for authentication and authorization
Implement data validation tests
Task 14.2: Database Optimization
Review and optimize database indexes
Implement query performance monitoring
Add database connection pooling optimization
Create database scaling strategy
Implement data archiving for historical records
Task 14.3: API Performance Optimization
Implement response caching for appropriate endpoints
Add rate limiting for public endpoints
Create compression optimization
Implement request batching for location updates
Add pagination optimization for list endpoints
Task 14.4: Security Hardening
Implement input validation for all endpoints
Add output sanitization
Create security headers configuration
Implement CSRF protection
Add rate limiting for authentication attempts
Task 14.5: Documentation and Deployment
Generate API documentation from code comments
Create deployment scripts
Add environment configuration documentation
Create database migration scripts
Implement CI/CD pipeline configuration
Stage 15: Final Integration and Launch Preparation
Task 15.1: Frontend Integration Support
Create API client examples for mobile app
Add example requests for web dashboard
Create WebSocket integration for real-time features
Implement cross-platform authentication flow
Add example integration tests
Task 15.2: Monitoring and Logging Setup
Implement centralized logging configuration
Add error tracking and alerting
Create performance monitoring
Implement user activity logging
Add audit trail for sensitive operations
Task 15.3: Data Migration Tools
Create data import utilities
Add data export functionality
Implement data validation tools
Create data transformation utilities
Add data cleanup scripts
Task 15.4: Launch Checklist
Create production environment configuration
Add backup and recovery procedures
Implement scaling strategy
Create incident response plan
Add maintenance procedures documentation
Task 15.5: Post-Launch Support
Create monitoring dashboards
Add automated health checks
Implement performance benchmarking
Create support documentation
Add troubleshooting guides
Implementation Sequence and Dependencies
This development plan is designed to be implemented in the sequence presented, as each stage builds upon the previous ones. However, some stages can be worked on in parallel by different team members:
Core Infrastructure (Stage 1) must be completed first as it provides the foundation for all other modules.
Authentication Module (Stage 2) should be implemented early as it's required by all other modules.
User Management (Stage 3) depends on Authentication and should be implemented next.
The following modules can be developed in parallel after Stages 1-3 are complete:
Attendance Module (Stage 4)
Geofence Module (Stage 5)
Checkpoint and Patrol Module (Stage 6)
Task Management Module (Stage 7)
Alert and Alertness Module (Stage 8)
Location Tracking Module (Stage 9)
Report Module (Stage 10) and Dashboard Module (Stage 11) depend on the data from previous modules and should be implemented after them.
Admin Module (Stage 12) can be developed in parallel with Stages 4-9.
Integration Services (Stage 13) should be implemented as needed by other modules.
System Testing and Optimization (Stage 14) and Final Integration (Stage 15) must come last.
Task Assignment Strategy
When assigning these tasks to developers or AI assistants:
Group Related Tasks: Assign all tasks for a specific module to the same developer/team to ensure consistency.
Consider Dependencies: Ensure prerequisites are completed before starting dependent tasks.
Balance Complexity: Mix complex and simpler tasks in each assignment to maintain progress.
Provide Context: Include links to relevant documentation and requirements for each task.
Set Clear Deliverables: Define what "done" means for each task, including testing requirements.
For AI assistants specifically:
Provide Specific Instructions: Include file paths, function names, and expected behavior.
Reference Examples: Point to similar implementations in the codebase for consistency.
Break Down Complex Tasks: Further subdivide tasks if they involve multiple complex steps.
Include Test Cases: Provide example inputs and expected outputs for validation.
Conclusion
This stagewise development plan provides a structured approach to implementing the Yatri Mobile GPS Employee Tracking System backend. By following this plan, development teams can ensure systematic progress, maintain code quality, and deliver a robust solution that meets all requirements.
Conclusion
This comprehensive development guide provides a complete blueprint for implementing the Yatri Mobile GPS-based Employee Tracking System backend. By following the architecture, database design, API specifications, and development plan outlined in this document, developers can build a robust, scalable, and maintainable system that meets all the requirements specified in the project documentation and UI mockups.
The guide emphasizes the use of direct SQL queries through the poolQuery utility rather than an ORM, following the pattern established in the Flying Chital Logistics Management System. This approach provides greater control over database interactions while maintaining a structured and organized codebase.
By breaking down the development process into manageable stages and tasks, this guide facilitates efficient implementation and tracking of progress. Each API endpoint is clearly documented with its purpose, request/response formats, and relationship to specific UI screens, ensuring complete traceability between frontend and backend components.
With this guide as a reference, development teams can proceed with confidence in building a high-quality backend system for the Yatri Mobile GPS-based Employee Tracking System.
