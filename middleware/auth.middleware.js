const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const apiResponse = require('../utils/apiResponse');

/**
 * Middleware to protect routes that require authentication
 * Verifies the JWT token from the request
 */
const protect = async (req, res, next) => {
  try {
    let token;

    // Check for token in cookies first (for browser clients)
    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    } 
    // Then check Authorization header (for API clients)
    else if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }

    // If no token found, return unauthorized
    if (!token) {
      return apiResponse.unauthorized(res, 'Not authorized, no token provided');
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Get user from database - explicitly select the active field
    const user = await User.findById(decoded.id).select('+active');
    
    // Check if user exists
    if (!user) {
      return apiResponse.unauthorized(res, 'User not found');
    }

    // Check if user is active
    if (!user.active) {
      return apiResponse.unauthorized(res, 'User account is deactivated');
    }

    // Add user to request object
    req.user = user;
    
    // Continue to the next middleware or route handler
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return apiResponse.unauthorized(res, 'Invalid token');
    }
    if (error.name === 'TokenExpiredError') {
      return apiResponse.unauthorized(res, 'Token expired');
    }
    return apiResponse.serverError(res, 'Authentication error', error);
  }
};

module.exports = { protect };