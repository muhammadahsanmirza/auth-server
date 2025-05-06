const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const apiResponse = require('../utils/apiResponse');
const { keycloakAuth } = require('./keycloak.middleware');

const protect = async (req, res, next) => {
  try {
    let token;
    let authType = 'local';
    
    // Check for token in cookies or Authorization header
    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }
    else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
      
      // Check if this is a Keycloak token
      try {
        const decoded = jwt.decode(token);
        if (decoded && decoded.iss && decoded.iss.includes('keycloak')) {
          authType = 'keycloak';
        }
      } catch (error) {
        // If we can't decode the token, assume it's a local token
      }
    }

    if (!token) {
      return apiResponse.unauthorized(res, 'Not authorized, no token provided');
    }

    // Handle based on auth type
    if (authType === 'keycloak') {
      return keycloakAuth(req, res, next);
    }
    
    // Local JWT authentication
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("+active");
    if (!user) {
      return apiResponse.unauthorized(res, 'User not found');
    }
    if (!user.active) {
      return apiResponse.unauthorized(res, 'User account is deactivated');
    }

    req.user = user;
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

module.exports = {
  protect
};