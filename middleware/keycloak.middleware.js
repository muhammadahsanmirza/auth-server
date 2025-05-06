const jwt = require('jsonwebtoken');
const axios = require('axios');
const User = require('../models/user.model');
const apiResponse = require('../utils/apiResponse');

// Cache for the public key to avoid fetching it on every request
let publicKey = null;
let publicKeyLastFetched = null;
const PUBLIC_KEY_CACHE_TIME = 3600000; // 1 hour

const fetchPublicKey = async () => {
  try {
    // Check if we need to fetch the public key
    const now = Date.now();
    if (publicKey && publicKeyLastFetched && (now - publicKeyLastFetched < PUBLIC_KEY_CACHE_TIME)) {
      return publicKey;
    }

    // Fetch the public key from Keycloak
    const response = await axios.get(
      `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/certs`
    );
    
    // Get the RSA public key from the response
    const key = response.data.keys[0];
    publicKey = `-----BEGIN PUBLIC KEY-----\n${key.n}\n-----END PUBLIC KEY-----`;
    publicKeyLastFetched = now;
    
    return publicKey;
  } catch (error) {
    console.error('Error fetching Keycloak public key:', error);
    throw error;
  }
};

const verifyKeycloakToken = async (token) => {
  try {
    const key = await fetchPublicKey();
    return jwt.verify(token, key, { algorithms: ['RS256'] });
  } catch (error) {
    console.error('Error verifying Keycloak token:', error);
    throw error;
  }
};

const keycloakAuth = async (req, res, next) => {
  try {
    let token;
    
    // Extract token from Authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    
    if (!token) {
      return apiResponse.unauthorized(res, 'Not authorized, no token provided');
    }
    
    // Verify the Keycloak token
    const decoded = await verifyKeycloakToken(token);
    
    // Find or create user in our database
    let user = await User.findOne({ providerId: decoded.sub });
    
    if (!user) {
      // Create a new user with Keycloak data
      user = await User.create({
        name: decoded.name || `${decoded.given_name} ${decoded.family_name}`,
        email: decoded.email,
        authProvider: 'keycloak',
        providerId: decoded.sub,
        role: 'user', // Default role for new users
        active: true,
        emailVerified: decoded.email_verified || false
      });
    }
    
    // Update user info if needed
    if (user.name !== decoded.name || user.email !== decoded.email) {
      user.name = decoded.name || `${decoded.given_name} ${decoded.family_name}`;
      user.email = decoded.email;
      user.emailVerified = decoded.email_verified || user.emailVerified;
      await user.save();
    }
    
    // Attach user to request
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
  keycloakAuth
};