const User = require("../models/user.model");
const apiResponse = require("../utils/apiResponse");
const jwt = require("jsonwebtoken");
const crypto = require('crypto'); // Add this line to import the crypto module
require("dotenv").config();
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} = require("../utils/jwt.utils");

const signup = async (req, res) => {
  console.log('[AUTH_CONTROLLER] Starting signup process');
  console.log('[AUTH_CONTROLLER] Request body:', {
    Name: req.body.Name,
    email: req.body.email,
    password: req.body.password ? '******' : undefined,
    role: req.body.role
  });
  console.log('[AUTH_CONTROLLER] Request headers:', {
    origin: req.headers.origin,
    'content-type': req.headers['content-type'],
    'user-agent': req.headers['user-agent']
  });
  
  try {
    const { Name, email, password, role } = req.body;
    console.log('[AUTH_CONTROLLER] Checking if user exists with email:', email);

    const userExists = await User.findOne({ email });
    if (userExists) {
      console.log('[AUTH_CONTROLLER] User already exists with email:', email);
      return apiResponse.conflict(res, "User with this email already exists");
    }

    console.log('[AUTH_CONTROLLER] Creating new user with email:', email);
    const user = await User.create({
      Name,
      email,
      password,
      role: role || "user",
      authProvider: "local",
      providerId: `local_${email}`, // Make providerId unique by combining with email
    });
    console.log('[AUTH_CONTROLLER] User created successfully with ID:', user._id);

    console.log('[AUTH_CONTROLLER] Generating tokens');
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Set cookies if possible (for same-origin requests)
    if (req.headers.origin === process.env.FRONTEND_URL || !req.headers.origin) {
      console.log('[AUTH_CONTROLLER] Setting cookies for same-origin request');
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        secure: process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true',
        sameSite: "strict",
      });

      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        maxAge: 60 * 60 * 1000, // 1 hour
        secure: process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true',
        sameSite: "strict",
      });
    } else {
      console.log('[AUTH_CONTROLLER] Cross-origin request detected, not setting cookies');
      console.log('[AUTH_CONTROLLER] Request origin:', req.headers.origin);
      console.log('[AUTH_CONTROLLER] Expected origin:', process.env.FRONTEND_URL);
    }

    console.log('[AUTH_CONTROLLER] Signup successful, returning response');
    // Always include tokens in the response body for frontend clients
    return apiResponse.success(
      res,
      "User registered successfully",
      {
        user,
        tokens: {
          accessToken,
          refreshToken
        }
      },
      201
    );
  } catch (error) {
    console.error('[AUTH_CONTROLLER] Error in signup process:', error);
    console.error('[AUTH_CONTROLLER] Error name:', error.name);
    console.error('[AUTH_CONTROLLER] Error message:', error.message);
    console.error('[AUTH_CONTROLLER] Error stack:', error.stack);
    
    if (error.name === "ValidationError") {
      console.error('[AUTH_CONTROLLER] Validation error details:', error.errors);
      return apiResponse.validationError(
        res,
        "Validation failed",
        error.errors
      );
    }
    return apiResponse.serverError(res, "Error registering user", error);
  }
};

const login = async (req, res) => {
  console.log('[AUTH_CONTROLLER] Starting login process');
  console.log('[AUTH_CONTROLLER] Login attempt for email:', req.body.email);
  
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      console.log('[AUTH_CONTROLLER] Missing email or password');
      return apiResponse.badRequest(res, "Please provide email and password");
    }
    
    console.log('[AUTH_CONTROLLER] Finding user with email:', email);
    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      console.log('[AUTH_CONTROLLER] User not found with email:', email);
      return apiResponse.unauthorized(res, "Invalid credentials");
    }
    
    console.log('[AUTH_CONTROLLER] Checking if account is locked');
    if (user.isLocked()) {
      console.log('[AUTH_CONTROLLER] Account is locked for user:', email);
      return apiResponse.unauthorized(
        res,
        "Account is locked due to too many failed attempts. Try again later."
      );
    }
    
    console.log('[AUTH_CONTROLLER] Comparing password');
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      console.log('[AUTH_CONTROLLER] Invalid password for user:', email);
      await user.incrementLoginAttempts();
      return apiResponse.unauthorized(res, "Invalid credentials");
    }
    
    console.log('[AUTH_CONTROLLER] Password matched, resetting login attempts');
    await User.findByIdAndUpdate(user._id, {
      $set: { loginAttempts: 0, lockUntil: null },
    });
    
    console.log('[AUTH_CONTROLLER] Generating tokens');
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    console.log('[AUTH_CONTROLLER] Setting cookies');
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      secure:
        process.env.NODE_ENV === "production" ||
        process.env.COOKIE_SECURE === "true",
      sameSite: "strict",
    });

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      maxAge: 60 * 60 * 1000, // 1 hour
      secure:
        process.env.NODE_ENV === "production" ||
        process.env.COOKIE_SECURE === "true",
      sameSite: "strict",
    });
    
    console.log('[AUTH_CONTROLLER] Login successful for user:', email);
    return apiResponse.success(res, "Login successful", {
      user,
    });
  } catch (error) {
    console.error('[AUTH_CONTROLLER] Error in login process:', error);
    console.error('[AUTH_CONTROLLER] Error stack:', error.stack);
    return apiResponse.serverError(res, "Error logging in");
  }
};

const logout = async (req, res) => {
  try {
    res.clearCookie("refreshToken");
    res.clearCookie("accessToken");

    return apiResponse.success(res, "Logged out successfully");
  } catch (error) {
    return apiResponse.serverError(res, "Error logging out");
  }
};

const refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!refreshToken) {
      return apiResponse.unauthorized(res, "Refresh token not provided");
    }

    const decoded = verifyRefreshToken(refreshToken);
    const user = await User.findById(decoded.id);
    if (!user) {
      return apiResponse.unauthorized(res, "User not found");
    }

    const accessToken = generateAccessToken(user);

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      maxAge: 60 * 60 * 1000, // 1 hour
      secure:
        process.env.NODE_ENV === "production" ||
        process.env.COOKIE_SECURE === "true",
      sameSite: "strict",
    });

    return apiResponse.success(res, "Token refreshed successfully");
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return apiResponse.unauthorized(res, "Invalid refresh token");
    }
    if (error.name === "TokenExpiredError") {
      return apiResponse.unauthorized(res, "Refresh token expired");
    }
    return apiResponse.serverError(res, "Error refreshing token", error);
  }
};

const getUserProfile = async (req, res) => {
  try {
    return apiResponse.success(res, "User profile retrieved successfully", {
      user: req.user,
    });
  } catch (error) {
    return apiResponse.serverError(res, "Error retrieving user profile", error);
  }
};

// In your syncKeycloakUser function
const syncKeycloakUser = async (req, res) => {
  try {
    console.log('[AUTH_CONTROLLER] Processing Keycloak user sync request');
    const { keycloakUser } = req.body;
    
    if (!keycloakUser || !keycloakUser.id) {
      console.log('[AUTH_CONTROLLER] Invalid Keycloak user data:', keycloakUser);
      return apiResponse.badRequest(res, 'Invalid Keycloak user data');
    }
    
    console.log('[AUTH_CONTROLLER] Keycloak user data:', {
      id: keycloakUser.id,
      email: keycloakUser.email,
      firstName: keycloakUser.firstName,
      lastName: keycloakUser.lastName
    });
    
    // First try to find user by providerId
    console.log('[AUTH_CONTROLLER] Finding user by providerId:', keycloakUser.id);
    let user = await User.findOne({ providerId: keycloakUser.id });
    
    // If not found by providerId, try to find by email
    if (!user && keycloakUser.email) {
      console.log(`[AUTH_CONTROLLER] User not found by providerId, checking email: ${keycloakUser.email}`);
      user = await User.findOne({ email: keycloakUser.email });
      
      // If found by email, update the providerId to link accounts
      if (user) {
        console.log(`[AUTH_CONTROLLER] Found existing user by email, updating providerId`);
        user.providerId = keycloakUser.id;
        user.authProvider = 'keycloak'; // Update auth provider to keycloak
      }
    }
    
    // If user still not found, create a new one
    if (!user) {
      console.log('[AUTH_CONTROLLER] User not found, creating new user');
      
      try {
        // Generate random password
        console.log('[AUTH_CONTROLLER] Generating random password');
        const randomPassword = crypto.randomBytes(16).toString('hex');
        
        // Create new user data
        const userData = {
          Name: `${keycloakUser.firstName} ${keycloakUser.lastName}`,
          email: keycloakUser.email,
          authProvider: 'keycloak',
          providerId: keycloakUser.id,
          role: keycloakUser.role || 'user',
          active: true,
          emailVerified: keycloakUser.emailVerified || false,
          // Add a random password for Keycloak users
          password: randomPassword
        };
        
        console.log('[AUTH_CONTROLLER] Creating new user with data:', {
          ...userData,
          password: '******'
        });
        
        user = new User(userData);
      } catch (cryptoError) {
        console.error('[AUTH_CONTROLLER] Error generating random password:', cryptoError);
        console.error('[AUTH_CONTROLLER] Crypto error details:', {
          name: cryptoError.name,
          message: cryptoError.message,
          stack: cryptoError.stack
        });
        throw cryptoError;
      }
    } else {
      // Update existing user with latest info from Keycloak
      console.log('[AUTH_CONTROLLER] Updating existing user with Keycloak data');
      user.Name = `${keycloakUser.firstName} ${keycloakUser.lastName}`;
      user.email = keycloakUser.email;
      user.role = keycloakUser.role || user.role || 'user';
      user.emailVerified = keycloakUser.emailVerified || user.emailVerified || false;
    }
    
    // Save the user (whether new or updated)
    console.log('[AUTH_CONTROLLER] Saving user');
    await user.save();
    
    console.log(`[AUTH_CONTROLLER] User synced successfully: ${user._id}`);
    
    return apiResponse.success(res, 'User synced successfully', {
      user: {
        id: user._id,
        name: user.Name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('[AUTH_CONTROLLER] Error syncing Keycloak user:', error);
    console.error('[AUTH_CONTROLLER] Error name:', error.name);
    console.error('[AUTH_CONTROLLER] Error message:', error.message);
    console.error('[AUTH_CONTROLLER] Error stack:', error.stack);
    return apiResponse.serverError(res, 'Error syncing Keycloak user');
  }
};

module.exports = {
  signup,
  login,
  refreshToken,
  getUserProfile,
  logout,
  syncKeycloakUser
};
