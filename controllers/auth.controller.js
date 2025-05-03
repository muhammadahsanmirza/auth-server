const User = require("../models/user.model");
const apiResponse = require("../utils/apiResponse");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} = require("../utils/jwt.utils");

const signup = async (req, res) => {
  try {
    const { Name, email, password, role } = req.body;

    const userExists = await User.findOne({ email });
    if (userExists) {
      return apiResponse.conflict(res, "User with this email already exists");
    }

    const user = await User.create({
      Name,
      email,
      password,
      role: role || "user",
      authProvider: "local",
      providerId: "local",
    });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

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

    return apiResponse.success(
      res,
      "User registered successfully",
      {
        user,
      },
      201
    );
  } catch (error) {
    if (error.name === "ValidationError") {
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
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return apiResponse.badRequest(res, "Please provide email and password");
    }
    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return apiResponse.unauthorized(res, "Invalid credentials");
    }
    if (user.isLocked()) {
      return apiResponse.unauthorized(
        res,
        "Account is locked due to too many failed attempts. Try again later."
      );
    }
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      await user.incrementLoginAttempts();
      return apiResponse.unauthorized(res, "Invalid credentials");
    }
    await User.findByIdAndUpdate(user._id, {
      $set: { loginAttempts: 0, lockUntil: null },
    });
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

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
    return apiResponse.success(res, "Login successful", {
      user,
    });
  } catch (error) {
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

module.exports = {
  signup,
  login,
  refreshToken,
  getUserProfile,
  logout,
};
