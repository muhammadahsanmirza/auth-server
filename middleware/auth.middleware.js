const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const apiResponse = require('../utils/apiResponse');

const protect = async (req, res, next) => {
  try {
    let token;
    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }
    else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return apiResponse.unauthorized(res, 'Not authorized, no token provided');
    }

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