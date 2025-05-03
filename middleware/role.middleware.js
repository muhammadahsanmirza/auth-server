const apiResponse = require('../utils/apiResponse');

const authorize = (roles = []) => {
  if (typeof roles === 'string') {
    roles = [roles];
  }

  return (req, res, next) => {
    if (!req.user) {
      return apiResponse.unauthorized(res, 'User not authenticated');
    }
    if (roles.length && !roles.includes(req.user.role)) {
      return apiResponse.forbidden(res, 'You do not have permission to access this resource');
    }
    next();
  };
};

module.exports = {
  authorize
};