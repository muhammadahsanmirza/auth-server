const success = (res, message, data = null, statusCode = 200) => {
  const response = {
    success: true,
    message,
    ...(data !== null && { data }),
  };
  return res.status(statusCode).json(response);
};

const error = (res, message, errors = null, statusCode = 500) => {
  const response = {
    success: false,
    message,
    ...(errors !== null && { errors }),
  };
  return res.status(statusCode).json(response);
};

const validationError = (res, message = "Validation failed", errors) => {
  return error(res, message, errors, 422);
};

const notFound = (res, message = "Resource not found") => {
  return error(res, message, null, 404);
};

const unauthorized = (res, message = "Unauthorized access") => {
  return error(res, message, null, 401);
};

const forbidden = (res, message = "Forbidden access") => {
  return error(res, message, null, 403);
};

const badRequest = (res, message = "Bad request", errors = null) => {
  return error(res, message, errors, 400);
};

const methodNotAllowed = (res, message = 'Method not allowed') => {
  return res.status(405).json({
    success: false,
    message
  });
};

const conflict = (res, message = "Resource conflict") => {
  return error(res, message, null, 409);
};

const tooManyRequests = (res, message = "Too many requests") => {
  return error(res, message, null, 429);
};

const serverError = (res, message = "Internal server error", errors = null) => {
  return error(res, message, errors, 500);
};

module.exports = {
  success,
  error,
  validationError,
  notFound,
  unauthorized,
  forbidden,
  badRequest,
  methodNotAllowed,
  conflict,
  tooManyRequests,
  serverError
};
