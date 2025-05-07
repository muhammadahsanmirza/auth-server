const express = require('express');
const router = express.Router();
const usersController = require('../controllers/users.controller');
const { protect } = require('../middleware/auth.middleware');
const { authorize } = require('../middleware/role.middleware');
const { rateLimiter } = require('../middleware/rateLimiter.middleware');

router.use(rateLimiter);
router.use(protect); // All routes require authentication

// Admin-only routes
router.get('/', authorize('admin'), usersController.getAllUsers);
router.patch('/role', authorize('admin'), usersController.updateUserRole);

module.exports = router;