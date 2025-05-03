const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const { protect } = require('../middleware/auth.middleware');
const { rateLimiter } = require('../middleware/rateLimiter.middleware');

router.use(rateLimiter);

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/refresh', authController.refreshToken);
router.post('/logout', authController.logout);
router.get('/user', protect, authController.getUserProfile);

module.exports = router;