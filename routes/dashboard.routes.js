const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth.middleware');
const { authorize } = require('../middleware/role.middleware');
const apiResponse = require('../utils/apiResponse');

/**
 * @route   GET /api/v1/dashboard/admin
 * @desc    Admin dashboard
 * @access  Private/Admin
 */
router.get('/admin', protect, authorize('admin'), (req, res) => {
  return apiResponse.success(res, 'Admin dashboard data', {
    dashboardType: 'admin',
    features: [
      'User Management',
      'Role Management',
      'System Configuration',
      'Audit Logs',
      'Analytics'
    ]
  });
});

/**
 * @route   GET /api/v1/dashboard/manager
 * @desc    Manager dashboard
 * @access  Private/Manager
 */
router.get('/manager', protect, authorize('manager'), (req, res) => {
  return apiResponse.success(res, 'Manager dashboard data', {
    dashboardType: 'manager',
    features: [
      'Team Management',
      'Project Overview',
      'Task Assignment',
      'Reports'
    ]
  });
});

/**
 * @route   GET /api/v1/dashboard/user
 * @desc    User dashboard
 * @access  Private/User
 */
router.get('/user', protect, authorize(['user', 'manager', 'admin']), (req, res) => {
  return apiResponse.success(res, 'User dashboard data', {
    dashboardType: 'user',
    features: [
      'Profile',
      'Tasks',
      'Notifications',
      'Messages'
    ]
  });
});

module.exports = router;