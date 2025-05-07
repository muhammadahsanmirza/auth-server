const User = require("../models/user.model");
const apiResponse = require("../utils/apiResponse");

// Get all users - only accessible by admin
const getAllUsers = async (req, res) => {
  try {
    console.log('[USERS_CONTROLLER] Getting all users');
    
    // Fetch all users but exclude password field
    const users = await User.find().select('-password');
    
    console.log(`[USERS_CONTROLLER] Found ${users.length} users`);
    
    return apiResponse.success(
      res,
      "Users retrieved successfully",
      { users }
    );
  } catch (error) {
    console.error('[USERS_CONTROLLER] Error getting users:', error);
    return apiResponse.serverError(res, "Error retrieving users", error);
  }
};

// Update user role - only accessible by admin
const updateUserRole = async (req, res) => {
  try {
    const { userId, role } = req.body;
    
    console.log(`[USERS_CONTROLLER] Updating role for user ${userId} to ${role}`);
    
    if (!userId || !role) {
      return apiResponse.badRequest(res, "User ID and role are required");
    }
    
    // Validate role
    const validRoles = ['user', 'manager', 'admin'];
    if (!validRoles.includes(role)) {
      return apiResponse.badRequest(res, "Invalid role. Role must be one of: user, manager, admin");
    }
    
    // Find user and update role
    const user = await User.findById(userId);
    
    if (!user) {
      return apiResponse.notFound(res, "User not found");
    }
    
    // Update user role
    user.role = role;
    await user.save();
    
    console.log(`[USERS_CONTROLLER] Successfully updated role for user ${userId} to ${role}`);
    
    return apiResponse.success(
      res,
      "User role updated successfully",
      { user: { _id: user._id, Name: user.Name, email: user.email, role: user.role } }
    );
  } catch (error) {
    console.error('[USERS_CONTROLLER] Error updating user role:', error);
    return apiResponse.serverError(res, "Error updating user role", error);
  }
};

module.exports = {
  getAllUsers,
  updateUserRole
};