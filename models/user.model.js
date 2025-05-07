const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  Name: {
    type: String,
    required: [true, "Name is required"],
    trim: true,
    minlength: [2, "Name must be at least 2 characters long"],
    maxlength: [50, "Name cannot exceed 50 characters"],
    validate: {
      validator: function (v) {
        return !/^\d/.test(v);
      },
      message: (props) => "Name cannot start with a number",
    },
  },
  password: {
    type: String,
    required: function() {
      // Only require password for local authentication
      return this.authProvider === 'local' || !this.authProvider;
    }
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
    lowercase: true,
    trim: true,
    match: [
      /^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/,
      "Please provide a valid email address",
    ],
  },
  role: {
    type: String,
    enum: ['admin', 'manager', 'user'],
    default: 'user'
  },
  authProvider: {
    type: String,
    required: true,
    enum: ["local", "auth0", "keycloak"],
    default: "local",
  },
  providerId: {
    type: String,
    required: function () {
      return this.authProvider !== "local";
    },
    unique: true,
    sparse: true,
  },
  active: {
    type: Boolean,
    default: true,
    select: false,
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date
  }
},
{
  timestamps: true,
}
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  try {
    const salt = await bcrypt.genSalt(
      Number(process.env.BCRYPT_SALT_ROUNDS) || 12
    );
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.toJSON = function () {
  const userObject = this.toObject();
  delete userObject.password;
  delete userObject.__v;
  return userObject;
};

userSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

userSchema.methods.incrementLoginAttempts = async function() {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    this.loginAttempts = 1;
    this.lockUntil = undefined;
  } else {
    this.loginAttempts += 1;
    
    if (this.loginAttempts >= 5 && !this.lockUntil) {
      this.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
    }
  }
  
  return this.save();
};

const User = mongoose.model("User", userSchema);

module.exports = User;