require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const twilio = require('twilio');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const http = require('http');
const { Server } = require('socket.io');
const schedule = require('node-schedule');
const MenuItem = require('./models/MenuItem');
const DailyInventory = require('./models/DailyInventory');
const QRCodeLib = require('qrcode');

const app = express();
const server = http.createServer(app);

// Define allowed origins (both HTTP and HTTPS for localhost and production domains)
const allowedOrigins = [
  'http://localhost:8080',
  'https://localhost:8080',
  'https://server-food-court.onrender.com',
  'https://14-prasanna.github.io/Food_Court',
  'https://14-prasanna.github.io',
  'https://14-prasanna.github.io/Kiot-Admin/'
];

const normalizeOrigin = (origin) => {
  if (!origin) return origin;
  return origin.replace(/\/+$/, ''); // Remove trailing slashes
};

// CORS configuration for Socket.IO
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      const normalizedOrigin = normalizeOrigin(origin);
      if (!origin || allowedOrigins.includes(normalizedOrigin)) {
        callback(null, true);
      } else {
        console.log('CORS rejected origin:', origin); // Debugging log
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  },
});

// CORS configuration for Express
app.use(cors({
  origin: (origin, callback) => {
    const normalizedOrigin = normalizeOrigin(origin);
    if (!origin || allowedOrigins.includes(normalizedOrigin)) {
      callback(null, true);
    } else {
      console.log('CORS rejected origin:', origin); // Debugging log
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));

app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  tls: true,
  tlsAllowInvalidCertificates: false,
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema (for customers)
const userSchema = new mongoose.Schema({
  phone: { type: String, required: true, unique: true },
  name: String,
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', userSchema);

// Admin Schema
const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Admin = mongoose.model('Admin', adminSchema);

// Order Schema
const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  studentName: String,
  studentEmail: String,
  studentPhone: String,
  items: [
    {
      id: String,
      name: String,
      price: Number,
      quantity: Number,
      serviceType: String,
    },
  ],
  totalAmount: Number,
  paymentMethod: String,
  status: { type: String, default: 'pending' },
  razorpay_order_id: String,
  razorpay_payment_id: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
const Order = mongoose.model('Order', orderSchema);

// OTP Schema
const otpSchema = new mongoose.Schema({
  phone: { type: String, required: true },
  otp: { type: String, required: true },
  type: { type: String, default: 'user' },
  createdAt: { type: Date, default: Date.now, expires: 300 },
});
const OTP = mongoose.model('OTP', otpSchema);

// Razorpay Instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Twilio Client
const twilioClient = new twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// Helper function to normalize phone number
function normalizePhone(phone) {
  let normalized = phone.replace(/\s+/g, '');
  if (!normalized.startsWith('+')) {
    normalized = '+91' + normalized;
  }
  return normalized;
}

// Socket.IO Connection Handling
io.on('connection', (socket) => {
  console.log('A client connected:', socket.id);

  socket.on('joinAdmin', () => {
    socket.join('adminRoom');
    console.log('Client joined adminRoom:', socket.id);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Helper function to get IST date
const getISTDate = () => {
  const now = new Date();
  const offsetIST = 5.5 * 60 * 60 * 1000; // IST is UTC+5:30
  const istDate = new Date(now.getTime() + offsetIST);
  return new Date(istDate.getFullYear(), istDate.getMonth(), istDate.getDate());
};

// Reset inventory quantities at midnight IST
schedule.scheduleJob('0 0 0 * * *', async () => {
  try {
    const today = getISTDate();
    const menuItems = await MenuItem.find();
    for (const menuItem of menuItems) {
      await DailyInventory.findOneAndUpdate(
        { menuItemId: menuItem._id, date: today },
        { quantity: 0 },
        { upsert: true }
      );
    }
    console.log('Inventory quantities reset at midnight IST');
    io.emit('inventoryReset');
  } catch (error) {
    console.error('Error resetting inventory:', error);
  }
});

// Deactivate all menu items at 3:30 PM IST
schedule.scheduleJob('30 15 * * *', async () => {
  try {
    const today = getISTDate();
    console.log(`Deactivating all menu items at 3:30 PM IST on ${today}`);
    
    const result = await MenuItem.updateMany(
      {},
      { isActive: false, updatedAt: Date.now() }
    );
    
    console.log(`Deactivated ${result.modifiedCount} menu items`);

    const updatedMenuItems = await MenuItem.find();
    io.emit('menuItemsDeactivated', updatedMenuItems);
  } catch (error) {
    console.error('Error deactivating menu items at 3:30 PM IST:', error);
  }
});

// Admin Order Fetch Endpoint
app.get('/admin/order', async (req, res) => {
  try {
    const { startDate, endDate, status } = req.query;

    let query = {};
    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate),
      };
    }
    if (status) {
      query.status = status;
    }

    const orders = await Order.find(query).sort({ createdAt: -1 });
    res.json({ status: 'success', orders });
  } catch (error) {
    console.error('Fetch admin orders error:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Update Order Status
app.put('/admin/order/:orderId', async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;

    if (!status || !['pending', 'completed', 'cancelled'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const order = await Order.findOneAndUpdate(
      { orderId },
      { status, updatedAt: new Date() },
      { new: true, runValidators: true }
    );

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    io.to('adminRoom').emit('orderUpdated', order);

    if (status === 'completed') {
      await twilioClient.messages.create({
        body: `Your order ID ${order.orderId} is complete. You received your food. Enjoy your meal! 🙂‍↕️🤗`,
        to: order.studentPhone,
        from: process.env.TWILIO_PHONE_NUMBER,
      });
    } else if (status === 'cancelled') {
      await twilioClient.messages.create({
        body: `Sorry, ${order.studentName}! Your order ${order.orderId} has been cancelled.`,
        to: order.studentPhone,
        from: process.env.TWILIO_PHONE_NUMBER,
      });
    }

    res.json({ status: 'success', order });
  } catch (error) {
    console.error('Update order status error:', error);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

// Check if admin exists
app.post('/admin/check', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) {
      return res.status(400).json({ error: 'Phone number is required' });
    }

    const normalizedPhone = normalizePhone(phone);

    const admin = await Admin.findOne({ phone: normalizedPhone });
    if (admin) {
      res.json({ status: 'success', exists: true });
    } else {
      res.json({ status: 'success', exists: false });
    }
  } catch (error) {
    console.error('Check admin error:', error);
    res.status(500).json({ error: 'Failed to check admin' });
  }
});

// Register Admin
app.post('/admin/register', async (req, res) => {
  const { name, email, phone, password, confirmPassword } = req.body;
  if (!name || !email || !phone || !password || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  const normalizedPhone = normalizePhone(phone);

  try {
    const existingAdmin = await Admin.findOne({ $or: [{ email }, { phone: normalizedPhone }] });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin with this email or phone already exists' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await OTP.create({ phone: normalizedPhone, otp, type: 'admin' });
    await twilioClient.messages.create({
      body: `Your OTP for Menu Pulse Admin registration is ${otp}. Valid for 5 minutes.`,
      to: normalizedPhone,
      from: process.env.TWILIO_PHONE_NUMBER,
    });

    res.json({ status: 'success', message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Admin register error:', error);
    res.status(500).json({ error: 'Failed to register admin' });
  }
});

// Verify Admin Registration OTP
app.post('/admin/verify-register', async (req, res) => {
  const { phone, otp, name, email, password } = req.body;
  if (!phone || !otp || !name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const normalizedPhone = normalizePhone(phone);

  try {
    const otpRecord = await OTP.findOne({ phone: normalizedPhone, otp, type: 'admin' });
    if (!otpRecord) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await Admin.create({
      name,
      email,
      phone: normalizedPhone,
      password: hashedPassword,
    });

    await OTP.deleteOne({ phone: normalizedPhone, otp });

    res.json({ status: 'success', message: 'Admin registered successfully' });
  } catch (error) {
    console.error('Verify admin register error:', error);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

// Admin Login Send OTP
app.post('/admin/send-otp', async (req, res) => {
  const { phone } = req.body;
  if (!phone) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  const normalizedPhone = normalizePhone(phone);

  try {
    const admin = await Admin.findOne({ phone: normalizedPhone });
    if (!admin) {
      return res.status(400).json({ error: 'Admin not found' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.create({ phone: normalizedPhone, otp, type: 'admin' });
    await twilioClient.messages.create({
      body: `Your OTP for Menu Pulse Admin login is ${otp}. Valid for 5 minutes.`,
      to: normalizedPhone,
      from: process.env.TWILIO_PHONE_NUMBER,
    });

    res.json({ status: 'success', message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Admin send OTP error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Admin Login Verify OTP
app.post('/admin/verify-otp', async (req, res) => {
  console.log('Received admin verify OTP request:', req.body);
  const { phone, otp } = req.body;
  if (!phone || !otp) {
    return res.status(400).json({ error: 'Phone number and OTP are required' });
  }

  const normalizedPhone = normalizePhone(phone);

  try {
    const otpRecord = await OTP.findOne({ phone: normalizedPhone, otp, type: 'admin' });
    if (!otpRecord) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    const admin = await Admin.findOne({ phone: normalizedPhone });
    if (!admin) {
      return res.status(400).json({ error: 'Admin not found' });
    }

    await OTP.deleteOne({ phone: normalizedPhone, otp });

    // Generate a dummy token (you can replace this with a real JWT if needed)
    const token = crypto.randomBytes(32).toString('hex');

    res.json({ 
      status: 'success', 
      user: { name: admin.name, email: admin.email, phone: admin.phone, role: 'admin' },
      token 
    });
  } catch (error) {
    console.error('Admin verify OTP error:', error);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

// Check if any admin exists
app.get('/admin/check-any', async (req, res) => {
  try {
    const admin = await Admin.findOne();
    if (admin) {
      res.json({ status: 'success', exists: true, phone: admin.phone });
    } else {
      res.json({ status: 'success', exists: false });
    }
  } catch (error) {
    console.error('Check any admin error:', error);
    res.status(500).json({ error: 'Failed to check admin existence' });
  }
});

// Delete Admin
app.delete('/admin/delete', async (req, res) => {
  const { phone } = req.body;
  if (!phone) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  const normalizedPhone = normalizePhone(phone);

  try {
    const admin = await Admin.findOneAndDelete({ phone: normalizedPhone });
    if (!admin) {
      return res.status(400).json({ error: 'Admin not found' });
    }

    res.json({ status: 'success', message: 'Admin account deleted successfully' });
  } catch (error) {
    console.error('Delete admin error:', error);
    res.status(500).json({ error: 'Failed to delete admin' });
  }
});

// Fetch Admin Profile
app.post('/admin/profile', async (req, res) => {
  console.log('Received profile request:', req.body);
  const { phone } = req.body;
  if (!phone) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  try {
    const admin = await Admin.findOne({ phone });
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    res.json({
      status: 'success',
      user: {
        name: admin.name,
        email: admin.email,
        phone: admin.phone,
        role: 'admin'
      },
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update Admin Profile
app.post('/admin/update-profile', async (req, res) => {
  const { phone, name, email } = req.body;
  if (!phone || !name || !email) {
    return res.status(400).json({ status: 'error', error: 'Phone, name, and email are required' });
  }

  const normalizedPhone = normalizePhone(phone);

  try {
    const admin = await Admin.findOneAndUpdate(
      { phone: normalizedPhone },
      { name, email },
      { new: true, runValidators: true }
    );
    if (admin) {
      res.json({ 
        status: 'success', 
        user: { name: admin.name, email: admin.email, phone: admin.phone, role: 'admin' } 
      });
    } else {
      res.status(404).json({ status: 'error', error: 'Admin not found' });
    }
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ status: 'error', error: 'Failed to update profile' });
  }
});

// Update Admin Password
app.post('/admin/update-password', async (req, res) => {
  const { phone, currentPassword, newPassword } = req.body;
  if (!phone || !currentPassword || !newPassword) {
    return res.status(400).json({ status: 'error', error: 'All fields are required' });
  }

  const normalizedPhone = normalizePhone(phone);

  try {
    const admin = await Admin.findOne({ phone: normalizedPhone });
    if (!admin) {
      return res.status(404).json({ status: 'error', error: 'Admin not found' });
    }

    const isMatch = await bcrypt.compare(currentPassword, admin.password);
    if (!isMatch) {
      return res.status(400).json({ status: 'error', error: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    admin.password = hashedPassword;
    await admin.save();

    res.json({ status: 'success', message: 'Password updated successfully' });
  } catch (error) {
    console.error('Update password error:', error);
    res.status(500).json({ status: 'error', error: 'Failed to update password' });
  }
});

// Send OTP (for customers and admins)
app.post('/send-otp', async (req, res) => {
  const { phone, role = 'user' } = req.body;
  if (!phone) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  const normalizedPhone = normalizePhone(phone);
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpType = role === 'admin' ? 'admin' : 'user';

  try {
    await OTP.create({ phone: normalizedPhone, otp, type: otpType });
    await twilioClient.messages.create({
      body: `Your OTP for ${role === 'admin' ? 'Menu Pulse Admin' : 'Food Court'} login is ${otp}. Valid for 5 minutes.`,
      to: normalizedPhone,
      from: process.env.TWILIO_PHONE_NUMBER,
    });

    res.json({ status: 'success', message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP (for customers and admins)
app.post('/verify-otp', async (req, res) => {
  console.log('Received verify OTP request:', req.body); // Debugging log
  const { phone, otp, name, role = 'user' } = req.body;
  if (!phone || !otp) {
    return res.status(400).json({ error: 'Phone number and OTP are required' });
  }

  const normalizedPhone = normalizePhone(phone);
  const otpType = role === 'admin' ? 'admin' : 'user';

  try {
    const otpRecord = await OTP.findOne({ phone: normalizedPhone, otp, type: otpType });
    if (!otpRecord) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    let user;
    if (otpType === 'user') {
      user = await User.findOne({ phone: normalizedPhone });
      if (!user) {
        user = await User.create({ phone: normalizedPhone, name });
      } else if (name && user.name !== name) {
        user.name = name;
        await user.save();
      }
      // Generate a dummy token (replace with real JWT if needed)
      const token = crypto.randomBytes(32).toString('hex');
      res.json({ 
        status: 'success', 
        user: { phone: user.phone, name: user.name, role: 'customer' },
        token 
      });
    } else if (otpType === 'admin') {
      user = await Admin.findOne({ phone: normalizedPhone });
      if (!user) {
        return res.status(400).json({ error: 'Admin not found' });
      }
      const token = crypto.randomBytes(32).toString('hex');
      res.json({ 
        status: 'success', 
        user: { name: user.name, email: user.email, phone: user.phone, role: 'admin' },
        token 
      });
    }

    await OTP.deleteOne({ phone: normalizedPhone, otp });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

// Check if phone exists (for customers)
app.post('/check-user', async (req, res) => {
  const { phone } = req.body;
  if (!phone) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  const normalizedPhone = normalizePhone(phone);

  try {
    const user = await User.findOne({ phone: normalizedPhone });
    if (user) {
      res.json({ status: 'success', exists: true, name: user.name });
    } else {
      res.json({ status: 'success', exists: false });
    }
  } catch (error) {
    console.error('Check user error:', error);
    res.status(500).json({ error: 'Failed to check user' });
  }
});

// Create Razorpay Order
app.post('/create-order', async (req, res) => {
  const { amount } = req.body;
  if (!amount) {
    return res.status(400).json({ error: 'Amount is required' });
  }

  try {
    const options = {
      amount: amount * 100,
      currency: 'INR',
      receipt: `receipt_${Date.now()}`,
    };

    const order = await razorpay.orders.create(options);
    res.json(order);
  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Verify Payment and Store Order
app.post('/verify-payment', async (req, res) => {
  const {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    studentName,
    studentEmail,
    studentPhone,
    items,
    totalAmount,
    orderId,
    paymentMethod,
  } = req.body;

  const normalizedPhone = normalizePhone(studentPhone);

  const orderDetails = {
    orderId,
    studentName,
    studentEmail,
    studentPhone: normalizedPhone,
    items,
    totalAmount,
    paymentMethod,
    status: 'pending',
    razorpay_order_id: paymentMethod === 'cash' ? undefined : razorpay_order_id,
    razorpay_payment_id: paymentMethod === 'cash' ? undefined : razorpay_payment_id,
  };

  try {
    const order = await Order.create(orderDetails);

    const message = paymentMethod === 'cash'
      ? `Your order ID ${orderId} total cost ₹${formatCurrency(order.totalAmount)} cash payment method successfully placed. Your meal will be ready in 30 mins, after 30 mins buy and grab it. Thank you for choosing us!`
      : `Your order ID ${orderId} total cost ₹${formatCurrency(order.totalAmount)} UPI payment method successfully placed. Your meal will be ready in 30 mins, after 30 mins buy and grab it. Thank you for choosing us!`;
    await twilioClient.messages.create({
      body: message,
      to: normalizedPhone,
      from: process.env.TWILIO_PHONE_NUMBER,
    });

    for (const item of order.items) {
      await DailyInventory.findOneAndUpdate(
        { menuItemId: item.id, date: getISTDate() },
        { $inc: { quantity: -item.quantity } },
        { upsert: true }
      );
      const updatedInventory = await DailyInventory.findOne({ menuItemId: item.id, date: getISTDate() });
      io.emit('inventoryUpdated', { menuItemId: item.id, quantity: updatedInventory ? updatedInventory.quantity : 0 });
    }

    io.to('adminRoom').emit('newOrder', order);

    if (paymentMethod === 'cash') {
      return res.json({ status: 'success', orderId });
    }

    const generatedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest('hex');

    if (generatedSignature === razorpay_signature) {
      res.json({ status: 'success', orderId });
    } else {
      res.status(400).json({ error: 'Invalid payment signature' });
    }
  } catch (error) {
    console.error('Verify payment error:', error);
    res.status(500).json({ error: 'Failed to verify payment' });
  }
});

// Get Orders by Phone
app.get('/orders', async (req, res) => {
  const { phone } = req.query;
  if (!phone) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  const normalizedPhone = normalizePhone(phone.toString());
  console.log('Fetching orders for phone:', normalizedPhone);

  try {
    const orders = await Order.find({ studentPhone: normalizedPhone }).sort({ createdAt: -1 });
    console.log('Found orders:', orders);

    res.json({ status: 'success', orders });
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

function formatCurrency(amount) {
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: 'INR',
  }).format(amount);
}

// Routes for Menu Items
app.get('/menu-items', async (req, res) => {
  try {
    const today = getISTDate();
    const menuItems = await MenuItem.find();
    const dailyInventories = await DailyInventory.find({ date: today });

    const menuItemsWithQuantity = menuItems.map((menuItem) => {
      const inventory = dailyInventories.find((inv) => inv.menuItemId.toString() === menuItem._id.toString());
      return {
        ...menuItem._doc,
        id: menuItem._id.toString(),
        quantity: inventory ? inventory.quantity : 0,
        timeSlot: menuItem.availableTime,
        type: menuItem.category,
      };
    });

    res.json({ status: 'success', menuItems: menuItemsWithQuantity });
  } catch (error) {
    console.error('Fetch menu items error:', error);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Get a single menu item by ID
app.get('/menu-items/:id', async (req, res) => {
  try {
    const menuItem = await MenuItem.findById(req.params.id);
    if (!menuItem) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    const today = getISTDate();
    const inventory = await DailyInventory.findOne({ menuItemId: menuItem._id, date: today });
    const menuItemWithQuantity = {
      ...menuItem._doc,
      id: menuItem._id.toString(),
      quantity: inventory ? inventory.quantity : 0,
      timeSlot: menuItem.availableTime,
      type: menuItem.category,
    };
    res.json({ status: 'success', menuItem: menuItemWithQuantity });
  } catch (error) {
    console.error('Error fetching menu item:', error);
    res.status(500).json({ error: 'Failed to fetch menu item' });
  }
});

// Create a new menu item (admin only)
app.post('/admin/menu-items', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { name, description, price, category, availableTime, isActive } = req.body;
  if (!name || !description || !price || !category) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const menuItem = new MenuItem({ name, description, price, category, availableTime, isActive });
    await menuItem.save();

    const today = getISTDate();
    await DailyInventory.create({
      menuItemId: menuItem._id,
      date: today,
      quantity: 0,
    });

    io.emit('menuItemUpdated', menuItem);
    res.status(201).json({ menuItem });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create menu item' });
  }
});

// Update a menu item (admin only)
app.put('/admin/menu-items/:id', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { id } = req.params;
  const { name, description, price, category, availableTime, isActive } = req.body;

  try {
    const menuItem = await MenuItem.findByIdAndUpdate(
      id,
      { name, description, price, category, availableTime, isActive, updatedAt: Date.now() },
      { new: true }
    );
    if (!menuItem) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    io.emit('menuItemUpdated', menuItem);
    res.json({ menuItem });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update menu item' });
  }
});

// Delete a menu item (admin only)
app.delete('/admin/menu-items/:id', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { id } = req.params;

  try {
    const menuItem = await MenuItem.findByIdAndDelete(id);
    if (!menuItem) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    await DailyInventory.deleteMany({ menuItemId: id });
    io.emit('menuItemDeleted', id);
    res.json({ message: 'Menu item deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete menu item' });
  }
});

// Routes for Daily Inventory
app.get('/admin/daily-inventory', async (req, res) => {
  try {
    const today = getISTDate();
    const dailyInventories = await DailyInventory.find({ date: today }).populate('menuItemId');
    res.json({ dailyInventories });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch daily inventory' });
  }
});

app.put('/admin/daily-inventory/:menuItemId', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { menuItemId } = req.params;
  const { quantity } = req.body;

  try {
    console.log('Received update request for menuItemId:', menuItemId, 'with quantity:', quantity);
    const today = getISTDate();
    const dailyInventory = await DailyInventory.findOneAndUpdate(
      { menuItemId, date: today },
      { quantity },
      { upsert: true, new: true }
    );
    io.emit('inventoryUpdated', { menuItemId, quantity });
    res.json({ dailyInventory });
  } catch (error) {
    console.error('Error updating daily inventory:', error);
    res.status(500).json({ error: 'Failed to update daily inventory' });
  }
});

function formatCurrency(amount) {
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: 'INR',
  }).format(amount);
}

app.delete('/cancel-order', async (req, res) => {
  const { orderId } = req.body;
  try {
    const order = await Order.findOneAndDelete({ orderId });
    if (order) {
      res.json({ status: 'success' });
    } else {
      res.status(404).json({ error: 'Order not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete order' });
  }
});

// QR Code Schema
const qrCodeSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  qrCodeData: { type: String, required: true },
  isUsed: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now, expires: 16200 }, // 4 hours 30 minutes = 16200 seconds
});
const QRCode = mongoose.model('QRCode', qrCodeSchema);

// Generate QR Code for an Order
app.post('/customer/generate-qr', async (req, res) => {
  const { orderId, phone } = req.body;
  if (!orderId || !phone) {
    return res.status(400).json({ error: 'Order ID and phone number are required' });
  }

  const normalizedPhone = normalizePhone(phone);

  try {
    const order = await Order.findOne({ orderId, studentPhone: normalizedPhone });
    if (!order) {
      return res.status(404).json({ error: 'Order not found or unauthorized' });
    }

    if (order.status !== 'pending') {
      return res.status(400).json({ error: 'QR code cannot be generated for non-pending orders' });
    }

    let qrCodeRecord = await QRCode.findOne({ orderId });
    if (qrCodeRecord) {
      if (qrCodeRecord.isUsed) {
        return res.status(400).json({ error: 'This QR code has already been used or expired' });
      }

      // Check if the QR code has expired
      const qrGeneratedTime = new Date(qrCodeRecord.createdAt);
      const currentTime = new Date();
      const timeDiffMinutes = (currentTime - qrGeneratedTime) / (1000 * 60);

      if (timeDiffMinutes > 270) { // 4 hours 30 minutes = 270 minutes
        return res.status(400).json({ error: 'This QR code has expired' });
      }

      return res.json({ status: 'success', qrCode: qrCodeRecord.qrCodeData });
    }

    // Encode only the orderId in the QR code
    const qrData = order.orderId;

    const qrCodeDataUrl = await QRCodeLib.toDataURL(qrData);

    qrCodeRecord = await QRCode.create({ orderId, qrCodeData: qrCodeDataUrl });

    res.json({ status: 'success', qrCode: qrCodeDataUrl });
  } catch (error) {
    console.error('Generate QR code error:', error);
    res.status(500).json({ error: 'Failed to generate QR code' });
  }
});

// Validate QR Code (for Admin Panel)
app.post('/admin/validate-qr', async (req, res) => {
  const { qrCodeData } = req.body;
  if (!qrCodeData) {
    return res.status(400).json({ error: 'QR code data is required' });
  }

  try {
    const orderId = qrCodeData; // QR code contains only the orderId

    const qrCodeRecord = await QRCode.findOne({ orderId });
    if (!qrCodeRecord) {
      return res.status(404).json({ error: 'QR code not found or expired' });
    }

    if (qrCodeRecord.isUsed) {
      return res.status(400).json({ error: 'This QR code has already been used' });
    }

    // Check if the QR code has expired
    const qrGeneratedTime = new Date(qrCodeRecord.createdAt);
    const currentTime = new Date();
    const timeDiffMinutes = (currentTime - qrGeneratedTime) / (1000 * 60);

    if (timeDiffMinutes > 270) { // 4 hours 30 minutes = 270 minutes
      return res.status(400).json({ error: 'This QR code has expired' });
    }

    const order = await Order.findOne({ orderId });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    qrCodeRecord.isUsed = true;
    await qrCodeRecord.save();

    order.status = 'completed';
    order.updatedAt = new Date();
    await order.save();

    io.to('adminRoom').emit('orderUpdated', order);

    await twilioClient.messages.create({
      body: `Your order ID ${order.orderId} has been successfully scanned and is now complete. Enjoy your meal!`,
      to: order.studentPhone,
      from: process.env.TWILIO_PHONE_NUMBER,
    });

    res.json({
      status: 'success',
      order: {
        orderId: order.orderId,
        customerName: order.studentName,
        items: order.items,
        totalCost: order.totalAmount,
        dateTime: order.createdAt,
      },
    });
  } catch (error) {
    console.error('Validate QR code error:', error);
    res.status(500).json({ error: 'Failed to validate QR code' });
  }
});

server.listen(5000, () => {
  console.log('Server running on http://localhost:5000');
});
