const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const axios = require('axios');
const multer = require('multer');
const path = require('path');
const socketIo = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// MongoDB Connection
const MONGODB_URI = 'mongodb+srv://kxshrii:i7sgjXF6SO2cTJwU@kelumxz.zggub8h.mongodb.net/sila_ai';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ Imeshikamana na MongoDB kikamilifu');
}).catch(err => {
  console.error('❌ Hitilafu ya kushikamana na MongoDB:', err);
});

// Schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '' },
  language: { type: String, default: 'sw' },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const ConversationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  sessionId: { type: String, required: true },
  messages: [{
    role: { type: String, enum: ['user', 'assistant', 'system'] },
    content: String,
    timestamp: { type: Date, default: Date.now },
    isImage: { type: Boolean, default: false },
    imageUrl: String,
    language: String
  }],
  title: { type: String, default: 'New Chat' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const AdminSettingsSchema = new mongoose.Schema({
  adminPin: { type: String, default: 'sila0022' },
  aiName: { type: String, default: 'Sila AI' },
  aiPersonality: { type: String, default: 'Ninasema Kiswahili na Kiingereza, ni msaidizi wenye uelewa mkuu, mwenye huruma na ufasaha.' },
  apiEndpoints: {
    chat: { type: String, default: 'https://api.yupra.my.id/api/ai/gpt5?text=' },
    think: { type: String, default: 'https://api.yupra.my.id/api/ai/copilot-think?text=' },
    image: { type: String, default: 'https://api.siputzx.my.id/api/ai/magicstudio?prompt=' }
  }
});

const User = mongoose.model('User', UserSchema);
const Conversation = mongoose.model('Conversation', ConversationSchema);
const AdminSettings = mongoose.model('AdminSettings', AdminSettingsSchema);

// Middleware
app.use(cors({
  origin: ['https://sila-ai.onrender.com', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));
app.use(session({
  secret: 'sila_ai_secret_key_2026_v2',
  resave: true,
  saveUninitialized: true,
  store: MongoStore.create({
    mongoUrl: MONGODB_URI,
    ttl: 24 * 60 * 60 // 1 day
  }),
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

// File Upload Setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({ 
    error: 'Hitilafu ya mtandao imetokea', 
    details: process.env.NODE_ENV === 'development' ? err.message : undefined 
  });
});

// Authentication Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '') || 
                  req.session.token;
    
    if (!token) {
      return res.status(401).json({ error: 'Tafadhali ingia kwanza' });
    }
    
    const decoded = jwt.verify(token, 'sila_ai_jwt_secret_2026');
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'Mtumiaji huyu hayupo' });
    }
    
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Hitilafu ya uthibitishaji' });
  }
};

// Admin Panel Route (Public with PIN)
app.post('/admin/login', async (req, res) => {
  try {
    const { pin } = req.body;
    const settings = await AdminSettings.findOne();
    
    if (!settings || pin !== settings.adminPin) {
      return res.status(401).json({ 
        error: 'Pini ya admin sio sahihi',
        success: false 
      });
    }
    
    // Create admin session
    const adminToken = jwt.sign({ 
      admin: true, 
      timestamp: Date.now() 
    }, 'sila_admin_secret_2026');
    
    res.json({ 
      success: true, 
      token: adminToken,
      message: 'Umeingia kwenye admin panel'
    });
  } catch (error) {
    res.status(500).json({ error: 'Hitilafu ya mtandao' });
  }
});

// Admin middleware
const adminAuth = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '') || 
                  req.session.adminToken;
    
    if (!token) {
      return res.status(401).json({ error: 'Una hitaji ruhusa ya admin' });
    }
    
    const decoded = jwt.verify(token, 'sila_admin_secret_2026');
    
    if (!decoded.admin || Date.now() - decoded.timestamp > 24 * 60 * 60 * 1000) {
      return res.status(401).json({ error: 'Muda wa ruhusa umekwisha' });
    }
    
    next();
  } catch (error) {
    res.status(401).json({ error: 'Hitilafu ya uthibitishaji wa admin' });
  }
};

// Serve Admin Page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// API Routes

// 1. User Authentication
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, language = 'sw' } = req.body;
    
    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ 
        error: 'Tafadhali jaza sehemu zote' 
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ 
        error: 'Nenosiri lazima liwe na angalau herufi 6' 
      });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email: email.toLowerCase() }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        error: existingUser.email === email.toLowerCase() 
          ? 'Barua pepe tayari imetumika' 
          : 'Jina la mtumiaji tayari lipo' 
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create user
    const user = new User({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      language
    });
    
    await user.save();
    
    // Generate token
    const token = jwt.sign({ 
      userId: user._id,
      email: user.email 
    }, 'sila_ai_jwt_secret_2026', { expiresIn: '30d' });
    
    // Store in session
    req.session.userId = user._id;
    req.session.token = token;
    
    res.status(201).json({
      success: true,
      message: 'Akaunti imeundwa kikamilifu',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        language: user.language,
        isAdmin: user.isAdmin
      },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      error: 'Hitilafu ya mtandao imetokea. Tafadhali jaribu tena.' 
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Tafadhali jaza barua pepe na nenosiri' 
      });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(400).json({ 
        error: 'Barua pepe au nenosiri sio sahihi' 
      });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        error: 'Barua pepe au nenosiri sio sahihi' 
      });
    }
    
    const token = jwt.sign({ 
      userId: user._id,
      email: user.email 
    }, 'sila_ai_jwt_secret_2026', { expiresIn: '30d' });
    
    // Update last login
    user.lastLogin = Date.now();
    await user.save();
    
    // Store in session
    req.session.userId = user._id;
    req.session.token = token;
    
    res.json({
      success: true,
      message: 'Umeingia kikamilifu',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        language: user.language,
        isAdmin: user.isAdmin
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        error: 'Tafadhali weka barua pepe yako' 
      });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      // Return success even if email not found (security best practice)
      return res.json({ 
        success: true,
        message: 'Ikiwa barua pepe iko kwenye mfumo, maelekezo yatatumwa.' 
      });
    }
    
    // Generate reset token
    const resetToken = jwt.sign(
      { userId: user._id, purpose: 'password_reset' },
      'sila_reset_secret_2026',
      { expiresIn: '1h' }
    );
    
    // In production, send email here
    // For now, return the token (in production, send via email)
    res.json({
      success: true,
      message: 'Maelekezo ya kubadilisha nenosiri yatatumwa kwenye email yako',
      resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({ 
        error: 'Tafadhali jaza sehemu zote' 
      });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        error: 'Nenosiri jipya lazima liwe na angalau herufi 6' 
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, 'sila_reset_secret_2026');
    
    if (decoded.purpose !== 'password_reset') {
      return res.status(400).json({ 
        error: 'Tokeni sio sahihi' 
      });
    }
    
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ 
        error: 'Mtumiaji huyu hayupo' 
      });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    await user.save();
    
    res.json({ 
      success: true,
      message: 'Nenosiri limebadilishwa kikamilifu' 
    });
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(400).json({ 
        error: 'Tokeni imekwisha au sio sahihi' 
      });
    }
    res.status(500).json({ 
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

app.post('/api/update-language', auth, async (req, res) => {
  try {
    const { language } = req.body;
    
    if (!['sw', 'en', 'fr', 'es', 'ar'].includes(language)) {
      return res.status(400).json({ 
        error: 'Lugha hii haiungwi mkono' 
      });
    }
    
    req.user.language = language;
    await req.user.save();
    
    res.json({
      success: true,
      message: 'Lugha imesasishwa',
      language
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

// 2. Chat & AI Functions
app.post('/api/chat', auth, async (req, res) => {
  try {
    const { message, sessionId, generateImage, language = req.user.language || 'sw' } = req.body;
    const userId = req.user._id;
    
    // Validate message
    if (!message || message.trim().length === 0) {
      return res.status(400).json({ 
        error: 'Tafadhali andika ujumbe' 
      });
    }
    
    let conversation = await Conversation.findOne({ userId, sessionId });
    
    if (!conversation) {
      conversation = new Conversation({
        userId,
        sessionId,
        messages: []
      });
    }
    
    // Add user message
    conversation.messages.push({
      role: 'user',
      content: message.trim(),
      language
    });
    
    // Save conversation
    conversation.updatedAt = new Date();
    await conversation.save();
    
    let aiResponse;
    let imageUrl = null;
    
    try {
      if (generateImage) {
        // Generate image
        const imageResponse = await axios.get(
          `https://api.siputzx.my.id/api/ai/magicstudio?prompt=${encodeURIComponent(message)}`,
          { timeout: 30000 }
        );
        
        imageUrl = imageResponse.data;
        aiResponse = `[Picha imetengenezwa kwa: "${message}"]`;
        
      } else {
        // Get thinking response
        let thinkResponse;
        try {
          thinkResponse = await axios.get(
            `https://api.yupra.my.id/api/ai/copilot-think?text=${encodeURIComponent(message)}`,
            { timeout: 30000 }
          );
        } catch (thinkError) {
          console.warn('Think API failed, using direct chat:', thinkError.message);
          thinkResponse = { data: '' };
        }
        
        // Get chat response
        const chatResponse = await axios.get(
          `https://api.yupra.my.id/api/ai/gpt5?text=${encodeURIComponent(
            thinkResponse.data ? thinkResponse.data + ' ' + message : message
          )}`,
          { timeout: 30000 }
        );
        
        aiResponse = chatResponse.data;
      }
      
      // Add AI response
      conversation.messages.push({
        role: 'assistant',
        content: aiResponse,
        isImage: generateImage,
        imageUrl: imageUrl,
        language
      });
      
      await conversation.save();
      
      res.json({
        success: true,
        response: aiResponse,
        isImage: generateImage,
        imageUrl: imageUrl,
        sessionId,
        language
      });
      
    } catch (apiError) {
      console.error('AI API Error:', apiError.message);
      
      // Fallback response
      const fallbackResponse = language === 'sw' 
        ? 'Samahani, kuna shida na muunganisho wa AI. Tafadhali jaribu tena baadae.'
        : 'Sorry, there is an issue with the AI connection. Please try again later.';
      
      conversation.messages.push({
        role: 'assistant',
        content: fallbackResponse,
        language
      });
      
      await conversation.save();
      
      res.status(503).json({
        success: false,
        response: fallbackResponse,
        error: 'AI service temporarily unavailable'
      });
    }
    
  } catch (error) {
    console.error('Chat error:', error);
    const errorMessage = req.user.language === 'sw'
      ? 'Hitilafu ya mtandao imetokea. Tafadhali jaribu tena.'
      : 'Network error occurred. Please try again.';
    
    res.status(500).json({ 
      success: false,
      error: errorMessage 
    });
  }
});

// 3. Conversation History
app.get('/api/conversations', auth, async (req, res) => {
  try {
    const conversations = await Conversation.find({ userId: req.user._id })
      .sort({ updatedAt: -1 })
      .select('title sessionId createdAt updatedAt')
      .limit(50);
    
    res.json({
      success: true,
      conversations
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

app.get('/api/conversation/:sessionId', auth, async (req, res) => {
  try {
    const conversation = await Conversation.findOne({
      userId: req.user._id,
      sessionId: req.params.sessionId
    });
    
    if (!conversation) {
      return res.status(404).json({ 
        success: false,
        error: 'Mazungumzo hayajapatikana' 
      });
    }
    
    res.json({
      success: true,
      conversation
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

// 4. File Upload
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false,
        error: 'Hakuna faili iliyopakiwa' 
      });
    }
    
    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({ 
      success: true, 
      fileUrl,
      filename: req.file.originalname,
      size: req.file.size,
      message: req.user.language === 'sw' 
        ? 'Faili imepakiwa kikamilifu' 
        : 'File uploaded successfully'
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Hitilafu katika kupakia faili' 
    });
  }
});

// 5. Admin Panel APIs
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalConversations = await Conversation.countDocuments();
    const activeUsers = await User.countDocuments({
      lastLogin: { $gt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });
    
    const users = await User.find()
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(100);
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        totalConversations,
        activeUsers,
        todayUsers: await User.countDocuments({
          createdAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        })
      },
      users
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

app.post('/api/admin/update-pin', adminAuth, async (req, res) => {
  try {
    const { newPin } = req.body;
    
    if (!newPin || newPin.length < 4) {
      return res.status(400).json({ 
        success: false,
        error: 'Pini ya admin lazima iwe na angalau herufi 4' 
      });
    }
    
    let settings = await AdminSettings.findOne();
    if (!settings) {
      settings = new AdminSettings();
    }
    
    settings.adminPin = newPin;
    await settings.save();
    
    res.json({ 
      success: true, 
      message: 'Pini ya admin imesasishwa kikamilifu',
      newPin
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

app.post('/api/admin/update-user', adminAuth, async (req, res) => {
  try {
    const { userId, updates } = req.body;
    
    if (!userId || !updates) {
      return res.status(400).json({ 
        success: false,
        error: 'Data haijakamilika' 
      });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'Mtumiaji huyu hayupo' 
      });
    }
    
    // Update allowed fields
    if (updates.username) user.username = updates.username;
    if (updates.email) user.email = updates.email.toLowerCase();
    if (updates.language) user.language = updates.language;
    if (updates.isAdmin !== undefined) user.isAdmin = updates.isAdmin;
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Taarifa za mtumiaji zimesasishwa',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        language: user.language,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

// 6. Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date(),
    version: '2.0.0'
  });
});

// Serve static files
app.use('/uploads', express.static('public/uploads'));

// Serve main app
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/admin')) {
    return res.status(404).json({ error: 'Njia hii haijapatikana' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize Admin Settings
const initializeAdmin = async () => {
  try {
    const settings = await AdminSettings.findOne();
    if (!settings) {
      await AdminSettings.create({});
      console.log('✅ Mipangilio ya admin imesanikishwa');
    }
  } catch (error) {
    console.error('❌ Hitilafu ya kusanikisha admin:', error);
  }
};

// WebSocket for real-time chat
io.on('connection', (socket) => {
  console.log('🔌 Mteja ameshikamana');
  
  socket.on('join-chat', (sessionId) => {
    socket.join(sessionId);
  });
  
  socket.on('chat-message', (data) => {
    io.to(data.sessionId).emit('new-message', data);
  });
  
  socket.on('typing', (data) => {
    socket.to(data.sessionId).emit('user-typing', data);
  });
  
  socket.on('disconnect', () => {
    console.log('🔌 Mteja amekatika');
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
  await initializeAdmin();
  console.log(`🚀 Sila AI server inatumika kwenye port ${PORT}`);
  console.log(`🌐 Unganisha: http://localhost:${PORT}`);
  console.log(`👑 Admin Panel: http://localhost:${PORT}/admin`);
});
