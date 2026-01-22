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
    language: String,
    isVoice: { type: Boolean, default: false },
    audioUrl: String
  }],
  title: { type: String, default: 'New Chat' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Conversation = mongoose.model('Conversation', ConversationSchema);

// Middleware
app.use(cors({
  origin: ['https://sila-ai.onrender.com', 'http://localhost:3000', 'http://localhost:5500'],
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));
app.use(session({
  secret: 'sila_ai_secret_key_2026_v3',
  resave: true,
  saveUninitialized: true,
  store: MongoStore.create({
    mongoUrl: MONGODB_URI,
    ttl: 24 * 60 * 60
  }),
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: false
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
  limits: { fileSize: 50 * 1024 * 1024 }
});

// Helper Functions for APIs
const callChatAPI = async (message) => {
  try {
    console.log('📞 Calling Chat API with message:', message);
    const response = await axios.get(`https://api.yupra.my.id/api/ai/gpt5?text=${encodeURIComponent(message.trim())}`);
    console.log('✅ Chat API Response:', response.data ? 'Received' : 'Empty');
    return response.data || 'Nimekushindikania kujibu. Tafadhali jaribu tena.';
  } catch (error) {
    console.error('❌ Chat API Error:', error.message);
    return 'Samahani, kuna shida na API ya mazungumzo. Tafadhali jaribu tena baadae.';
  }
};

const callThinkAPI = async (message) => {
  try {
    console.log('🤔 Calling Think API with message:', message);
    const response = await axios.get(`https://api.yupra.my.id/api/ai/copilot-think?text=${encodeURIComponent(message.trim())}`);
    console.log('✅ Think API Response:', response.data ? 'Received' : 'Empty');
    return response.data || '';
  } catch (error) {
    console.error('❌ Think API Error:', error.message);
    return '';
  }
};

const callImageAPI = async (prompt) => {
  try {
    console.log('🎨 Calling Image API with prompt:', prompt);
    // Try multiple image APIs
    const apis = [
      `https://api.siputzx.my.id/api/ai/magicstudio?prompt=${encodeURIComponent(prompt)}`,
      `https://api.siputzx.my.id/api/tools/lexica?prompt=${encodeURIComponent(prompt)}`,
      `https://api.siputzx.my.id/api/tools/aiimage?prompt=${encodeURIComponent(prompt)}`
    ];
    
    for (const apiUrl of apis) {
      try {
        const response = await axios.get(apiUrl, { timeout: 30000 });
        if (response.data && (response.data.image || response.data.url || typeof response.data === 'string')) {
          console.log('✅ Image API Success from:', apiUrl);
          return response.data.image || response.data.url || response.data;
        }
      } catch (apiError) {
        console.warn(`⚠️ Image API failed (${apiUrl}):`, apiError.message);
        continue;
      }
    }
    
    throw new Error('All image APIs failed');
  } catch (error) {
    console.error('❌ All Image APIs Error:', error.message);
    // Return placeholder image
    return `https://via.placeholder.com/512x512/007AFF/ffffff?text=${encodeURIComponent('Image+Error:' + prompt.substring(0, 20))}`;
  }
};

const callVoiceAPI = async (text) => {
  try {
    console.log('🔊 Calling Voice API with text:', text.substring(0, 50) + '...');
    const response = await axios.get(`https://api.siputzx.my.id/api/tools/ttsgoogle?text=${encodeURIComponent(text.trim())}`);
    console.log('✅ Voice API Response:', response.data ? 'Received' : 'Empty');
    return response.data || null;
  } catch (error) {
    console.error('❌ Voice API Error:', error.message);
    return null;
  }
};

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({ 
    success: false,
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
      return res.status(401).json({ 
        success: false,
        error: 'Tafadhali ingia kwanza' 
      });
    }
    
    const decoded = jwt.verify(token, 'sila_ai_jwt_secret_2026');
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        error: 'Mtumiaji huyu hayupo' 
      });
    }
    
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).json({ 
      success: false,
      error: 'Hitilafu ya uthibitishaji' 
    });
  }
};

// Admin middleware
const adminAuth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '') || 
                  req.query.token;
    
    if (!token) {
      return res.status(401).json({ 
        success: false,
        error: 'Una hitaji ruhusa ya admin' 
      });
    }
    
    const decoded = jwt.verify(token, 'sila_admin_secret_2026');
    
    if (!decoded.admin || Date.now() - decoded.timestamp > 24 * 60 * 60 * 1000) {
      return res.status(401).json({ 
        success: false,
        error: 'Muda wa ruhusa umekwisha' 
      });
    }
    
    next();
  } catch (error) {
    res.status(401).json({ 
      success: false,
      error: 'Hitilafu ya uthibitishaji wa admin' 
    });
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
    
    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Tafadhali jaza sehemu zote' 
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false,
        error: 'Nenosiri lazima liwe na angalau herufi 6' 
      });
    }
    
    const existingUser = await User.findOne({ 
      $or: [{ email: email.toLowerCase() }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        error: existingUser.email === email.toLowerCase() 
          ? 'Barua pepe tayari imetumika' 
          : 'Jina la mtumiaji tayari lipo' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = new User({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      language
    });
    
    await user.save();
    
    const token = jwt.sign({ 
      userId: user._id,
      email: user.email 
    }, 'sila_ai_jwt_secret_2026', { expiresIn: '30d' });
    
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
      success: false,
      error: 'Hitilafu ya mtandao imetokea. Tafadhali jaribu tena.' 
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Tafadhali jaza barua pepe na nenosiri' 
      });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(400).json({ 
        success: false,
        error: 'Barua pepe au nenosiri sio sahihi' 
      });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false,
        error: 'Barua pepe au nenosiri sio sahihi' 
      });
    }
    
    const token = jwt.sign({ 
      userId: user._id,
      email: user.email 
    }, 'sila_ai_jwt_secret_2026', { expiresIn: '30d' });
    
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
      success: false,
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

// 2. Chat & AI Functions - FIXED WITH WORKING APIs
app.post('/api/chat', auth, async (req, res) => {
  try {
    const { message, sessionId, generateImage, generateVoice, language = req.user.language || 'sw' } = req.body;
    const userId = req.user._id;
    
    if (!message || message.trim().length === 0) {
      return res.status(400).json({ 
        success: false,
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
    
    conversation.updatedAt = new Date();
    await conversation.save();
    
    let aiResponse;
    let imageUrl = null;
    let audioUrl = null;
    
    try {
      if (generateImage) {
        // Generate image
        imageUrl = await callImageAPI(message);
        aiResponse = `[Picha imetengenezwa kwa: "${message}"]`;
        
      } else if (generateVoice) {
        // Generate voice response
        const chatResponse = await callChatAPI(message);
        audioUrl = await callVoiceAPI(chatResponse);
        aiResponse = chatResponse;
        
      } else {
        // Get AI response with thinking process
        const thinkResponse = await callThinkAPI(message);
        let finalMessage = message;
        
        if (thinkResponse && thinkResponse.trim().length > 0) {
          finalMessage = thinkResponse + ' ' + message;
        }
        
        aiResponse = await callChatAPI(finalMessage);
      }
      
      // Add AI response
      conversation.messages.push({
        role: 'assistant',
        content: aiResponse,
        isImage: generateImage,
        imageUrl: imageUrl,
        isVoice: generateVoice,
        audioUrl: audioUrl,
        language
      });
      
      await conversation.save();
      
      res.json({
        success: true,
        response: aiResponse,
        isImage: generateImage,
        imageUrl: imageUrl,
        isVoice: generateVoice,
        audioUrl: audioUrl,
        sessionId,
        language
      });
      
    } catch (apiError) {
      console.error('AI Processing Error:', apiError.message);
      
      // Fallback response
      const fallbackResponse = language === 'sw' 
        ? 'Samahani, kuna shida na huduma ya AI. Nimeshindwa kukujibu kwa sasa. Tafadhali jaribu tena baadae au badilisha swali lako.'
        : 'Sorry, there is an issue with the AI service. I failed to respond at the moment. Please try again later or rephrase your question.';
      
      conversation.messages.push({
        role: 'assistant',
        content: fallbackResponse,
        language
      });
      
      await conversation.save();
      
      res.json({
        success: false,
        response: fallbackResponse,
        error: 'AI service temporarily unavailable'
      });
    }
    
  } catch (error) {
    console.error('Chat error:', error);
    const errorMessage = req.user?.language === 'sw'
      ? 'Hitilafu ya mtandao imetokea. Tafadhali jaribu tena.'
      : 'Network error occurred. Please try again.';
    
    res.status(500).json({ 
      success: false,
      error: errorMessage 
    });
  }
});

// Direct API calls for testing
app.get('/api/test/chat', async (req, res) => {
  try {
    const { text } = req.query;
    if (!text) {
      return res.status(400).json({ error: 'Text parameter required' });
    }
    
    const response = await callChatAPI(text);
    res.json({ success: true, response });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/test/think', async (req, res) => {
  try {
    const { text } = req.query;
    if (!text) {
      return res.status(400).json({ error: 'Text parameter required' });
    }
    
    const response = await callThinkAPI(text);
    res.json({ success: true, response });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/test/image', async (req, res) => {
  try {
    const { prompt } = req.query;
    if (!prompt) {
      return res.status(400).json({ error: 'Prompt parameter required' });
    }
    
    const imageUrl = await callImageAPI(prompt);
    res.json({ success: true, imageUrl });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/test/voice', async (req, res) => {
  try {
    const { text } = req.query;
    if (!text) {
      return res.status(400).json({ error: 'Text parameter required' });
    }
    
    const audioUrl = await callVoiceAPI(text);
    res.json({ success: true, audioUrl });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 3. Conversation History
app.get('/api/conversations', auth, async (req, res) => {
  try {
    const conversations = await Conversation.find({ userId: req.user._id })
      .sort({ updatedAt: -1 })
      .select('title sessionId createdAt updatedAt messages')
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
      sessionId: req.params.sessionId
    }).populate('userId', 'username email');
    
    if (!conversation) {
      return res.status(404).json({ 
        success: false,
        error: 'Mazungumzo hayajapatikana' 
      });
    }
    
    if (!req.user.isAdmin && conversation.userId._id.toString() !== req.user._id.toString()) {
      return res.status(403).json({ 
        success: false,
        error: 'Huna ruhusa ya kuona mazungumzo haya' 
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
app.post('/admin/login', async (req, res) => {
  try {
    const { pin } = req.body;
    
    // Hardcoded admin PIN
    if (pin !== 'sila0022') {
      return res.status(401).json({ 
        success: false,
        error: 'Pini ya admin sio sahihi'
      });
    }
    
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
    res.status(500).json({ 
      success: false,
      error: 'Hitilafu ya mtandao' 
    });
  }
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalConversations = await Conversation.countDocuments();
    const activeUsers = await User.countDocuments({
      createdAt: { $gt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });
    
    const users = await User.find()
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(100);
    
    const allConversations = await Conversation.find()
      .populate('userId', 'username email')
      .sort({ updatedAt: -1 })
      .limit(50);
    
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
      users,
      conversations: allConversations
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

app.get('/api/admin/user/:userId/conversations', adminAuth, async (req, res) => {
  try {
    const conversations = await Conversation.find({ userId: req.params.userId })
      .sort({ updatedAt: -1 })
      .populate('userId', 'username email');
    
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

app.get('/api/admin/user/:userId/details', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'Mtumiaji huyu hayupo' 
      });
    }
    
    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        language: user.language,
        isAdmin: user.isAdmin,
        createdAt: user.createdAt,
        password: user.password
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Hitilafu ya mtandao imetokea' 
    });
  }
});

app.post('/api/admin/user/:userId/update-password', adminAuth, async (req, res) => {
  try {
    const { newPassword } = req.body;
    
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ 
        success: false,
        error: 'Nenosiri lazima liwe na angalau herufi 6' 
      });
    }
    
    const user = await User.findById(req.params.userId);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'Mtumiaji huyu hayupo' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    await user.save();
    
    res.json({
      success: true,
      message: 'Nenosiri limebadilishwa kikamilifu'
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
    success: true,
    status: 'healthy',
    timestamp: new Date(),
    version: '3.2.0',
    apis: {
      chat: 'https://api.yupra.my.id/api/ai/gpt5',
      think: 'https://api.yupra.my.id/api/ai/copilot-think',
      image: 'https://api.siputzx.my.id/api/ai/magicstudio',
      voice: 'https://api.siputzx.my.id/api/tools/ttsgoogle'
    }
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

// WebSocket for real-time chat
io.on('connection', (socket) => {
  console.log('🔌 Mteja ameshikamana');
  
  socket.on('join-chat', (sessionId) => {
    socket.join(sessionId);
  });
  
  socket.on('disconnect', () => {
    console.log('🔌 Mteja amekatika');
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Sila AI server inatumika kwenye port ${PORT}`);
  console.log(`🌐 Unganisha: http://localhost:${PORT}`);
  console.log(`👑 Admin Panel: http://localhost:${PORT}/admin`);
  console.log(`🤖 APIs Available:`);
  console.log(`   - Chat: https://api.yupra.my.id/api/ai/gpt5`);
  console.log(`   - Think: https://api.yupra.my.id/api/ai/copilot-think`);
  console.log(`   - Image: https://api.siputzx.my.id/api/ai/magicstudio`);
  console.log(`   - Voice: https://api.siputzx.my.id/api/tools/ttsgoogle`);
});
