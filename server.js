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
mongoose.connect('mongodb+srv://kxshrii:i7sgjXF6SO2cTJwU@kelumxz.zggub8h.mongodb.net/sila_ai', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '' },
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
    imageUrl: String
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
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: 'sila_ai_secret_key_2026',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: 'mongodb+srv://kxshrii:i7sgjXF6SO2cTJwU@kelumxz.zggub8h.mongodb.net/sila_ai'
  })
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
const upload = multer({ storage });

// Authentication Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error();
    
    const decoded = jwt.verify(token, 'sila_ai_jwt_secret');
    const user = await User.findById(decoded.userId);
    
    if (!user) throw new Error();
    
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Tafadhali ingia kwanza' });
  }
};

// Admin Middleware
const adminAuth = (req, res, next) => {
  const { adminPin } = req.body;
  if (adminPin === 'sila0022') {
    next();
  } else {
    res.status(403).json({ error: 'Pini ya admin sio sahihi' });
  }
};

// API Routes

// 1. User Authentication
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Email au jina la mtumiaji tayari lipo' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });
    
    await user.save();
    
    // Generate token
    const token = jwt.sign({ userId: user._id }, 'sila_ai_jwt_secret');
    
    res.status(201).json({
      message: 'Akaunti imeundwa kikamilifu',
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      },
      token
    });
  } catch (error) {
    res.status(500).json({ error: 'Hitilafu imetokea' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Email au nenosiri sio sahihi' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Email au nenosiri sio sahihi' });
    }
    
    const token = jwt.sign({ userId: user._id }, 'sila_ai_jwt_secret');
    
    res.json({
      message: 'Umeingia kikamilifu',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin
      },
      token
    });
  } catch (error) {
    res.status(500).json({ error: 'Hitilafu imetokea' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  // In production, implement email sending logic here
  res.json({ message: 'Maelekezo ya kubadilisha nenosiri yametumwa kwenye email yako' });
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'Mtumiaji hajapatikana' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    
    res.json({ message: 'Nenosiri limebadilishwa kikamilifu' });
  } catch (error) {
    res.status(500).json({ error: 'Hitilafu imetokea' });
  }
});

// 2. Chat & AI Functions
app.post('/api/chat', auth, async (req, res) => {
  try {
    const { message, sessionId, generateImage } = req.body;
    const userId = req.user._id;
    
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
      content: message
    });
    
    // Save conversation
    conversation.updatedAt = Date.now();
    await conversation.save();
    
    // Determine which API to use
    let apiUrl;
    if (generateImage) {
      apiUrl = `https://api.siputzx.my.id/api/ai/magicstudio?prompt=${encodeURIComponent(message)}`;
    } else {
      // First get thinking response
      const thinkResponse = await axios.get(`https://api.yupra.my.id/api/ai/copilot-think?text=${encodeURIComponent(message)}`);
      
      // Then get final response
      apiUrl = `https://api.yupra.my.id/api/ai/gpt5?text=${encodeURIComponent(thinkResponse.data + ' ' + message)}`;
    }
    
    // Call AI API
    const aiResponse = await axios.get(apiUrl);
    
    // Add AI response
    const responseContent = generateImage 
      ? `[Picha iliyotengenezwa kwa: ${message}]` 
      : aiResponse.data;
    
    conversation.messages.push({
      role: 'assistant',
      content: responseContent,
      isImage: generateImage,
      imageUrl: generateImage ? aiResponse.data : null
    });
    
    await conversation.save();
    
    res.json({
      response: responseContent,
      isImage: generateImage,
      imageUrl: generateImage ? aiResponse.data : null,
      sessionId
    });
    
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ error: 'Hitilafu katika AI' });
  }
});

// 3. Conversation History
app.get('/api/conversations', auth, async (req, res) => {
  try {
    const conversations = await Conversation.find({ userId: req.user._id })
      .sort({ updatedAt: -1 })
      .select('title sessionId createdAt updatedAt');
    
    res.json(conversations);
  } catch (error) {
    res.status(500).json({ error: 'Hitilafu imetokea' });
  }
});

app.get('/api/conversation/:sessionId', auth, async (req, res) => {
  try {
    const conversation = await Conversation.findOne({
      userId: req.user._id,
      sessionId: req.params.sessionId
    });
    
    if (!conversation) {
      return res.status(404).json({ error: 'Mazungumzo hayajapatikana' });
    }
    
    res.json(conversation);
  } catch (error) {
    res.status(500).json({ error: 'Hitilafu imetokea' });
  }
});

// 4. File Upload
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  try {
    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({ 
      success: true, 
      fileUrl,
      message: 'Faili imepakiwa kikamilifu'
    });
  } catch (error) {
    res.status(500).json({ error: 'Hitilafu katika kupakia faili' });
  }
});

// 5. Admin Panel
app.get('/api/admin/users', auth, adminAuth, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    const conversations = await Conversation.countDocuments();
    
    res.json({
      totalUsers: users.length,
      users,
      totalConversations: conversations
    });
  } catch (error) {
    res.status(500).json({ error: 'Hitilafu imetokea' });
  }
});

app.post('/api/admin/update-pin', auth, adminAuth, async (req, res) => {
  try {
    const { newPin } = req.body;
    // In production, store in database
    res.json({ message: 'Pini ya admin imesasishwa', newPin });
  } catch (error) {
    res.status(500).json({ error: 'Hitilafu imetokea' });
  }
});

// 6. Text-to-Speech (Using Web Speech API on frontend, but here's backup)
app.post('/api/speech', (req, res) => {
  const { text } = req.body;
  // This would integrate with Google Cloud TTS in production
  res.json({ 
    audioUrl: null,
    message: 'Sauti inapatikana kupitia Web Speech API kwenye browser'
  });
});

// Initialize Admin Settings
const initializeAdmin = async () => {
  const settings = await AdminSettings.findOne();
  if (!settings) {
    await AdminSettings.create({});
    console.log('Admin settings initialized');
  }
};

// WebSocket for real-time chat
io.on('connection', (socket) => {
  console.log('Client connected');
  
  socket.on('join-chat', (sessionId) => {
    socket.join(sessionId);
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
  await initializeAdmin();
  console.log(`Sila AI server inatumika kwenye port ${PORT}`);
});
