require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const User = require('./models/user'); // Replace with your actual User model
const { Parser } = require('json2csv');
let ejs = require('ejs');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const port = process.env.PORT || 3000;

app.set('view engine', 'ejs');

//检查必须的环境变量
if (!process.env.MONGODB_URI) {
  console.error('错误：缺少环境变量 MONGODB_URI');
  process.exit(1);
}

// 使用的中间件
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads')); // Serve static files from the uploads directory
app.use(express.static('public'));
// MongoDB 连接
mongoose
  .connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('已连接到 MongoDB');
    setupAdmin();
  })
  .catch((err) => console.error('MongoDB 连接错误:', err));

// 针对头像上传的 Multer（一个 node.js 中间件）设置。
const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('只允许上传图片文件!'), false);
    }
    cb(null, true);
  },
  limits: { fileSize: 2 * 1024 * 1024 }, // Limit file size to 2MB
});

//针对帖子图片上传的 Multer（中间件）设置。
const postStorage = multer.diskStorage({
  destination: 'uploads/posts/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const postUpload = multer({
  storage: postStorage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('只允许上传图片文件!'), false);
    }
    cb(null, true);
  },
  limits: { fileSize: 2 * 1024 * 1024 }, // Limit file size to 2MB
});

// 用于验证请求体的中间件。
const validateRequestBody = (requiredFields) => (req, res, next) => {
  const missingFields = requiredFields.filter((field) => !req.body[field]);
  if (missingFields.length > 0) {
    return res.status(400).json({ message: `Missing fields: ${missingFields.join(', ')}` });
  }
  next();
};

// 设置默认管理员
const setupAdmin = async () => {
  try {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('123456', 10);
      await User.create({
        username: 'admin',
        password: hashedPassword,
        role: 'admin',
        status: 'active',
      });
      console.log('Default admin created (username: admin, password: 123456)');
    } else {
      console.log('Default admin already exists');
    }
  } catch (error) {
    console.error('Error setting up default admin:', error.message);
  }
};

// Mongoose schemas
const postSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  avatar: String,
  content: String,
  image: String,
  likes: { type: Number, default: 0 },
  likedBy: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    username: String,
    avatar: String
  }],
  shares: { type: Number, default: 0 },
  sharedBy: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    username: String,
    avatar: String
  }],
  ipAddress: String,
  comments: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    username: String,
    avatar: String,
    content: String,
    ipAddress: String,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const Post = mongoose.model('Post', postSchema);


// 修改用户角色
app.put('/api/users/:id/role', async (req, res) => {
  try {
    const userId = req.params.id;
    const { role } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: '用户未找到' });
    }

    if (user.username === 'admin') {
      return res.status(403).json({ message: '无法修改管理员角' });
    }

    user.role = role;
    await user.save();

    res.json({ message: '角色更新成功', user });
  } catch (error) {
    res.status(500).json({ message: '更新角色失败', error: error.message });
  }
});

// 切换用户状态
app.put('/api/users/:id/status', async (req, res) => {
  try {
    const userId = req.params.id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: '用户未找到' });
    }

    if (user.username === 'admin') {
      return res.status(403).json({ message: '无法修改管理员状' });
    }

    user.status = user.status === 'active' ? 'inactive' : 'active';
    await user.save();

    res.json({ message: '状态更新成功', user });
  } catch (error) {
    res.status(500).json({ message: '更新状态失败', error: error.message });
  }
});

// 删除户
app.delete('/api/users/:id', async (req, res) => {
  try {
    const userId = req.params.id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: '用户未找到' });
    }

    if (user.username === 'admin') {
      return res.status(403).json({ message: '无法删除管理员' });
    }

    await User.deleteOne({ _id: userId });

    res.json({ message: '用户删除成功' });
  } catch (error) {
    res.status(500).json({ message: '删除用户失败', error: error.message });
  }
});
// 获得所有用户
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().select('-password -resetToken -resetTokenExpiry');
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: '获取用户失败', error: err.message });
  }
});

// 根据 ID 获取用户
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -resetToken -resetTokenExpiry');
    if (!user) {
      return res.status(404).json({ message: '用户未找到' });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: '获取用户失败', error: err.message });
  }
});

// 注用户
app.post(
  '/api/register',
  upload.single('avatar'),
  validateRequestBody(['username', 'password']),
  async (req, res) => {
    const { username, email, password } = req.body;
    const avatar = req.file ? `/uploads/${req.file.filename}` : null;

    try {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ message: '用户名已存在' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({
        username,
        email,
        password: hashedPassword,
        role: 'user',
        status: 'active',
        avatar,
      });

      await newUser.save();
      res.status(201).json({ message: '用户注册成功' });
    } catch (err) {
      res.status(500).json({ message: '注册用户时出错', error: err.message });
    }
  }
);

// 用户登录
app.post('/api/login', validateRequestBody(['username', 'password']), async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: '用户未找到' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: '密码无效' });
    }

    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        avatar: user.avatar || '/uploads/default-avatar.png',
        role: user.role,
        status: user.status,
      },
    });
  } catch (err) {
    res.status(500).json({ message: '登录时出错', error: err.message });
  }
});

// 上传用户头像
app.put('/api/users/:id/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const userId = req.params.id;
    const avatarPath = `/uploads/${req.file.filename}`;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.avatar = avatarPath; // Update avatar
    await user.save();

    res.json({
      message: '头像更新成功',
      user: {
        id: user._id,
        username: user.username,
        avatar: user.avatar,
      },
    });
  } catch (error) {
    console.error('Error updating avatar:', error);
    res.status(500).json({ message: 'Failed to update avatar', error: error.message });
  }
});

// 导出用户数据到 CSV
app.get('/api/export', async (req, res) => {
  try {
    const users = await User.find().select('-password -resetToken -resetTokenExpiry');
    if (users.length === 0) {
      return res.status(404).json({ message: '没有找到要导出的用户' });
    }

    const fields = ['_id', 'username', 'email', 'role', 'status', 'createdAt', 'updatedAt'];
    const opts = { fields };
    const parser = new Parser(opts);
    const csv = parser.parse(users);

    res.header('Content-Type', 'text/csv');
    res.attachment('users.csv');
    res.send(csv);
  } catch (err) {
    res.status(500).json({ message: 'Error exporting users to CSV', error: err.message });
  }
});

// 获得所有帖子
app.get('/api/posts', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    const posts = await Post.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Post.countDocuments();
    
    res.json({
      posts,
      totalPages: Math.ceil(total / limit),
      currentPage: page
    });
  } catch (err) {
    res.status(500).send(err);
  }
});

// 添加新的函数用于获取地理位置
async function getLocationFromIP(ip) {
    try {
        // 如果是本地 IP，返回默认位置
        if (ip === '::1' || ip === '127.0.0.1' || ip.includes('::ffff:127.0.0.1')) {
            return '福建厦门'; // 可以设置一个默认位置
        }
        
        // 去除 IPv6 前缀
        ip = ip.replace(/^::ffff:/, '');
        
        // 使用 ip-api.com 的服务获取位置信息
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        const data = await response.json();
        
        if (data.status === 'success') {
            return `${data.regionName}${data.city}`;
        } else {
            // 如果获取失败，返回默认位置
            return '福建厦门';
        }
    } catch (error) {
        console.error('Error getting location:', error);
        return '福建厦门';
    }
}

// 修改创建帖子的接口
app.post('/api/posts', postUpload.single('image'), async (req, res) => {
    try {
        const { userId, content } = req.body;
        const imagePath = req.file ? `/uploads/posts/${req.file.filename}` : null;
        
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ message: 'Invalid userId' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // 获取客户端 IP 地址并转换为地理位置
        const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const location = await getLocationFromIP(ipAddress);

        const newPost = new Post({
            userId: user._id,
            username: user.username,
            avatar: user.avatar || '/uploads/default-avatar.png',
            content: content,
            image: imagePath,
            ipAddress: location,  // 保存地理位置而不是 IP
            createdAt: new Date()
        });

        await newPost.save();
        io.emit('newPost', newPost);
        res.status(201).json(newPost);
    } catch (err) {
        console.error('Error creating post:', err);
        res.status(500).json({ message: 'Failed to create post', error: err.message });
    }
});

// 修改添加评论的接口
app.post('/api/posts/:id/comments', async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).send('Post not found');

        const user = await User.findById(req.body.userId);
        if (!user) return res.status(404).send('User not found');

        // 获取客户端 IP 地址并转换为地理位置
        const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const location = await getLocationFromIP(ipAddress);

        const comment = {
            userId: user._id,
            username: user.username,
            avatar: user.avatar || '/uploads/default-avatar.png',
            content: req.body.content,
            ipAddress: location,  // 保存地理位置而不是 IP
            createdAt: new Date()
        };

        post.comments.push(comment);
        await post.save();
        io.emit('newComment', { postId: req.params.id, comment: comment });
        res.status(201).json(post);
    } catch (err) {
        res.status(500).send(err);
    }
});


// 转发帖子
// 转发帖子
app.post('/api/posts/:id/share', async (req, res) => {
  try {
    const postId = req.params.id;
    const { userId, additionalContent } = req.body;

    const originalPost = await Post.findById(postId);
    if (!originalPost) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // 更新原帖子的转发记录
    originalPost.sharedBy.push({
      userId: user._id,
      username: user.username,
      avatar: user.avatar
    });
    originalPost.shares += 1;
    await originalPost.save();

    // 创建新的转发帖子，包含用户添加的内容
    const newPostContent = additionalContent ? 
      `${additionalContent}\n\n "${originalPost.content}" —— 来自 ${originalPost.username}` :
      ` "${originalPost.content}" —— 来自 ${originalPost.username}`;

    const newPost = new Post({
      userId: user._id,
      username: user.username,
      avatar: user.avatar || '/uploads/default-avatar.png',
      content: newPostContent,
      image: originalPost.image,
      ipAddress: req.ip
    });

    await newPost.save();
    io.emit('newPost', newPost);
    io.emit('updateShares', { postId: originalPost._id, shares: originalPost.shares, sharedBy: originalPost.sharedBy });
    
    res.status(201).json(newPost);
  } catch (err) {
    console.error('Error sharing post:', err);
    res.status(500).json({ message: '转发帖子失败', error: err.message });
  }
});

// 添加用户主页的API
app.get('/api/users/:userId/profile', async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: '用户未找到' });
    }

    const posts = await Post.find({ userId })
      .sort({ createdAt: -1 });

    res.json({
      user: {
        id: user._id,
        username: user.username,
        avatar: user.avatar,
        createdAt: user.createdAt
      },
      posts
    });
  } catch (err) {
    res.status(500).json({ message: '获取用户资料失败', error: err.message });
  }
});

// 获得用户的帖子
app.get('/api/users/:userId/posts', async (req, res) => {
  try {
    const userId = req.params.userId;
    const posts = await Post.find({ userId }).sort({ createdAt: -1 });
    res.json(posts);
  } catch (err) {
    res.status(500).json({ message: '获取帖子失败', error: err.message });
  }
});

// 删除帖子
app.delete('/api/posts/:id', async (req, res) => {
  try {
    const postId = req.params.id;
    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({ message: '帖子未找到' });
    }

    await Post.deleteOne({ _id: postId });
    res.json({ message: '帖子删除成功' });
  } catch (err) {
    res.status(500).json({ message: '删除帖子失败', error: err.message });
  }
});

//连接socket.io
const server = http.createServer(app);
const io = socketIo(server);

io.on('connection', (socket) => {
  console.log('New client connected');

  // 处理新帖子
  socket.on('newPost', async (data) => {
    try {
      const user = await User.findById(data.userId);
      console.log(user);
      
      if (!user) return;

      const newPost = new Post({
        userId: user._id,
        username: user.username,
        avatar: user.avatar || '/uploads/default-avatar.png',
        content: data.content
      });

      await newPost.save();
      io.emit('updatePosts', { type: 'new', post: newPost });
    } catch (err) {
      console.error('Error creating post:', err);
    }
  });

  // 处理新评论
  socket.on('newComment', async (data) => {
    try {
      const user = await User.findById(data.userId);
      const post = await Post.findById(data.postId);
      
      if (!user || !post) return;

      const comment = {
        userId: user._id,
        username: user.username,
        avatar: user.avatar || '/uploads/default-avatar.png',
        content: data.content
      };

      post.comments.push(comment);
      await post.save();
      
      io.emit('updateComments', {
        postId: data.postId,
        comment: comment
      });
    } catch (err) {
      console.error('Error creating comment:', err);
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});


// 修改密码
app.put('/api/users/:username/password', validateRequestBody(['oldPassword', 'password']), async (req, res) => {
  try {
    const { username } = req.params;
    const { oldPassword, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: '用户未找到' });
    }

    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isOldPasswordValid) {
      return res.status(401).json({ message: '旧密码无效' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: '密码更新成功' });
  } catch (error) {
    console.error('更新密码时出错:', error);
    res.status(500).json({ message: '更新密码失败', error: error.message });
  }
});

// 点赞或取消点赞
let posts = [
  {
    id: '1',
    userId: 'user1',
    username: 'User One',
    avatar: '/uploads/default-avatar.png',
    content: 'This is a sample post',
    images: [],
    likes: 0,
    likedBy: [],
    comments: [],
    shares: 0,
    createdAt: new Date()
  }
  
];

// 点赞或取消点赞
app.post('/api/posts/:id/like', async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.body.userId;

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ message: '帖子未找到' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: '用户未找到' });
    }

    const likedIndex = post.likedBy.findIndex(like => like.userId.toString() === userId);
    
    if (likedIndex === -1) {
      // 添加点赞
      post.likedBy.push({
        userId: user._id,
        username: user.username,
        avatar: user.avatar
      });
      post.likes += 1;
    } else {
      // 取消点赞
      post.likedBy.splice(likedIndex, 1);
      post.likes -= 1;
    }

    await post.save();
    io.emit('updateLikes', { postId: post._id, likes: post.likes, likedBy: post.likedBy });
    res.json(post);
  } catch (err) {
    res.status(500).json({ message: '点赞操作失败', error: err.message });
  }
});
// 开启服务器
server.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});

app.get("/dt.html", (req, res)=>{
  return res.render("dt")
})
app.get("/Login.html", (req, res)=>{
  return res.render("Login")
} )
app.get("/register.html", (req, res)=>{
  return res.render("register")
} )

app.get("/Navigation.html", (req, res)=>{
  return res.render("Navigation")
} )

app.get("/Changepassword.html", (req, res)=>{
  return res.render("Changepassword")
} )
app.get("/Weather.html", (req, res)=>{
  return res.render("Weather")
} )

app.get("/Admin.html", (req, res)=>{
  return res.render("Admin")
} )
app.get("/forum.html", (req, res)=>{
  return res.render("forum")
} )
app.get("/ManageData.html", (req, res)=>{
  return res.render("ManageData")
} )

// 转发评论
app.post('/api/posts/:postId/comments/:commentId/share', async (req, res) => {
    try {
        const { postId, commentId } = req.params;
        const { userId, additionalContent } = req.body;

        const originalPost = await Post.findById(postId);
        if (!originalPost) {
            return res.status(404).json({ message: 'Post not found' });
        }

        const originalComment = originalPost.comments.id(commentId);
        if (!originalComment) {
            return res.status(404).json({ message: 'Comment not found' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // 创建新帖子，包含用户添加的内容和原评论
        const newPostContent = additionalContent ? 
          `${additionalContent}\n\n转发评论: "${originalComment.content}" —— 来自 ${originalComment.username}` :
          `转发评论: "${originalComment.content}" —— 来自 ${originalComment.username}`;

        const newPost = new Post({
            userId: user._id,
            username: user.username,
            avatar: user.avatar || '/uploads/default-avatar.png',
            content: newPostContent,
            image: originalPost.image
        });

        await newPost.save();
        
        io.emit('newPost', newPost);
        
        res.status(201).json(newPost);
    } catch (err) {
        console.error('Error sharing comment:', err);
        res.status(500).json({ message: '转发评论失败', error: err.message });
    }
});
