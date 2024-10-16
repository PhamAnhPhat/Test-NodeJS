const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const authRoutes = require('./routes/auth'); // Đường dẫn tới file auth.js
require('dotenv').config();

const app = express();

// Middleware CORS phải được cấu hình trước khi sử dụng các routes
app.use(cors({
    origin: 'http://127.0.0.1:5500', // Cho phép frontend truy cập
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware để xử lý JSON
app.use(bodyParser.json());

app.use('/api/auth', authRoutes); // Gắn routes auth vào đường dẫn /api/auth

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
