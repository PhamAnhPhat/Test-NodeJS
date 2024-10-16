const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const authRoutes = require('./routes/auth'); 
require('dotenv').config();

const app = express();


app.use(cors({
    origin: 'http://127.0.0.1:5500', 
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware để xử lý JSON
app.use(bodyParser.json());

app.use('/api/auth', authRoutes); 

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
