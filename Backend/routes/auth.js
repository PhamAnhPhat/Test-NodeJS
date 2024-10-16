const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy'); 
const nodemailer = require('nodemailer'); 
const router = express.Router();
require('dotenv').config();

const users = []; 
const SECRET_KEY = '123456'; 


const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASS
    },
    tls: {
        rejectUnauthorized: false 
    }
});

// Register user
router.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ email, password: hashedPassword });
    res.send({ message: 'User registered successfully!' });
});

// Login user
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    
    if (!user) return res.status(404).send('User not found!');
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).send('Invalid password!');

    // Tạo mã MFA
    const secret = speakeasy.generateSecret();
    const token = jwt.sign({ email, secret: secret.base32 }, SECRET_KEY, { expiresIn: '15m' });

    // Điền thông tin chuẩn bị gửi OTP
    const otp = speakeasy.totp({ secret: secret.base32, encoding: 'base32' });
    const mailOptions = {
        from:  process.env.EMAIL,
        to: email,
        subject: 'Your MFA OTP',
        text: `Your OTP is ${otp}`
    };
    
    // Gửi MFA qua mail
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            console.log('Error while sending email:', err); 
        } else {
            console.log('Email sent:', info.response); 
        }
        
    });
   
    res.send({ token });
});

// Verify MFA OTP
router.post('/verify-mfa', (req, res) => {
    const { token, otp } = req.body;
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const isValidOTP = speakeasy.totp.verify({
            secret: decoded.secret,
            encoding: 'base32',
            token: otp,
            window: 1
        });
        
        if (isValidOTP) {
            const finalToken = jwt.sign({ email: decoded.email }, SECRET_KEY, { expiresIn: '1h' });
            res.send({ message: 'Login successful', token: finalToken });
        } else {
            res.status(400).send('Invalid OTP');
        }
    } catch (error) {
        res.status(401).send('Token expired or invalid');
    }
});

module.exports = router;
