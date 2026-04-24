require('dotenv').config();

const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const serverless = require('serverless-http');

const app = express();

// ─── SECURITY MIDDLEWARE ─────────────────────────────────────────────
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*'
}));

app.use(express.json({ limit: '10kb' }));

// 🔥 Rate Limiter (anti-spam)
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 5,
  message: { error: "Too many requests. Try again later." }
});
app.use('/send', limiter);

// ─── SIMPLE SANITIZER (Vercel Safe) ───────────────────────────────────
function sanitizeText(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g, '').trim();
}

// ─── SMTP CONFIG ─────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Verify SMTP
transporter.verify((err) => {
  if (err) console.error("❌ SMTP Error:", err);
  else console.log("✅ SMTP Ready");
});

// ─── HEALTH CHECK ────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: "API Running 🚀" });
});

// ─── CONTACT ROUTE ───────────────────────────────────────────────────
app.post('/send', async (req, res) => {

  const name    = sanitizeText(req.body.name);
  const email   = sanitizeText(req.body.email);
  const subject = sanitizeText(req.body.subject);
  const message = sanitizeText(req.body.message);

  // Validation
  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: "All fields are required." });
  }

  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: "Invalid email address." });
  }

  if (name.length > 100 || subject.length > 200 || message.length > 5000) {
    return res.status(400).json({ error: "Input too large." });
  }

  const blockedDomains = [
    'mailinator.com',
    'trashmail.com',
    'guerrillamail.com',
    'tempmail.com'
  ];

  const emailDomain = email.split('@')[1]?.toLowerCase();
  if (blockedDomains.includes(emailDomain)) {
    return res.status(400).json({ error: "Disposable emails not allowed." });
  }

  try {

    // 📬 ADMIN EMAIL
    const adminMail = {
      from: process.env.EMAIL_FROM,
      to: process.env.EMAIL_USER,
      replyTo: email,
      subject: `📩 New Contact: ${subject}`,
      html: `
        <h3>New Contact Message</h3>
        <p><b>Name:</b> ${name}</p>
        <p><b>Email:</b> ${email}</p>
        <p><b>Subject:</b> ${subject}</p>
        <p><b>Message:</b><br>${message}</p>
      `
    };

    // 📧 USER CONFIRMATION
    const userMail = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: "✅ Message Received",
      html: `
        <h2>Hi ${name},</h2>
        <p>Thanks for reaching out! 🚀</p>
        <p>We’ve received your message and will get back to you soon.</p>
        <hr>
        <p><b>Your Message:</b><br>${message}</p>
      `
    };

    // Send both emails
    await Promise.all([
      transporter.sendMail(adminMail),
      transporter.sendMail(userMail)
    ]);

    return res.status(200).json({
      success: true,
      message: "Message sent successfully"
    });

  } catch (err) {
    console.error("❌ Mail Error:", err);
    return res.status(500).json({
      error: "Failed to send email"
    });
  }
});

// ❌ DO NOT USE app.listen() on Vercel
// ✅ Export serverless function
module.exports = serverless(app);
