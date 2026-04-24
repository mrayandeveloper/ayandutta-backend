require('dotenv').config();

const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const validator = require('validator');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const rateLimit = require('express-rate-limit');
const serverless = require('serverless-http'); // 🔥 for Vercel

const app = express();

// ─── Security Middleware ─────────────────────────────────────────────
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*'
}));

app.use(express.json({ limit: '10kb' }));

// 🔥 Rate limiter (5 requests/min per IP)
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: "Too many requests. Try again later." }
});
app.use('/send', limiter);

// ─── DOMPurify Setup ─────────────────────────────────────────────────
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

function sanitizeText(str) {
  if (typeof str !== 'string') return '';
  return DOMPurify.sanitize(str, { ALLOWED_TAGS: [] }).trim();
}

// ─── SMTP Transport ──────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

transporter.verify((err) => {
  if (err) console.error("❌ SMTP Error:", err);
  else console.log("✅ SMTP Ready");
});

// ─── Health Check (important for deployment debugging) ────────────────
app.get('/', (req, res) => {
  res.json({ status: "API Running 🚀" });
});

// ─── POST /send ──────────────────────────────────────────────────────
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
    return res.status(400).json({ error: "Invalid email." });
  }

  if (name.length > 100 || subject.length > 200 || message.length > 5000) {
    return res.status(400).json({ error: "Input too large." });
  }

  const blockedDomains = ['mailinator.com','trashmail.com','guerrillamail.com','tempmail.com'];
  const emailDomain = email.split('@')[1]?.toLowerCase();

  if (blockedDomains.includes(emailDomain)) {
    return res.status(400).json({ error: "Disposable emails not allowed." });
  }

  try {
    // 📬 Admin Mail
    const adminMail = {
      from: process.env.EMAIL_FROM,
      to: process.env.EMAIL_USER,
      replyTo: email,
      subject: `📩 New Contact: ${subject}`,
      html: `<h3>New Message</h3>
             <p><b>Name:</b> ${name}</p>
             <p><b>Email:</b> ${email}</p>
             <p><b>Subject:</b> ${subject}</p>
             <p><b>Message:</b><br>${message}</p>`
    };

    // 📧 User Mail
    const userMail = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: "✅ Message Received",
      html: `<h2>Hi ${name},</h2>
             <p>Thanks for contacting us. We'll reply soon.</p>
             <hr>
             <p><b>Your Message:</b><br>${message}</p>`
    };

    await Promise.all([
      transporter.sendMail(adminMail),
      transporter.sendMail(userMail)
    ]);

    res.status(200).json({
      success: true,
      message: "Message sent successfully"
    });

  } catch (err) {
    console.error("❌ Mail Error:", err);
    res.status(500).json({
      error: "Mail service failed"
    });
  }
});

// ❌ REMOVE app.listen for Vercel
// ✅ EXPORT for serverless
module.exports = serverless(app);
