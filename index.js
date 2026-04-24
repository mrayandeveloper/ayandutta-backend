require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const validator = require('validator'); // npm install validator
const createDOMPurify = require('dompurify'); // npm install dompurify
const { JSDOM } = require('jsdom');           // npm install jsdom

const app = express();

// ─── CORS (lock to your frontend origin in production) ─────────────────────
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*'
}));
app.use(express.json({ limit: '10kb' })); // 🛡️ Reject oversized payloads

// ─── DOMPurify setup (server-side XSS sanitizer) ───────────────────────────
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// ─── Helper: sanitize plain text (strip all HTML tags + trim) ──────────────
function sanitizeText(str) {
  if (typeof str !== 'string') return '';
  return DOMPurify.sanitize(str, { ALLOWED_TAGS: [] }).trim();
}

// ─── SMTP Transport ─────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

transporter.verify((err) => {
  if (err) console.error("❌ SMTP Error:", err);
  else     console.log("✅ SMTP Server Ready");
});

// ─── POST /send ─────────────────────────────────────────────────────────────
app.post('/send', async (req, res) => {

  // 1️⃣  Sanitize inputs first (before any validation)
  const name    = sanitizeText(req.body.name);
  const email   = sanitizeText(req.body.email);
  const subject = sanitizeText(req.body.subject);
  const message = sanitizeText(req.body.message);

  // 2️⃣  Presence check
  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: "All fields are required." });
  }

  // 3️⃣  Strict email validation
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: "Invalid email address." });
  }

  // 4️⃣  Length limits (prevent huge payloads slipping through)
  if (name.length > 100) {
    return res.status(400).json({ error: "Name too long (max 100 chars)." });
  }
  if (subject.length > 200) {
    return res.status(400).json({ error: "Subject too long (max 200 chars)." });
  }
  if (message.length > 5000) {
    return res.status(400).json({ error: "Message too long (max 5000 chars)." });
  }

  // 5️⃣  Block disposable / clearly fake email domains (optional but useful)
  const blockedDomains = ['mailinator.com', 'trashmail.com', 'guerrillamail.com', 'tempmail.com'];
  const emailDomain = email.split('@')[1].toLowerCase();
  if (blockedDomains.includes(emailDomain)) {
    return res.status(400).json({ error: "Disposable email addresses are not allowed." });
  }

  try {

    // ── 📬 Admin Notification Email ──────────────────────────────────────
    const adminMail = {
      from: process.env.EMAIL_FROM,
      to: process.env.EMAIL_USER,
      replyTo: email,
      subject: `📩 New Contact: ${subject}`,
      html: `
        <!DOCTYPE html>
        <html>
        <body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td align="center" style="padding:30px 0;">
              <table width="600" cellpadding="0" cellspacing="0"
                     style="background:#ffffff;border-radius:8px;overflow:hidden;
                            box-shadow:0 2px 8px rgba(0,0,0,.1);">
                <tr>
                  <td style="background:#1a1a2e;padding:24px 32px;">
                    <h2 style="margin:0;color:#ffffff;font-size:20px;">
                      📩 New Contact Form Submission
                    </h2>
                  </td>
                </tr>
                <tr>
                  <td style="padding:32px;">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="padding:10px 0;border-bottom:1px solid #eee;">
                          <span style="color:#888;font-size:13px;">NAME</span><br>
                          <strong style="font-size:16px;">${name}</strong>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:10px 0;border-bottom:1px solid #eee;">
                          <span style="color:#888;font-size:13px;">EMAIL</span><br>
                          <strong style="font-size:16px;">${email}</strong>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:10px 0;border-bottom:1px solid #eee;">
                          <span style="color:#888;font-size:13px;">SUBJECT</span><br>
                          <strong style="font-size:16px;">${subject}</strong>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:10px 0;">
                          <span style="color:#888;font-size:13px;">MESSAGE</span><br>
                          <p style="font-size:15px;line-height:1.6;margin:8px 0 0;">
                            ${message.replace(/\n/g, '<br>')}
                          </p>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td style="background:#f9f9f9;padding:16px 32px;text-align:center;">
                    <p style="margin:0;font-size:12px;color:#aaa;">
                      Received via your portfolio contact form
                    </p>
                  </td>
                </tr>
              </table>
            </td></tr>
          </table>
        </body>
        </html>
      `
    };

    // ── 📧 User Confirmation Email (Rich UX) ─────────────────────────────
    const userMail = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: "✅ Got your message — I'll be in touch!",
      html: `
        <!DOCTYPE html>
        <html>
        <body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td align="center" style="padding:40px 0;">
              <table width="600" cellpadding="0" cellspacing="0"
                     style="background:#ffffff;border-radius:12px;overflow:hidden;
                            box-shadow:0 2px 12px rgba(0,0,0,.1);">

                <!-- Header -->
                <tr>
                  <td style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);
                              padding:40px 32px;text-align:center;">
                    <div style="width:64px;height:64px;background:rgba(255,255,255,.1);
                                border-radius:50%;margin:0 auto 16px;line-height:64px;
                                font-size:30px;">✉️</div>
                    <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:700;">
                      Message Received!
                    </h1>
                    <p style="margin:8px 0 0;color:rgba(255,255,255,.7);font-size:15px;">
                      Thanks for reaching out, ${name} 👋
                    </p>
                  </td>
                </tr>

                <!-- Body -->
                <tr>
                  <td style="padding:36px 32px;">
                    <p style="margin:0 0 20px;font-size:16px;color:#333;line-height:1.7;">
                      I've received your message and will get back to you as soon as possible —
                      usually within <strong>24–48 hours</strong>. 🚀
                    </p>

                    <!-- Message summary box -->
                    <div style="background:#f8f9ff;border-left:4px solid #1a1a2e;
                                border-radius:4px;padding:20px 24px;margin:24px 0;">
                      <p style="margin:0 0 12px;font-size:13px;color:#888;
                                text-transform:uppercase;letter-spacing:1px;">
                        YOUR MESSAGE SUMMARY
                      </p>
                      <p style="margin:0 0 6px;font-size:14px;color:#555;">
                        <strong>Subject:</strong> ${subject}
                      </p>
                      <p style="margin:0;font-size:14px;color:#555;line-height:1.6;">
                        <strong>Message:</strong><br>
                        ${message.replace(/\n/g, '<br>')}
                      </p>
                    </div>

                    <p style="margin:0;font-size:15px;color:#444;line-height:1.7;">
                      While you wait, feel free to check out my work or connect with me
                      on social media. Talk soon! 😊
                    </p>
                  </td>
                </tr>

                <!-- Divider -->
                <tr>
                  <td style="padding:0 32px;">
                    <hr style="border:none;border-top:1px solid #eee;margin:0;">
                  </td>
                </tr>

                <!-- Footer -->
                <tr>
                  <td style="padding:24px 32px;text-align:center;background:#fafafa;">
                    <p style="margin:0 0 4px;font-size:13px;color:#999;">
                      This is an automated confirmation. Please do not reply to this email.
                    </p>
                    <p style="margin:0;font-size:12px;color:#bbb;">
                      © ${new Date().getFullYear()} Your Portfolio
                    </p>
                  </td>
                </tr>

              </table>
            </td></tr>
          </table>
        </body>
        </html>
      `
    };

    // 🔥 Send both in parallel
    await Promise.all([
      transporter.sendMail(adminMail),
      transporter.sendMail(userMail)
    ]);

    res.status(200).json({ message: "✅ Message sent & confirmation delivered!" });

  } catch (err) {
    console.error("❌ Mail Error:", err.message);
    res.status(500).json({ error: "Failed to send email. Please try again later." });
  }
});

// ─── Start Server ────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';
app.listen(PORT, HOST, () => {
  console.log(`🚀 Server running at http://${HOST}:${PORT}`);
});
