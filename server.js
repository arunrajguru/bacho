
require('dotenv').config();
const express = require('express');
const { google } = require('googleapis');
const cors = require('cors');
const session = require('express-session');
const axios = require('axios');
const detector = require('./detector');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
    origin: 'http://localhost:5000', // Update if frontend is served differently
    credentials: true
}));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'bacho-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Serve static files (frontend)
app.use(express.static('.'));

const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || 'http://localhost:5000/auth/google/callback'
);

const SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify'
];

// ── AUTH ROUTES ──

app.get('/auth/google', (req, res) => {
    const url = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
    });
    res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
    const { code } = req.query;
    try {
        const { tokens } = await oauth2Client.getToken(code);
        req.session.tokens = tokens;
        res.redirect('/#inbox'); // Redirect back to frontend
    } catch (error) {
        console.error('Error retrieving access token', error);
        res.status(500).send('Authentication failed');
    }
});

app.get('/auth/status', (req, res) => {
    const isMock = !process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID === 'your_client_id_here';
    res.json({ 
        authenticated: !!req.session.tokens || isMock,
        isMock: isMock
    });
});

app.post('/auth/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// ── GMAIL API LOGIC ──

async function getGmailService(tokens) {
    const client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        process.env.GOOGLE_REDIRECT_URI
    );
    client.setCredentials(tokens);
    return google.gmail({ version: 'v1', auth: client });
}

app.get('/emails/fetch', async (req, res) => {
    // ── MOCK MODE DETECTION ──
    const isMock = !process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID === 'your_client_id_here';

    if (isMock) {
        // Return realistic demo data for testing
        return res.json([
            {
                id: 'mock1',
                subject: 'URGENT: Selection for Web Development Internship',
                from: 'HR Team <hr@startup-growth.co>',
                snippet: 'Congratulations! You have been selected. Please pay the registration fee...',
                body: 'Congratulations! You have been selected for a virtual internship. To confirm, pay ₹999 to our UPI ID...',
                risk: 'HIGH',
                score: 85,
                attachments: [{ filename: 'internship_offer.pdf.exe', risk: { risk: 'HIGH', flags: ['Possible double extension detected'] } }]
            },
            {
                id: 'mock2',
                subject: 'Interview Schedule: Software Engineer Intern',
                from: 'Google Recruitment <no-reply@google.com>',
                snippet: 'Dear Applicant, your interview is scheduled for tomorrow at 10 AM...',
                body: 'Hello, your interview is scheduled. There are no fees involved in our process...',
                risk: 'SAFE',
                score: 5,
                attachments: [{ filename: 'guidelines.pdf', risk: { risk: 'LOW', flags: [] } }]
            },
            {
                id: 'mock3',
                subject: 'Last 5 seats left! Enroll now for summer program',
                from: 'EduTech India <contact@edutech.in>',
                snippet: 'Only a few spots remaining. Apply now to secure your certificate...',
                body: 'Hurry! Limited seats available for our summer training. Apply ASAP within 24 hours!',
                risk: 'MEDIUM',
                score: 45,
                attachments: []
            }
        ]);
    }

    if (!req.session.tokens) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const gmail = await getGmailService(req.session.tokens);
        
        // Fetch last 30 unread or recent emails
        const listRes = await gmail.users.messages.list({
            userId: 'me',
            maxResults: 30,
            q: 'label:INBOX' // You can add 'is:unread' if desired
        });

        const messages = listRes.data.messages || [];
        const emailData = [];

        for (const msg of messages) {
            const detail = await gmail.users.messages.get({
                userId: 'me',
                id: msg.id
            });

            const payload = detail.data.payload;
            const headers = payload.headers;
            
            const subject = headers.find(h => h.name === 'Subject')?.value || '(No Subject)';
            const from = headers.find(h => h.name === 'From')?.value || '(Unknown Sender)';
            
            // Extract body
            let body = '';
            if (payload.parts) {
                const textPart = payload.parts.find(p => p.mimeType === 'text/plain');
                if (textPart && textPart.body.data) {
                    body = Buffer.from(textPart.body.data, 'base64').toString();
                } else if (payload.parts[0].parts) {
                    // Handle multipart/alternative
                    const subPart = payload.parts[0].parts.find(p => p.mimeType === 'text/plain');
                    if (subPart && subPart.body.data) {
                        body = Buffer.from(subPart.body.data, 'base64').toString();
                    }
                }
            } else if (payload.body.data) {
                body = Buffer.from(payload.body.data, 'base64').toString();
            }

            // Extract attachments metadata
            const attachments = (payload.parts || [])
                .filter(p => p.filename && p.filename.length > 0)
                .map(p => ({
                    filename: p.filename,
                    mimeType: p.mimeType,
                    risk: detector.analyzeAttachment(p.filename)
                }));

            // Analyze content
            const analysis = detector.analyze(body);
            
            // Final risk takes attachments into account
            let finalRisk = analysis.risk;
            if (attachments.some(a => a.risk.risk === "HIGH")) {
                finalRisk = "HIGH";
            }

            emailData.push({
                id: msg.id,
                subject,
                from,
                snippet: detail.data.snippet,
                body: body.substring(0, 5000), // Return more content for full analysis
                risk: finalRisk,
                score: analysis.score,
                attachments: attachments
            });
        }

        res.json(emailData);
    } catch (error) {
        console.error('Error fetching emails:', error);
        res.status(500).json({ error: 'Failed to fetch emails' });
    }
});

// ── VIRUSTOTAL INTEGRATION ──
async function scanUrlsInText(text) {
    const urlRegex = /https?:\/\/[^\s]+/g;
    const urls = text.match(urlRegex) || [];
    const uniqueUrls = [...new Set(urls)];
    const results = [];

    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey || apiKey === 'your_vt_api_key_here') {
        return null; // VT Scan disabled
    }

    // Limit to first 3 URLs to avoid hitting rate limits
    for (const url of uniqueUrls.slice(0, 3)) {
        try {
            const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
            const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
                headers: { 'x-apikey': apiKey },
                timeout: 5000
            });
            const stats = response.data.data.attributes.last_analysis_stats;
            results.push({
                url,
                malicious: stats.malicious,
                suspicious: stats.suspicious,
                total: stats.malicious + stats.suspicious + stats.harmless + stats.undetected
            });
        } catch (error) {
            results.push({ url, status: 'not_found_or_error' });
        }
    }
    return results;
}

app.post('/emails/analyze', async (req, res) => {
    const { message } = req.body;
    const result = detector.analyze(message);
    
    // Add VT results
    const vtResults = await scanUrlsInText(message);
    if (vtResults) {
        result.vt = vtResults;
        // If VT finds malicious URLs, bump risk to HIGH
        if (vtResults.some(r => r.malicious > 0)) {
            result.risk = "HIGH";
            result.score = Math.max(result.score, 90);
        }
    }
    
    res.json(result);
});

app.post('/emails/spam', async (req, res) => {
    const { messageId } = req.body;
    
    // Mock mode check
    const isMock = !process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID === 'your_client_id_here';
    if (isMock) {
        return res.json({ success: true, message: 'Moved to spam (MOCK)' });
    }

    if (!req.session.tokens) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const gmail = await getGmailService(req.session.tokens);
        await gmail.users.messages.modify({
            userId: 'me',
            id: messageId,
            resource: {
                addLabelIds: ['SPAM'],
                removeLabelIds: ['INBOX']
            }
        });
        res.json({ success: true, message: 'Successfully moved to spam' });
    } catch (error) {
        console.error('Error moving to spam:', error);
        res.status(500).json({ error: 'Failed to move to spam' });
    }
});

app.post('/analyze', async (req, res) => {
    const { message } = req.body;
    const result = detector.analyze(message);
    
    const vtResults = await scanUrlsInText(message);
    if (vtResults) {
        result.vt = vtResults;
        if (vtResults.some(r => r.malicious > 0)) {
            result.risk = "HIGH";
            result.score = Math.max(result.score, 90);
        }
    }
    
    res.json(result);
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
