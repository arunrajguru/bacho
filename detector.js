
const detector = {
    keywords: {
        pay: [/₹\s*\d+/gi, /rs\.?\s*\d+/gi, /registration\s*(fee|charge|amount)/gi, /pay\s+(a|the|only|just|small)?\s*(fee|amount|charge)/gi, /certificate\s*(fee|charge|cost|payment)/gi, /training\s*(fee|charge|deposit)/gi, /upi|gpay|paytm|phonepe|neft|transfer\s+the\s+amount/gi, /processing\s+(fee|charge)/gi, /security\s+deposit/gi],
        urg: [/limited\s+seats?/gi, /apply\s+(now|immediately|asap|today)/gi, /hurry[!.]*/gi, /last\s+chance/gi, /only\s+\d+\s+(spots?|seats?)\s*(left|remaining)?/gi, /don't\s+miss/gi, /within\s+24\s+hours?/gi, /reply\s+asap/gi, /\d+\s+seats?\s+(left|remaining)/gi],
        free: [/free\s+internship/gi, /no\s+cost\s+at\s+all/gi, /completely\s+free/gi, /zero\s+(cost|fee)/gi],
        prom: [/guaranteed\s+(placement|job)/gi, /100%\s+(job|placement)/gi, /placement\s+assistance/gi, /letter\s+of\s+recommendation/gi],
        beh: [/send\s+(the\s+)?screenshot/gi, /whatsapp.*\d{10}|\d{10}.*whatsapp/gi, /bit\.ly|tinyurl/gi]
    },

    countMatches(text, patterns) {
        let n = 0;
        for (const p of patterns) {
            const m = text.match(p);
            if (m) n += m.length;
        }
        return n;
    },

    analyze(text) {
        if (!text) return { score: 0, risk: "LOW" };
        
        const p = this.countMatches(text, this.keywords.pay);
        const u = this.countMatches(text, this.keywords.urg);
        const f = this.countMatches(text, this.keywords.free);
        const pr = this.countMatches(text, this.keywords.prom);
        const b = this.countMatches(text, this.keywords.beh);

        const hasP = p > 0;
        const hasF = f > 0;
        const hasC = /certificate/i.test(text);

        let score = p * 20 + u * 10 + f * 15 + pr * 8 + b * 12;
        if (hasF && hasP) score = Math.max(score, 72);
        if (hasF && hasP && hasC) score = Math.max(score, 78);
        if (/upi|gpay|paytm|phonepe/i.test(text)) score = Math.max(score, 70);
        
        score = Math.max(0, Math.min(100, Math.round(score)));

        let risk = "LOW";
        if (score >= 65) risk = "HIGH";
        else if (score >= 35) risk = "MEDIUM";

        return { score, risk };
    },

    analyzeAttachment(filename) {
        if (!filename) return { risk: "LOW", flags: [] };
        const flags = [];
        const ext = filename.split('.').pop().toLowerCase();
        
        // Suspicious types
        if (['exe', 'apk', 'zip', 'msi', 'bat', 'vbs', 'scr'].includes(ext)) {
            flags.push(`Suspicious file type: .${ext}`);
        }

        // Double extensions
        const parts = filename.toLowerCase().split('.');
        if (parts.length > 2) {
            const secondToLast = parts[parts.length - 2];
            const commonDocs = ['pdf', 'doc', 'docx', 'jpg', 'png', 'txt'];
            if (commonDocs.includes(secondToLast)) {
                flags.push(`Possible double extension detected: .${secondToLast}.${ext}`);
            }
        }

        return {
            risk: flags.length > 0 ? "HIGH" : "LOW",
            flags: flags
        };
    }
};

module.exports = detector;
