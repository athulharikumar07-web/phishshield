const ABUSEIPDB_KEY = '	a6c368e46f0bf0ee03d7cce7242787804247e697bc396a5733e79c724eeaf053b1c9b11d18ead004';

async function analyzeContent() {
    const text = document.getElementById('emailContent').value.toLowerCase();
    let urlInput = document.getElementById('urlInput').value.trim();
    const resultsDiv = document.getElementById('results');
    const btn = document.querySelector('button');

    let score = 0;
    let nlpReasons = [];
    let urlReasons = [];
    let verdict = "Legitimate";

    btn.innerText = "Scanning Threat DBs...";
    btn.disabled = true;

    // --- 1. NLP Analysis ---
    const urgencyWords = ['urgent', 'immediately', 'suspended', 'unauthorized', 'action required'];
    urgencyWords.forEach(word => {
        if (text.includes(word)) score += 15;
    });
    if (text.includes('dear customer') || text.includes('dear user')) {
        score += 10;
        nlpReasons.push("Generic greeting detected.");
    }

    // --- 2. URL & IP Reputation Analysis ---
    if (urlInput) {
        // Clean the URL to get the hostname (e.g., https://evil.com/path -> evil.com)
        let hostname = urlInput.replace(/^(?:https?:\/\/)?(?:www\.)?/i, "").split('/')[0];

        // Basic URL checks
        if (urlInput.includes('bit.ly') || urlInput.includes('t.co')) {
            score += 20;
            urlReasons.push("Link shortener detected.");
        }

        try {
            // STEP A: Get IP address of the domain using Cloudflare DNS
            const dnsRes = await fetch(`https://cloudflare-dns.com/query?name=${hostname}&type=A`, {
                headers: { 'Accept': 'application/dns-json' }
            });
            const dnsData = await dnsRes.json();
            
            if (dnsData.Answer && dnsData.Answer.length > 0) {
                const ipAddress = dnsData.Answer[0].data;

                // STEP B: Check the IP against AbuseIPDB
                const abuseRes = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ipAddress}&maxAgeInDays=90`, {
                    method: 'GET',
                    headers: {
                        'Key': ABUSEIPDB_KEY,
                        'Accept': 'application/json'
                    }
                });

                const abuseData = await abuseRes.json();
                const abuseScore = abuseData.data.abuseConfidenceScore;

                if (abuseScore > 0) {
                    score += (abuseScore / 2); // Add half of confidence score to our total
                    urlReasons.push(`IP Reputation: ${abuseScore}% abuse confidence (${ipAddress}).`);
                }
            }
        } catch (error) {
            console.error("AbuseIPDB Error:", error);
            urlReasons.push("Could not reach Reputation Database.");
        }
    }

    // --- 3. Final Categorization ---
    if (score > 80) verdict = "Phishing";
    else if (score > 40) verdict = "Suspicious";

    // Update UI
    document.getElementById('riskScore').innerText = Math.min(Math.round(score), 100);
    document.getElementById('verdict').innerText = verdict;
    document.getElementById('nlpAnalysis').innerText = nlpReasons.join(' ') || "No major linguistic red flags.";
    document.getElementById('urlAnalysis').innerText = urlReasons.join(' ') || "URL/IP appears clean.";
    
    document.getElementById('safetyTip').innerText = score > 40 ? 
        "High Risk: This IP or content has been flagged for malicious activity." : 
        "No immediate threats identified.";

    btn.innerText = "Run Security Audit";
    btn.disabled = false;
    resultsDiv.classList.remove('hidden');
}