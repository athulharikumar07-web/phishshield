function analyzeContent() {
    const text = document.getElementById('emailContent').value.toLowerCase();
    const url = document.getElementById('urlInput').value.toLowerCase();
    const resultsDiv = document.getElementById('results');
    
    let score = 0;
    let nlpReasons = [];
    let urlReasons = [];

    // 1. NLP Analysis
    const urgencyWords = ['urgent', 'immediately', 'suspended', 'unauthorized', 'action required'];
    urgencyWords.forEach(word => {
        if (text.includes(word)) score += 15;
    });
    if (text.includes('dear customer') || text.includes('dear user')) {
        score += 10;
        nlpReasons.push("Generic greeting detected.");
    }

    // 2. URL Analysis
    if (url.includes('bit.ly') || url.includes('t.co')) {
        score += 20;
        urlReasons.push("Link shortener masks destination.");
    }
    if (url && !url.includes('https')) {
        score += 15;
        urlReasons.push("Insecure connection (No HTTPS).");
    }

    // 3. Risk Categorization
    let verdict = "Legitimate";
    if (score > 70) verdict = "Phishing";
    else if (score > 40) verdict = "Suspicious";

    // Update UI
    document.getElementById('riskScore').innerText = Math.min(score, 100);
    document.getElementById('verdict').innerText = verdict;
    document.getElementById('nlpAnalysis').innerText = nlpReasons.join(' ') || "No major linguistic red flags.";
    document.getElementById('urlAnalysis').innerText = urlReasons.join(' ') || "URL structure appears standard.";
    
    document.getElementById('safetyTip').innerText = score > 40 ? 
        "Do not click any links or provide credentials. Contact the institution through their official app or website." : 
        "Exercise caution, but no immediate threats were identified.";

    resultsDiv.classList.remove('hidden');
}
