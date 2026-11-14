/**
 * ShieldCheck detection engine.
 *
 * Pure logic, no DOM access. Works as a classic <script> in the browser
 * (exposes window.ShieldCheck) and via require() in Node for the tests.
 */
(function (root) {
  'use strict';

  // ---------------------------------------------------------------------------
  // Request detection
  // Mentioning a password or code is not a scam sign by itself ("Your code is
  // 482913. Never share it."). Credential rules only count when the same
  // sentence asks the reader to hand something over, and is not a safety notice.
  // ---------------------------------------------------------------------------
  const SHARE_REQUEST = /\b(?:(?:send|give|forward|provide)\s+(?:us|me|it|them|the|your|this|that|those)\b|share\b|tell\s+(?:us|me)\b|disclose\b|reply\s+(?:with|back)\b|text\s+(?:us|me|back)\b|read\s+(?:out|back|me|us|it)\b)/i;
  const ANY_REQUEST = new RegExp(SHARE_REQUEST.source + '|' +
    /\b(?:enter|type|input|confirm|verify|update|submit|re-?enter|fill\s+in)\b/.source, 'i');
  // "Never share this code", "We will never ask for your PIN", "No one from X will ever ask..."
  const SAFETY_NOTICE = /(?:\bnever\b|\bnot\b|n['’]t\b|\bno one\b|\bnobody\b)(?:\s+[\w'’]+){0,4}?\s+(?:share|give|tell|disclose|reveal|ask|request|need)\b/i;

  // Categorized trigger patterns with severity and educational explanations.
  // Each rule adds its weight once per message, however often it matches.
  const SCAM_RULES = {
    urgency: {
      category: 'Urgency & Pressure Tactics',
      description: 'Scammers manufacture artificial panic to make you act before thinking.',
      severity: 'high',
      patterns: [
        { regex: /\b(?:urgent|urgently|immediate action required|act now|immediate attention)\b/gi, label: 'Urgent demand', weight: 15 },
        { regex: /\b(?:within \d{1,2} ?(?:hours?|hrs?|minutes?|mins?)|immediately|right now|without delay)\b/gi, label: 'Tight deadline pressure', weight: 12 },
        { regex: /\b(?:account|card|access|service|profile)s? (?:will be |has been |have been |is |was |is now )?(?:temporarily |permanently )?(?:suspended|terminated|locked|closed|disabled|frozen|blocked|restricted|deactivated)\b/gi, label: 'Account threat', weight: 18 },
        { regex: /\b(?:license (?:will be |has been )?(?:terminated|suspended|cancelled|expired)|expires today)\b/gi, label: 'Service/License termination threat', weight: 18 },
        { regex: /\b(?:legal action|arrest warrant|law enforcement|court appearance|police)\b/gi, label: 'Legal threat', weight: 20 },
        { regex: /\b(?:last warning|final notice|final warning)\b/gi, label: 'Final warning trigger', weight: 14 },
        { regex: /\b(?:do not (?:restart|shut down|turn off|close)|leave this window open)\b/gi, label: 'Forced panic constraint', weight: 15 }
      ]
    },
    credentials: {
      category: 'Credential & Personal Data Harvesters',
      description: 'Legitimate companies almost never ask for credentials, OTPs, or passwords via messages.',
      severity: 'critical',
      patterns: [
        { regex: /\b(?:passwords?|passcodes?|pin(?:s|\s?codes?|\s?numbers?)?|security codes?)\b/gi, label: 'Password/PIN request', weight: 22, request: ANY_REQUEST },
        // Legit OTP texts say "enter this code", so only asking to *share* a code counts here.
        { regex: /\b(?:otp|one[- ]time (?:password|passcode|code|pin)|verification codes?|auth(?:entication)? codes?|2fa codes?)\b/gi, label: '2FA/OTP code request', weight: 25, request: SHARE_REQUEST },
        { regex: /\b(?:ssn|social security(?: number)?|national insurance(?: number)?|tax id|id card number)\b/gi, label: 'Government ID request', weight: 25, request: ANY_REQUEST },
        { regex: /\b(?:credit card|debit card|cvv|cvc|card number|card details|expiration date|expiry date)\b/gi, label: 'Payment card details request', weight: 22, request: ANY_REQUEST },
        { regex: /\b(?:verify your identity|confirm your identity|update your billing info(?:rmation)?|re-enter your details)\b/gi, label: 'Identity verification bait', weight: 16, request: ANY_REQUEST }
      ]
    },
    financial: {
      category: 'Financial Bait & Demands',
      description: 'Unsolicited money, prizes, unexpected fees, or demands for untraceable payment.',
      severity: 'high',
      patterns: [
        { regex: /\b(?:gift cards?|apple gift card|itunes card|google play card|steam card)\b/gi, label: 'Gift card payment request (Classic scam)', weight: 25 },
        { regex: /\b(?:wire transfer|western union|moneygram|crypto(?:currency)?|bitcoin|usdt|cash app|venmo|zelle)\b/gi, label: 'Untraceable payment method', weight: 18 },
        { regex: /\b(?:you(?:'?ve| have) won|lottery|sweepstakes|jackpot|prize of|claim your reward)\b/gi, label: 'Unsolicited prize bait', weight: 20 },
        { regex: /\b(?:refund (?:pending|processed|waiting|ready)|reimbursement of|overpayment)\b/gi, label: 'Fake refund bait', weight: 15 },
        { regex: /\b(?:unauthorized (?:transaction|charge|purchase|payment|activity))\b/gi, label: 'Fabricated unauthorized charge', weight: 16 },
        { regex: /\b(?:processing fee|redelivery fee|customs fee|clearance fee)\b/gi, label: 'Small upfront fee trap', weight: 14 }
      ]
    },
    impersonation: {
      category: 'Vague Salutation & Fake Authority',
      description: 'Impersonators often use generic greetings or masquerade as official support teams.',
      severity: 'medium',
      patterns: [
        { regex: /\b(?:dear (?:customer|user|client|valued customer|account holder|sir\/madam|member))\b/gi, label: 'Generic anonymous greeting', weight: 10 },
        { regex: /\b(?:official support|helpdesk team|fraud prevention department|security operations|service desk)\b/gi, label: 'Vague security department claim', weight: 12 },
        { regex: /\b(?:microsoft support|apple support|amazon support|chase security|netflix support|geek squad|paypal support|usps support)\b/gi, label: 'High-profile brand impersonation', weight: 12 },
        { regex: /\b(?:system administrator|tech team|server admin)\b/gi, label: 'Generic IT authority claim', weight: 10 }
      ]
    },
    securityThreats: {
      category: 'Fake Security Alerts & Phone Traps',
      description: 'Scammers fabricate fake infections or breaches to coerce victims into calling fraudulent call centers.',
      severity: 'critical',
      patterns: [
        { regex: /\b(?:trojan(?: virus)?|malware detected|spyware|ransomware|system infected|critical virus)\b/gi, label: 'Fake virus/trojan alert', weight: 24 },
        { regex: /\b(?:call (?:microsoft|apple|support|helpdesk|fraud|security|us immediately|toll-free)|call \+?1?[-. ]?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4})\b/gi, label: 'Fraudulent support phone trap', weight: 22 },
        { regex: /\b(?:anydesk|teamviewer|ultraviewer|quick assist|remote desktop|remote access)\b/gi, label: 'Remote desktop access solicitation', weight: 25 },
        { regex: /\b(?:compromised your (?:system|credentials|data|files)|device is locked)\b/gi, label: 'System compromise scare tactic', weight: 18 }
      ]
    },
    formatting: {
      category: 'Suspicious Formatting & Tone',
      description: 'Excessive punctuation, all-caps yelling, and unnatural grammar patterns.',
      severity: 'low',
      patterns: [
        { regex: /!{2,}|\?{2,}/g, label: 'Excessive punctuation (!/?)', weight: 8 },
        // 5+ letters so short acronyms (USPS, FAQ, ATM) are not treated as shouting
        { regex: /\b[A-Z]{5,}\b/g, label: 'Aggressive ALL-CAPS words', weight: 6 }
      ]
    }
  };

  // ---------------------------------------------------------------------------
  // Link inspection data
  // ---------------------------------------------------------------------------

  // Known high-risk TLDs often used by phishing campaigns
  const SUSPICIOUS_TLDS = [
    'xyz', 'top', 'click', 'live', 'club', 'work', 'loan', 'download',
    'stream', 'racing', 'win', 'vip', 'gq', 'ml', 'cf', 'ga', 'tk',
    'rest', 'fit', 'buzz', 'cc', 'link', 'country'
  ];

  // Legitimate brands frequently impersonated
  const TARGETED_BRANDS = [
    'paypal', 'apple', 'amazon', 'microsoft', 'netflix', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'usps', 'fedex', 'ups',
    'dhl', 'facebook', 'instagram', 'google', 'ebay', 'walmart', 'binance'
  ];

  // Brand-owned domains that don't follow the brand.tld pattern
  const OFFICIAL_BRAND_DOMAINS = [
    'facebookmail.com', 'paypalobjects.com', 'microsoftonline.com', 'googleusercontent.com'
  ];

  // Character swaps used to imitate brand names (paypa1, micr0soft, arnazon).
  // `real` is the genuine spelling, which must not be flagged.
  const LOOKALIKE_PATTERNS = [
    { regex: /paypa[1il]/gi, brand: 'PayPal', real: 'paypal' },
    { regex: /micr[o0]s[o0]ft/gi, brand: 'Microsoft', real: 'microsoft' },
    { regex: /arnaz[o0]n|amaz0n/gi, brand: 'Amazon', real: 'amazon' },
    { regex: /netf[1l]ix/gi, brand: 'Netflix', real: 'netflix' },
    { regex: /app[1l]e/gi, brand: 'Apple', real: 'apple' }
  ];

  // Shortener services
  const URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
    'ow.ly', 'cutt.ly', 'rb.gy', 'shorte.st', 'tiny.cc'
  ];

  // Public suffixes with two labels, so amazon.co.uk resolves to "amazon.co.uk", not "co.uk"
  const TWO_LEVEL_SUFFIXES = [
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'gov.au',
    'co.nz', 'com.sg', 'gov.sg', 'com.my', 'gov.my', 'co.in', 'gov.in', 'co.jp',
    'com.br', 'com.mx', 'co.za', 'com.hk', 'com.ph', 'com.cn', 'com.tw', 'co.kr'
  ];

  // TLDs recognised for links written without http:// or www. (e.g. "usps-fee.top/pay")
  const BARE_DOMAIN_TLDS = [
    'com', 'net', 'org', 'info', 'biz', 'io', 'co', 'me', 'ly', 'gd', 'app',
    'online', 'site', 'shop', 'store', 'support', 'uk', 'us', 'ca', 'au', 'nz',
    'sg', 'my', 'in', 'ie', 'hk', 'ph'
  ].concat(SUSPICIOUS_TLDS);

  const URL_CHARS = /[^\s<>"'{}|\\^`[\]]/.source;
  const URL_REGEX = new RegExp(
    '(?:https?:\\/\\/|www\\.)' + URL_CHARS + '+' +
    '|\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:' + BARE_DOMAIN_TLDS.join('|') + ')\\b(?:\\/' + URL_CHARS + '*)?',
    'gi'
  );

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  // A sentence ends at ! ? newline, or a full stop followed by whitespace,
  // so the dots inside a URL don't split it.
  function isSentenceEnd(text, i) {
    const c = text[i];
    if (c === '!' || c === '?' || c === '\n') return true;
    return c === '.' && (i + 1 >= text.length || /\s/.test(text[i + 1]));
  }

  function sentenceAround(text, start, end) {
    let from = start;
    while (from > 0 && !isSentenceEnd(text, from - 1)) from--;
    let to = end;
    while (to < text.length && !isSentenceEnd(text, to)) to++;
    return text.slice(from, to);
  }

  function isRequest(text, start, end, requestPattern) {
    const sentence = sentenceAround(text, start, end);
    return requestPattern.test(sentence) && !SAFETY_NOTICE.test(sentence);
  }

  // Drop sentence punctuation stuck to the end of a link ("...fix." or "(see x.com)")
  function trimUrl(raw) {
    let url = raw;
    for (;;) {
      url = url.replace(/[.,;:!?'"’”]+$/, '');
      const opens = (url.match(/\(/g) || []).length;
      const closes = (url.match(/\)/g) || []).length;
      if (url.endsWith(')') && closes > opens) {
        url = url.slice(0, -1);
        continue;
      }
      return url;
    }
  }

  function registrableDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    const lastTwo = parts.slice(-2).join('.');
    return parts.slice(TWO_LEVEL_SUFFIXES.includes(lastTwo) ? -3 : -2).join('.');
  }

  // Returns the brand a hostname pretends to be, or null.
  // "chase-security-verify.xyz" -> "chase"; "secure.chase.com" and "amazon.co.uk" -> null.
  function impersonatedBrand(hostname, registrable) {
    if (OFFICIAL_BRAND_DOMAINS.includes(registrable)) return null;
    const label = registrable.split('.')[0];
    const tld = registrable.slice(label.length + 1);
    const tokens = hostname.split(/[.-]/);

    for (const brand of TARGETED_BRANDS) {
      // Whole words only for short brands, so "groups" doesn't match "ups" or "purchase" match "chase"
      const mentioned = tokens.some(t => t === brand || (brand.length >= 5 && t.startsWith(brand)));
      if (!mentioned) continue;
      const looksOfficial = label === brand && !SUSPICIOUS_TLDS.includes(tld);
      if (!looksOfficial) return brand;
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // URL inspection
  // ---------------------------------------------------------------------------

  /**
   * Extracts and inspects URLs found in text for phishing indicators
   */
  function inspectURLs(text) {
    const urlRegex = new RegExp(URL_REGEX.source, URL_REGEX.flags);
    const matches = [];
    let match;

    while ((match = urlRegex.exec(text)) !== null) {
      const rawUrl = trimUrl(match[0]);
      if (!rawUrl) continue;
      const startIndex = match.index;
      const endIndex = startIndex + rawUrl.length;

      let hostname = '';
      let hasUserInfo = false;
      try {
        const parsedUrl = new URL(/^https?:\/\//i.test(rawUrl) ? rawUrl : `http://${rawUrl}`);
        hostname = parsedUrl.hostname;
        hasUserInfo = Boolean(parsedUrl.username || parsedUrl.password);
      } catch (e) {
        hostname = rawUrl.replace(/^https?:\/\//i, '').split(/[/?#:]/)[0];
      }
      hostname = hostname.toLowerCase().replace(/\.$/, '');

      const issues = [];
      let urlRiskWeight = 0;
      const parts = hostname.split('.');
      const tld = parts[parts.length - 1];
      const registrable = registrableDomain(hostname);

      // Check 1: IP address used as host
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
        issues.push('Uses a raw numerical IP address instead of a recognized domain name');
        urlRiskWeight += 30;
      }

      // Check 2: "http://paypal.com@evil.example" really goes to evil.example
      if (hasUserInfo) {
        issues.push(`Hides the real destination (${hostname}) behind an "@" sign`);
        urlRiskWeight += 30;
      }

      // Check 3: Known URL shortener (hides real destination)
      if (URL_SHORTENERS.some(s => hostname === s || hostname.endsWith(`.${s}`))) {
        issues.push(`Uses a link shortener (${hostname}) which obscures the true destination`);
        urlRiskWeight += 18;
      }

      // Check 4: Suspicious TLD
      if (SUSPICIOUS_TLDS.includes(tld)) {
        issues.push(`Uses suspicious or high-risk domain extension (.${tld})`);
        urlRiskWeight += 20;
      }

      // Check 5: Brand name used in a domain the brand doesn't own
      const brand = impersonatedBrand(hostname, registrable);
      if (brand) {
        issues.push(`Uses the name "${brand}" but the actual domain is ${registrable}, not an official ${brand} website (possible lookalike)`);
        urlRiskWeight += 30;
      }

      // Check 6: Character swaps that imitate a brand (paypa1, micr0soft)
      for (const lp of LOOKALIKE_PATTERNS) {
        const found = hostname.match(lp.regex) || [];
        if (found.some(m => m.toLowerCase() !== lp.real)) {
          issues.push(`Domain mimics legitimate brand "${lp.brand}" using visual lookalike characters`);
          urlRiskWeight += 35;
          break;
        }
      }

      // Check 7: International characters disguised as normal letters (shown as xn-- punycode)
      if (parts.some(p => p.startsWith('xn--'))) {
        issues.push('Uses international characters that can imitate normal letters (lookalike domain)');
        urlRiskWeight += 30;
      }

      // Check 8: Multiple subdomains (domain nesting), e.g. paypal.com.secure.login.example.net
      const subdomains = parts.length - registrable.split('.').length - (parts[0] === 'www' ? 1 : 0);
      if (subdomains >= 3) {
        issues.push('Unusually long or deeply nested domain structure (often used to mislead)');
        urlRiskWeight += 12;
      }

      matches.push({
        rawUrl,
        hostname,
        startIndex,
        endIndex,
        issues,
        riskWeight: urlRiskWeight
      });
    }

    return matches;
  }

  // ---------------------------------------------------------------------------
  // Main analysis
  // ---------------------------------------------------------------------------

  const VERDICTS = {
    high: {
      level: 'high',
      badge: 'High Risk / Likely Scam',
      badgeClass: 'badge-danger',
      color: '#EF4444',
      description: 'Multiple critical warning signs detected! This message strongly resembles a social engineering or phishing attack.'
    },
    medium: {
      level: 'medium',
      badge: 'Moderate Caution',
      badgeClass: 'badge-warning',
      color: '#F59E0B',
      description: 'Contains warning triggers commonly used in manipulative or unsolicited outreach. Proceed with caution.'
    },
    low: {
      level: 'low',
      badge: 'Low Risk',
      badgeClass: 'badge-safe',
      color: '#10B981',
      description: 'Only minor warning signs were found. Still verify any request through the company\'s official app or website before acting.'
    },
    none: {
      level: 'low',
      badge: 'No Red Flags Found',
      badgeClass: 'badge-safe',
      color: '#10B981',
      description: 'No common scam warning signs were found. Scammers can still write convincing messages, so verify any request through the company\'s official app or website before acting.'
    }
  };

  /**
   * Main Analysis Function
   * Scans text, generates highlighted ranges, computes risk score and safety guidelines
   */
  function analyzeMessage(text) {
    if (typeof text !== 'string' || !text.trim()) {
      return null;
    }

    const flags = [];
    const highlights = [];
    let totalScore = 0;

    // 1. Scan Text Rules
    for (const [catKey, category] of Object.entries(SCAM_RULES)) {
      const categoryMatches = [];

      for (const rule of category.patterns) {
        const regex = new RegExp(rule.regex.source, rule.regex.flags);
        let counted = false;
        let match;

        while ((match = regex.exec(text)) !== null) {
          if (match[0] === '') { regex.lastIndex++; continue; }

          const matchedText = match[0];
          const startIndex = match.index;
          const endIndex = startIndex + matchedText.length;

          if (rule.request && !isRequest(text, startIndex, endIndex, rule.request)) {
            continue;
          }

          categoryMatches.push({
            matchedText,
            label: rule.label,
            weight: rule.weight,
            startIndex,
            endIndex
          });

          highlights.push({
            startIndex,
            endIndex,
            text: matchedText,
            severity: category.severity,
            category: category.category,
            reason: rule.label
          });

          // Repeating a word shouldn't stack the score
          if (!counted) {
            totalScore += rule.weight;
            counted = true;
          }
        }
      }

      if (categoryMatches.length > 0) {
        flags.push({
          key: catKey,
          name: category.category,
          description: category.description,
          severity: category.severity,
          matches: categoryMatches
        });
      }
    }

    // 2. Scan URLs
    const urlInspections = inspectURLs(text);
    const urlMatches = urlInspections.filter(u => u.issues.length > 0);

    urlMatches.forEach(urlObj => {
      totalScore += urlObj.riskWeight;
      highlights.push({
        startIndex: urlObj.startIndex,
        endIndex: urlObj.endIndex,
        text: urlObj.rawUrl,
        severity: 'critical',
        category: 'Suspicious Links',
        reason: urlObj.issues.join('; ')
      });
    });

    if (urlMatches.length > 0) {
      flags.push({
        key: 'links',
        name: 'Suspicious Web Links',
        description: 'Unusual, misleading, or obscured web links designed to mimic genuine login portals.',
        severity: 'critical',
        urlDetails: urlMatches
      });
    }

    // 3. Normalize Risk Score (0 to 100)
    const normalizedScore = Math.min(100, Math.max(0, Math.round(totalScore)));

    // 4. Determine Verdict. A critical sign (asking for codes, a disguised link,
    //    remote access) is never shown as low risk, whatever the total.
    let level = normalizedScore >= 60 ? 'high' : normalizedScore >= 25 ? 'medium' : 'low';
    if (level === 'low' && flags.some(f => f.severity === 'critical')) {
      level = 'medium';
    }
    const verdict = Object.assign({}, level === 'low' && flags.length === 0 ? VERDICTS.none : VERDICTS[level]);

    // 5. Generate Dynamic Actionable Safety Advice
    const advice = generateSafetyAdvice(flags, urlInspections);

    // 6. Merge & sort highlight spans for clean rendering without overlapping collision bugs
    const sortedHighlights = mergeHighlights(highlights);

    return {
      rawText: text,
      score: normalizedScore,
      verdict,
      flags,
      highlights: sortedHighlights,
      urlInspections,
      advice
    };
  }

  /**
   * Merges overlapping highlight intervals to prevent broken HTML tags
   */
  function mergeHighlights(highlights) {
    if (!highlights.length) return [];

    const severityRanks = { critical: 3, high: 2, medium: 1, low: 0 };

    // Sort by start index, then longer duration first
    const sorted = highlights.map(h => Object.assign({}, h)).sort((a, b) => {
      if (a.startIndex !== b.startIndex) {
        return a.startIndex - b.startIndex;
      }
      return (b.endIndex - b.startIndex) - (a.endIndex - a.startIndex);
    });

    const merged = [];
    let current = sorted[0];

    for (let i = 1; i < sorted.length; i++) {
      const next = sorted[i];
      if (next.startIndex < current.endIndex) {
        // Overlap detected: keep the higher severity, combine the reasons
        const reason = `${current.reason} & ${next.reason}`;
        const endIndex = Math.max(current.endIndex, next.endIndex);
        if (severityRanks[next.severity] > severityRanks[current.severity]) {
          current = Object.assign({}, next, { startIndex: current.startIndex });
        }
        current.endIndex = endIndex;
        current.reason = reason;
      } else {
        merged.push(current);
        current = next;
      }
    }
    merged.push(current);
    return merged;
  }

  /**
   * Tailored safety checklist based on detected threats
   */
  function generateSafetyAdvice(flags, urlInspections) {
    const steps = [];

    const hasLinks = urlInspections.some(u => u.issues.length > 0);
    const hasCredentials = flags.some(f => f.key === 'credentials');
    const hasUrgency = flags.some(f => f.key === 'urgency');
    const hasFinancial = flags.some(f => f.key === 'financial');
    const hasSecurityThreats = flags.some(f => f.key === 'securityThreats');

    // Baseline rule
    steps.push({
      title: 'Do not click links or call numbers provided in the message',
      description: 'Fraudulent messages often lead to fake credential-stealing portals or connect you with phone scammers.',
      type: 'critical'
    });

    if (hasSecurityThreats) {
      steps.push({
        title: 'Do not call the phone number or grant remote desktop access',
        description: 'Major tech firms (Microsoft, Apple) never send text alerts telling you to call a phone number or install AnyDesk/TeamViewer to clean a virus.',
        type: 'critical'
      });
    }

    if (hasLinks) {
      steps.push({
        title: 'Inspect destination URLs independently',
        description: 'Open a new browser tab and manually type the company’s known official website (e.g. chase.com, usps.com) instead of following links.',
        type: 'warning'
      });
    }

    if (hasCredentials) {
      steps.push({
        title: 'Never disclose OTPs, PINs, or Passwords',
        description: 'Authentic support staff never ask for your one-time SMS verification code or password under any circumstances.',
        type: 'critical'
      });
    }

    if (hasFinancial) {
      steps.push({
        title: 'Beware of non-standard payments & prize claims',
        description: 'Government agencies, banks, and major tech firms never demand payment via gift cards, wire transfers, or cryptocurrency.',
        type: 'warning'
      });
    }

    if (hasUrgency) {
      steps.push({
        title: 'Pause and disconnect from the manufactured urgency',
        description: 'Scammers count on haste to bypass rational thought. Legitimate account issues almost always provide reasonable resolution windows.',
        type: 'info'
      });
    }

    // Verification step
    steps.push({
      title: 'Verify via a verified alternative channel',
      description: 'Call the customer service number printed on the back of your physical payment card, your monthly utility statement, or the verified app.',
      type: 'action'
    });

    return steps;
  }

  const api = { SCAM_RULES, inspectURLs, analyzeMessage };

  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.ShieldCheck = Object.assign(root.ShieldCheck || {}, api);
  }
})(typeof window !== 'undefined' ? window : globalThis);
