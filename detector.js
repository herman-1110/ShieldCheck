/**
 * Suspicious Message Detection Engine
 * Comprehensive client-side analyzer for phishing, scams, and impersonation attempts.
 */

// Categorized trigger patterns with severity and educational explanations
export const SCAM_RULES = {
  urgency: {
    category: 'Urgency & Pressure Tactics',
    description: 'Scammers manufacture artificial panic to make you act before thinking.',
    severity: 'high',
    patterns: [
      { regex: /\b(?:urgent|urgently|immediate action required|act now|immediate attention)\b/gi, label: 'Urgent demand', weight: 15 },
      { regex: /\b(?:within (?:24|12|48|2|1) hours?|immediately|right now|without delay)\b/gi, label: 'Tight deadline pressure', weight: 12 },
      { regex: /\b(?:account (?:will be |has been )?(?:suspended|terminated|locked|closed|disabled|frozen|blocked))\b/gi, label: 'Account threat', weight: 18 },
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
      { regex: /\b(?:password|passcode|pin code|security code)\b/gi, label: 'Password/PIN request', weight: 22 },
      { regex: /\b(?:otp|one-time (?:password|code)|verification code|auth code|2fa code)\b/gi, label: '2FA/OTP code request', weight: 25 },
      { regex: /\b(?:ssn|social security|national insurance|tax id|id card number)\b/gi, label: 'Government ID request', weight: 25 },
      { regex: /\b(?:credit card|debit card|cvv|cvc|card number|expiration date)\b/gi, label: 'Payment card details request', weight: 22 },
      { regex: /\b(?:verify your identity|confirm your identity|update your billing info|re-enter your details)\b/gi, label: 'Identity verification bait', weight: 16 }
    ]
  },
  financial: {
    category: 'Financial Bait & Demands',
    description: 'Unsolicited money, prizes, unexpected fees, or demands for untraceable payment.',
    severity: 'high',
    patterns: [
      { regex: /\b(?:gift cards?|apple gift card|itunes card|google play card|steam card)\b/gi, label: 'Gift card payment request (Classic scam)', weight: 25 },
      { regex: /\b(?:wire transfer|western union|moneygram|crypto|bitcoin|usdt|cash app|venmo|zelle)\b/gi, label: 'Untraceable payment method', weight: 18 },
      { regex: /\b(?:you('?ve| have) won|lottery|sweepstakes|jackpot|prize of|claim your reward)\b/gi, label: 'Unsolicited prize bait', weight: 20 },
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
      { regex: /\b[A-Z]{4,}\b/g, label: 'Aggressive ALL-CAPS words', weight: 6 }
    ]
  }
};

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

// Shortener services
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
  'ow.ly', 'cutt.ly', 'rb.gy', 'shorte.st', 'tiny.cc'
];

/**
 * Extracts and inspects URLs found in text for phishing indicators
 */
export function inspectURLs(text) {
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`[\]]+/gi;
  const matches = [];
  let match;

  while ((match = urlRegex.exec(text)) !== null) {
    const rawUrl = match[0];
    const startIndex = match.index;
    const endIndex = startIndex + rawUrl.length;

    let parsedUrl = null;
    let hostname = '';
    try {
      const urlToParse = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`;
      parsedUrl = new URL(urlToParse);
      hostname = parsedUrl.hostname.toLowerCase();
    } catch {
      hostname = rawUrl.toLowerCase().split('/')[0];
    }

    const issues = [];
    let urlRiskWeight = 0;

    // Check 1: IP address used as host
    const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
      issues.push('Uses a raw numerical IP address instead of a recognized domain name');
      urlRiskWeight += 30;
    }

    // Check 2: Known URL shortener (hides real destination)
    const isShortener = URL_SHORTENERS.some(shortener => hostname.endsWith(shortener));
    if (isShortener) {
      issues.push(`Uses a link shortener (${hostname}) which obscures the true destination`);
      urlRiskWeight += 18;
    }

    // Check 3: Suspicious TLD
    const parts = hostname.split('.');
    const tld = parts[parts.length - 1];
    if (SUSPICIOUS_TLDS.includes(tld)) {
      issues.push(`Uses suspicious or high-risk domain extension (.${tld})`);
      urlRiskWeight += 20;
    }

    // Check 4: Brand name inside subdomain or typo-squatted
    for (const brand of TARGETED_BRANDS) {
      // Check for hyphenated spoof like "chase-security.com" or "paypal-verify.xyz"
      if (hostname.includes(brand) && !hostname.endsWith(`.${brand}.com`) && hostname !== `${brand}.com`) {
        issues.push(`Mentions brand "${brand}" but is not the official ${brand}.com domain (possible lookalike/typosquat)`);
        urlRiskWeight += 30;
        break;
      }
    }

    // Check 5: Common typo-squat replacements (e.g., paypa1, micros0ft, arnazon)
    const typoPatterns = [
      { regex: /paypa[1l|i]/i, brand: 'PayPal' },
      { regex: /micros[0o]ft/i, brand: 'Microsoft' },
      { regex: /arnaz[o0]n|amaz[o0]n-verify/i, brand: 'Amazon' },
      { regex: /netf[1l]ix/i, brand: 'Netflix' },
      { regex: /app[1l]e-id/i, brand: 'Apple' }
    ];

    for (const tp of typoPatterns) {
      if (tp.regex.test(hostname) && !hostname.includes(tp.brand.toLowerCase() + '.com')) {
        issues.push(`Domain mimics legitimate brand "${tp.brand}" using visual lookalike characters`);
        urlRiskWeight += 35;
        break;
      }
    }

    // Check 6: Multiple subdomains (domain nesting)
    if (parts.length > 3) {
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

/**
 * Main Analysis Function
 * Scans text, generates highlighted ranges, computes risk score and safety guidelines
 */
export function analyzeMessage(text) {
  if (!text || !text.trim()) {
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
      let match;

      while ((match = regex.exec(text)) !== null) {
        // Skip formatting flags if it's just regular caps (e.g. short words)
        if (rule.label === 'Aggressive ALL-CAPS words' && match[0].length < 4) {
          continue;
        }

        const matchedText = match[0];
        const startIndex = match.index;
        const endIndex = startIndex + matchedText.length;

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

        totalScore += rule.weight;
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
  if (urlInspections.length > 0) {
    const urlMatches = [];

    urlInspections.forEach(urlObj => {
      if (urlObj.issues.length > 0) {
        totalScore += urlObj.riskWeight;
        urlMatches.push(urlObj);

        highlights.push({
          startIndex: urlObj.startIndex,
          endIndex: urlObj.endIndex,
          text: urlObj.rawUrl,
          severity: 'critical',
          category: 'Suspicious Links',
          reason: urlObj.issues.join('; ')
        });
      }
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
  }

  // 3. Normalize Risk Score (0 to 100)
  const normalizedScore = Math.min(100, Math.max(0, Math.round(totalScore)));

  // 4. Determine Verdict
  let verdict = {
    level: 'low',
    badge: 'Appears Safe',
    badgeClass: 'badge-safe',
    color: '#10B981',
    description: 'No prominent scam red flags detected. However, always verify unexpected requests before taking action.'
  };

  if (normalizedScore >= 60) {
    verdict = {
      level: 'high',
      badge: 'High Risk / Likely Scam',
      badgeClass: 'badge-danger',
      color: '#EF4444',
      description: 'Multiple critical warning signs detected! This message strongly resembles a social engineering or phishing attack.'
    };
  } else if (normalizedScore >= 25) {
    verdict = {
      level: 'medium',
      badge: 'Moderate Caution',
      badgeClass: 'badge-warning',
      color: '#F59E0B',
      description: 'Contains warning triggers commonly used in manipulative or unsolicited outreach. Proceed with caution.'
    };
  }

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

  // Sort by start index, then longer duration first
  const sorted = [...highlights].sort((a, b) => {
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
      // Overlap detected: choose the higher severity
      const severityRanks = { critical: 3, high: 2, medium: 1, low: 0 };
      if (severityRanks[next.severity] > severityRanks[current.severity]) {
        current = {
          ...next,
          startIndex: Math.min(current.startIndex, next.startIndex),
          endIndex: Math.max(current.endIndex, next.endIndex),
          reason: `${current.reason} & ${next.reason}`
        };
      } else {
        current.endIndex = Math.max(current.endIndex, next.endIndex);
        current.reason = `${current.reason} & ${next.reason}`;
      }
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
  const hasImpersonation = flags.some(f => f.key === 'impersonation');
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
