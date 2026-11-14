(function () {
  'use strict';

  // -------------------------------------------------------------
  // 1. SCAM RULES & PATTERNS
  // -------------------------------------------------------------
  const SCAM_RULES = {
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

  const SUSPICIOUS_TLDS = [
    'xyz', 'top', 'click', 'live', 'club', 'work', 'loan', 'download',
    'stream', 'racing', 'win', 'vip', 'gq', 'ml', 'cf', 'ga', 'tk',
    'rest', 'fit', 'buzz', 'cc', 'link', 'country'
  ];

  const TARGETED_BRANDS = [
    'paypal', 'apple', 'amazon', 'microsoft', 'netflix', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'usps', 'fedex', 'ups',
    'dhl', 'facebook', 'instagram', 'google', 'ebay', 'walmart', 'binance'
  ];

  const URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
    'ow.ly', 'cutt.ly', 'rb.gy', 'shorte.st', 'tiny.cc'
  ];

  function inspectURLs(text) {
    const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`[\]]+/gi;
    const matches = [];
    let match;

    while ((match = urlRegex.exec(text)) !== null) {
      const rawUrl = match[0];
      const startIndex = match.index;
      const endIndex = startIndex + rawUrl.length;

      let hostname = '';
      try {
        const urlToParse = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`;
        const parsedUrl = new URL(urlToParse);
        hostname = parsedUrl.hostname.toLowerCase();
      } catch {
        hostname = rawUrl.toLowerCase().split('/')[0];
      }

      const issues = [];
      let urlRiskWeight = 0;

      const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
      if (ipPattern.test(hostname)) {
        issues.push('Uses a raw numerical IP address instead of a recognized domain name');
        urlRiskWeight += 30;
      }

      const isShortener = URL_SHORTENERS.some(shortener => hostname.endsWith(shortener));
      if (isShortener) {
        issues.push(`Uses a link shortener (${hostname}) which obscures the true destination`);
        urlRiskWeight += 18;
      }

      const parts = hostname.split('.');
      const tld = parts[parts.length - 1];
      if (SUSPICIOUS_TLDS.includes(tld)) {
        issues.push(`Uses suspicious or high-risk domain extension (.${tld})`);
        urlRiskWeight += 20;
      }

      for (const brand of TARGETED_BRANDS) {
        if (hostname.includes(brand) && !hostname.endsWith(`.${brand}.com`) && hostname !== `${brand}.com`) {
          issues.push(`Mentions brand "${brand}" but is not the official ${brand}.com domain (possible lookalike/typosquat)`);
          urlRiskWeight += 30;
          break;
        }
      }

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

  function analyzeMessage(text) {
    if (!text || !text.trim()) {
      return null;
    }

    const flags = [];
    const highlights = [];
    let totalScore = 0;

    for (const [catKey, category] of Object.entries(SCAM_RULES)) {
      const categoryMatches = [];

      for (const rule of category.patterns) {
        const regex = new RegExp(rule.regex.source, rule.regex.flags);
        let match;

        while ((match = regex.exec(text)) !== null) {
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

    const normalizedScore = Math.min(100, Math.max(0, Math.round(totalScore)));

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

    const advice = generateSafetyAdvice(flags, urlInspections);
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

  function mergeHighlights(highlights) {
    if (!highlights.length) return [];

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

  function generateSafetyAdvice(flags, urlInspections) {
    const steps = [];

    const hasLinks = urlInspections.some(u => u.issues.length > 0);
    const hasCredentials = flags.some(f => f.key === 'credentials');
    const hasUrgency = flags.some(f => f.key === 'urgency');
    const hasFinancial = flags.some(f => f.key === 'financial');
    const hasSecurityThreats = flags.some(f => f.key === 'securityThreats');

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

    steps.push({
      title: 'Verify via a verified alternative channel',
      description: 'Call the customer service number printed on the back of your physical payment card, your monthly utility statement, or the verified app.',
      type: 'action'
    });

    return steps;
  }

  // -------------------------------------------------------------
  // 2. SAMPLE PRESET MESSAGES
  // -------------------------------------------------------------
  const SAMPLE_MESSAGES = [
    {
      id: 'chase-phish',
      title: 'Chase Bank SMS Alert',
      badge: 'Phishing SMS',
      badgeColor: 'bg-red-100 text-red-700 border-red-200',
      icon: 'credit-card',
      text: `URGENT: Chase Bank Security Alert! Your debit card has been suspended due to unauthorized activity detected. Immediate action required within 24 hours to prevent permanent account closure. Verify your identity and confirm your card number & CVV immediately at http://chase-security-verify.xyz/login to restore access.`
    },
    {
      id: 'usps-delivery',
      title: 'USPS Package Delivery Trap',
      badge: 'Smishing Trap',
      badgeColor: 'bg-amber-100 text-amber-700 border-amber-200',
      icon: 'package',
      text: `USPS Delivery Notice: Your package #US98421 could not be delivered due to an incomplete street address. Please update your billing info and confirm your redelivery fee of $1.50 within 12 hours: http://bit.ly/usps-pkg-fix. Failure to respond will result in parcel return.`
    },
    {
      id: 'tech-support',
      title: 'Microsoft Tech Support Scam',
      badge: 'Fake Support',
      badgeColor: 'bg-red-100 text-red-700 border-red-200',
      icon: 'laptop',
      text: `Dear Customer, We detected a trojan virus on your personal computer that compromised your system credentials. Your Windows license will be terminated today. Call Microsoft Support Fraud Prevention Department immediately at +1-800-555-0199. Do not restart your computer!`
    },
    {
      id: 'ceo-giftcard',
      title: 'Boss Urgently Needs Gift Cards',
      badge: 'Impersonation Scam',
      badgeColor: 'bg-orange-100 text-orange-700 border-orange-200',
      icon: 'gift',
      text: `Hi, are you at your desk? I am currently in an urgent meeting with clients and cannot take phone calls. I urgently need you to purchase 4 x $100 Apple Gift Cards right now for client gifts. Please send the 16-digit pin codes directly to this message. I will process your reimbursement of $400 immediately afterwards.`
    },
    {
      id: 'paypal-refund',
      title: 'Fake PayPal Invoice / Refund',
      badge: 'Phishing Email',
      badgeColor: 'bg-yellow-100 text-yellow-700 border-yellow-200',
      icon: 'mail',
      text: `Dear Valued Customer, Your PayPal account has processed an unauthorized charge of $849.00 to Bitcoin Exchange Ltd. If you did not authorize this transaction, click immediately at http://paypa1-dispute-center.top/cancel-order to dispute and claim your instant refund. Enter your one-time password (OTP) when prompted.`
    },
    {
      id: 'legit-receipt',
      title: 'Legitimate Order Confirmation',
      badge: 'Authentic Message',
      badgeColor: 'bg-emerald-100 text-emerald-700 border-emerald-200',
      icon: 'check-circle-2',
      text: `Hi Elena, thanks for your order #89214 with REI! We're preparing your hiking boots for shipment. Your total payment of $120.00 has cleared. You can track your order status anytime by logging into your account dashboard at https://www.rei.com/account/orders. If you have questions, our team is here to help.`
    }
  ];

  // -------------------------------------------------------------
  // 3. UI CONTROLLER & APP LOGIC
  // -------------------------------------------------------------
  let currentAnalysis = null;

  function init() {
    const messageInput = document.getElementById('message-input');
    const charCount = document.getElementById('char-count');
    const btnAnalyze = document.getElementById('btn-analyze');
    const btnClear = document.getElementById('btn-clear');
    const btnPaste = document.getElementById('btn-paste');
    const btnCopyReport = document.getElementById('btn-copy-report');
    const sampleContainer = document.getElementById('sample-buttons-container');

    const resultsEmpty = document.getElementById('results-empty');
    const resultsActive = document.getElementById('results-active');

    const verdictBadge = document.getElementById('verdict-badge');
    const verdictScore = document.getElementById('verdict-score');
    const scoreMeterBar = document.getElementById('score-meter-bar');
    const verdictDescription = document.getElementById('verdict-description');
    const highlightedContainer = document.getElementById('highlighted-text-container');
    const flagCountPill = document.getElementById('flag-count-pill');
    const flagCategoriesList = document.getElementById('flag-categories-list');
    const safetyChecklist = document.getElementById('safety-checklist');
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toast-message');

    function refreshIcons() {
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
      }
    }

    function showToast(msg) {
      if (!toast) return;
      toastMessage.textContent = msg;
      toast.classList.remove('opacity-0', 'translate-y-20', 'pointer-events-none');
      toast.classList.add('opacity-100', 'translate-y-0');

      setTimeout(() => {
        toast.classList.remove('opacity-100', 'translate-y-0');
        toast.classList.add('opacity-0', 'translate-y-20', 'pointer-events-none');
      }, 2400);
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function updateCharCount() {
      const count = messageInput.value.length;
      charCount.textContent = `${count} char${count === 1 ? '' : 's'}`;
    }

    function showEmptyState() {
      currentAnalysis = null;
      resultsActive.classList.add('hidden');
      resultsEmpty.classList.remove('hidden');
      refreshIcons();
    }

    function renderSampleButtons() {
      if (!sampleContainer) return;
      sampleContainer.innerHTML = '';
      SAMPLE_MESSAGES.forEach(sample => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'group inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium bg-slate-100 hover:bg-slate-200/80 text-slate-700 transition border border-slate-200/60 active:scale-95';
        btn.innerHTML = `
          <i data-lucide="${sample.icon}" class="w-3.5 h-3.5 text-slate-500 group-hover:text-indigo-600 transition"></i>
          <span>${escapeHtml(sample.title)}</span>
          <span class="text-[10px] px-1.5 py-0.5 rounded-md font-semibold ${sample.badgeColor} border">${escapeHtml(sample.badge)}</span>
        `;
        btn.addEventListener('click', () => {
          loadSample(sample.id);
        });
        sampleContainer.appendChild(btn);
      });
    }

    function loadSample(sampleId) {
      const sample = SAMPLE_MESSAGES.find(s => s.id === sampleId);
      if (!sample) return;

      messageInput.value = sample.text;
      updateCharCount();
      runAnalysis();
      showToast(`Loaded sample: ${sample.title}`);
    }

    function runAnalysis() {
      const text = messageInput.value.trim();
      if (!text) {
        showEmptyState();
        return;
      }

      const analysis = analyzeMessage(text);
      currentAnalysis = analysis;

      if (!analysis) {
        showEmptyState();
        return;
      }

      renderResults(analysis);
      refreshIcons();
    }

    function renderResults(analysis) {
      resultsEmpty.classList.add('hidden');
      resultsActive.classList.remove('hidden');

      const { verdict, score, flags, highlights, rawText, advice, urlInspections } = analysis;

      verdictScore.textContent = score;
      verdictDescription.textContent = verdict.description;

      scoreMeterBar.style.width = `${score}%`;
      scoreMeterBar.style.backgroundColor = verdict.color;

      verdictBadge.textContent = verdict.badge;
      if (verdict.level === 'high') {
        verdictBadge.className = 'px-3.5 py-1.5 rounded-full text-xs font-bold tracking-wide uppercase inline-flex items-center gap-1.5 bg-red-100 text-red-700 border border-red-200 animate-alert-pulse';
        verdictBadge.innerHTML = `<i data-lucide="shield-alert" class="w-4 h-4"></i> ${verdict.badge}`;
      } else if (verdict.level === 'medium') {
        verdictBadge.className = 'px-3.5 py-1.5 rounded-full text-xs font-bold tracking-wide uppercase inline-flex items-center gap-1.5 bg-amber-100 text-amber-800 border border-amber-200';
        verdictBadge.innerHTML = `<i data-lucide="alert-triangle" class="w-4 h-4"></i> ${verdict.badge}`;
      } else {
        verdictBadge.className = 'px-3.5 py-1.5 rounded-full text-xs font-bold tracking-wide uppercase inline-flex items-center gap-1.5 bg-emerald-100 text-emerald-800 border border-emerald-200';
        verdictBadge.innerHTML = `<i data-lucide="shield-check" class="w-4 h-4"></i> ${verdict.badge}`;
      }

      renderHighlightedText(rawText, highlights);
      renderFlags(flags, urlInspections);
      renderChecklist(advice);
    }

    function renderHighlightedText(text, highlights) {
      if (!highlights || highlights.length === 0) {
        highlightedContainer.innerHTML = `<div class="text-slate-600">${escapeHtml(text)}</div><div class="mt-2 text-xs text-emerald-600 font-medium flex items-center gap-1"><i data-lucide="check" class="w-3.5 h-3.5"></i> No flagged phrases detected in this text.</div>`;
        return;
      }

      let html = '';
      let lastIndex = 0;

      for (const h of highlights) {
        if (h.startIndex > lastIndex) {
          html += escapeHtml(text.slice(lastIndex, h.startIndex));
        }

        const targetSlice = text.slice(h.startIndex, h.endIndex);
        const tooltipText = `⚠️ ${h.category}: ${h.reason}`;
        html += `<span class="highlight-span highlight-${h.severity}" data-tooltip="${escapeHtml(tooltipText)}">${escapeHtml(targetSlice)}</span>`;

        lastIndex = h.endIndex;
      }

      if (lastIndex < text.length) {
        html += escapeHtml(text.slice(lastIndex));
      }

      highlightedContainer.innerHTML = html;
    }

    function renderFlags(flags, urlInspections) {
      flagCategoriesList.innerHTML = '';

      const totalTriggers = flags.reduce((acc, f) => {
        return acc + (f.matches ? f.matches.length : (f.urlDetails ? f.urlDetails.length : 1));
      }, 0);

      flagCountPill.textContent = `${totalTriggers} Indicator${totalTriggers === 1 ? '' : 's'}`;

      if (flags.length === 0) {
        flagCategoriesList.innerHTML = `
          <div class="p-4 rounded-xl bg-emerald-50 border border-emerald-100 text-emerald-800 text-xs flex items-center gap-2">
            <i data-lucide="check-circle" class="w-4 h-4 text-emerald-600 flex-shrink-0"></i>
            <span>No typical phishing keywords or spoofing patterns were recognized in this message.</span>
          </div>
        `;
        return;
      }

      flags.forEach(flag => {
        const card = document.createElement('div');
        card.className = 'border border-slate-200 rounded-xl p-3.5 bg-slate-50/70 hover:bg-slate-50 transition';

        let severityBadge = '';
        if (flag.severity === 'critical') {
          severityBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-100 text-red-700 border border-red-200">Critical</span>`;
        } else if (flag.severity === 'high') {
          severityBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-orange-100 text-orange-700 border border-orange-200">High Risk</span>`;
        } else if (flag.severity === 'medium') {
          severityBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-100 text-amber-700 border border-amber-200">Warning</span>`;
        } else {
          severityBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-200 text-slate-700">Notice</span>`;
        }

        let itemsHtml = '';
        if (flag.matches) {
          itemsHtml = `
            <div class="mt-2.5 flex flex-wrap gap-1.5">
              ${flag.matches.map(m => `
                <span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white border border-slate-200 text-xs text-slate-700 font-mono">
                  <span class="w-1.5 h-1.5 rounded-full bg-red-500"></span>
                  "${escapeHtml(m.matchedText)}"
                  <span class="text-[10px] text-slate-400 font-sans">(${escapeHtml(m.label)})</span>
                </span>
              `).join('')}
            </div>
          `;
        } else if (flag.urlDetails) {
          itemsHtml = `
            <div class="mt-2.5 space-y-2">
              ${flag.urlDetails.map(u => `
                <div class="p-2.5 rounded-lg bg-white border border-red-200 text-xs">
                  <div class="font-mono text-red-600 font-semibold break-all flex items-center gap-1.5">
                    <i data-lucide="external-link" class="w-3.5 h-3.5 flex-shrink-0"></i>
                    ${escapeHtml(u.rawUrl)}
                  </div>
                  <ul class="mt-1.5 space-y-1 text-slate-600">
                    ${u.issues.map(iss => `
                      <li class="flex items-start gap-1.5">
                        <span class="text-red-500 font-bold">•</span>
                        <span>${escapeHtml(iss)}</span>
                      </li>
                    `).join('')}
                  </ul>
                </div>
              `).join('')}
            </div>
          `;
        }

        card.innerHTML = `
          <div class="flex items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <span class="font-bold text-xs text-slate-800">${escapeHtml(flag.name)}</span>
              ${severityBadge}
            </div>
          </div>
          <p class="text-[11px] text-slate-500 mt-1 leading-normal">${escapeHtml(flag.description)}</p>
          ${itemsHtml}
        `;

        flagCategoriesList.appendChild(card);
      });
    }

    function renderChecklist(steps) {
      safetyChecklist.innerHTML = '';

      steps.forEach((step, idx) => {
        const item = document.createElement('label');
        item.className = 'flex items-start gap-3 p-3 rounded-xl border border-slate-200 bg-white hover:bg-slate-50/80 cursor-pointer transition select-none group';

        item.innerHTML = `
          <input type="checkbox" class="mt-0.5 rounded text-indigo-600 focus:ring-indigo-500 w-4 h-4 border-slate-300">
          <div class="flex-1">
            <div class="text-xs font-bold text-slate-800 group-hover:text-indigo-600 transition flex items-center gap-2">
              <span>${idx + 1}. ${escapeHtml(step.title)}</span>
            </div>
            <p class="text-xs text-slate-500 mt-0.5 leading-relaxed">${escapeHtml(step.description)}</p>
          </div>
        `;

        const checkbox = item.querySelector('input[type="checkbox"]');
        checkbox.addEventListener('change', () => {
          const titleSpan = item.querySelector('.text-slate-800');
          if (checkbox.checked) {
            item.classList.add('bg-emerald-50/50', 'border-emerald-200');
            titleSpan.classList.add('line-through', 'text-slate-400');
          } else {
            item.classList.remove('bg-emerald-50/50', 'border-emerald-200');
            titleSpan.classList.remove('line-through', 'text-slate-400');
          }
        });

        safetyChecklist.appendChild(item);
      });
    }

    function copyReportSummary() {
      if (!currentAnalysis) {
        showToast('No active analysis to copy');
        return;
      }

      const { verdict, score, flags, advice } = currentAnalysis;

      const flagSummary = flags.map(f => {
        const details = f.matches
          ? f.matches.map(m => `"${m.matchedText}" (${m.label})`).join(', ')
          : f.urlDetails
            ? f.urlDetails.map(u => `${u.rawUrl} [${u.issues.join('; ')}]`).join(', ')
            : '';
        return `- ${f.name}: ${details}`;
      }).join('\n');

      const actionSummary = advice.map((a, i) => `${i + 1}. ${a.title}: ${a.description}`).join('\n');

      const report = `===========================================
SHIELDCHECK MESSAGE SECURITY ANALYSIS
===========================================
VERDICT: ${verdict.badge}
RISK SCORE: ${score} / 100
SUMMARY: ${verdict.description}

WARNING SIGNS IDENTIFIED:
${flagSummary || '- None detected'}

SAFE ACTION STEPS FOR THE CUSTOMER:
${actionSummary}

Analyzed securely client-side via ShieldCheck.
===========================================`;

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(report).then(() => {
          showToast('Security report copied to clipboard!');
        }).catch(() => {
          showToast('Failed to copy to clipboard');
        });
      } else {
        showToast('Clipboard access not supported in this environment');
      }
    }

    // Attach user action listeners
    messageInput.addEventListener('input', updateCharCount);
    btnAnalyze.addEventListener('click', runAnalysis);
    btnClear.addEventListener('click', () => {
      messageInput.value = '';
      updateCharCount();
      showEmptyState();
      messageInput.focus();
      showToast('Input cleared');
    });

    btnPaste.addEventListener('click', async () => {
      try {
        if (navigator.clipboard && navigator.clipboard.readText) {
          const text = await navigator.clipboard.readText();
          if (text) {
            messageInput.value = text;
            updateCharCount();
            runAnalysis();
            showToast('Pasted & analyzed');
          } else {
            showToast('Clipboard is empty');
          }
        } else {
          messageInput.focus();
          showToast('Press Ctrl+V to paste');
        }
      } catch {
        messageInput.focus();
        showToast('Press Ctrl+V to paste');
      }
    });

    btnCopyReport.addEventListener('click', copyReportSummary);

    // Initial render
    renderSampleButtons();
    refreshIcons();

    if (SAMPLE_MESSAGES.length > 0) {
      loadSample(SAMPLE_MESSAGES[0].id);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
