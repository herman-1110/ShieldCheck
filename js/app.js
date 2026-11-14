/**
 * ShieldCheck UI controller.
 * Classic script: needs js/detector.js and js/sample-messages.js loaded first.
 */
(function () {
  'use strict';

  const { analyzeMessage, SAMPLE_MESSAGES } = window.ShieldCheck;

  let currentAnalysis = null;
  let toastTimer = null;

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

      // Restart the timer so a new message isn't hidden early by an older one
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => {
        toast.classList.remove('opacity-100', 'translate-y-0');
        toast.classList.add('opacity-0', 'translate-y-20', 'pointer-events-none');
      }, 2400);
    }

    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
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

      const badgeBase = 'px-3.5 py-1.5 rounded-full text-xs font-bold tracking-wide uppercase inline-flex items-center gap-1.5';
      if (verdict.level === 'high') {
        verdictBadge.className = `${badgeBase} bg-red-100 text-red-700 border border-red-200 animate-alert-pulse`;
        verdictBadge.innerHTML = `<i data-lucide="shield-alert" class="w-4 h-4"></i> ${escapeHtml(verdict.badge)}`;
      } else if (verdict.level === 'medium') {
        verdictBadge.className = `${badgeBase} bg-amber-100 text-amber-800 border border-amber-200`;
        verdictBadge.innerHTML = `<i data-lucide="alert-triangle" class="w-4 h-4"></i> ${escapeHtml(verdict.badge)}`;
      } else {
        verdictBadge.className = `${badgeBase} bg-emerald-100 text-emerald-800 border border-emerald-200`;
        verdictBadge.innerHTML = `<i data-lucide="shield-check" class="w-4 h-4"></i> ${escapeHtml(verdict.badge)}`;
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
        // tabindex lets keyboard and touch users open the explanation too
        html += `<span class="highlight-span highlight-${h.severity}" tabindex="0" data-tooltip="${escapeHtml(tooltipText)}">${escapeHtml(targetSlice)}</span>`;

        lastIndex = h.endIndex;
      }

      if (lastIndex < text.length) {
        html += escapeHtml(text.slice(lastIndex));
      }

      highlightedContainer.innerHTML = html;
    }

    function renderFlags(flags) {
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
      } catch (e) {
        messageInput.focus();
        showToast('Press Ctrl+V to paste');
      }
    });

    btnCopyReport.addEventListener('click', copyReportSummary);

    // Initial render: show the first example so the page opens in a working state
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
