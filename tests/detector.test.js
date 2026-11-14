// Run from the project folder with: node --test
const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeMessage, inspectURLs } = require('../js/detector.js');
const { SAMPLE_MESSAGES } = require('../js/sample-messages.js');

const levelOf = text => analyzeMessage(text).verdict.level;
const flaggedUrls = text => inspectURLs(text).filter(u => u.issues.length > 0);

test('empty input returns null', () => {
  assert.equal(analyzeMessage(''), null);
  assert.equal(analyzeMessage('   \n '), null);
});

test('built-in samples get the expected verdict', () => {
  for (const sample of SAMPLE_MESSAGES) {
    const result = analyzeMessage(sample.text);
    if (sample.id === 'legit-receipt') {
      assert.equal(result.flags.length, 0, sample.id);
      assert.equal(result.verdict.badge, 'No Red Flags Found', sample.id);
    } else {
      assert.equal(result.verdict.level, 'high', `${sample.id} scored ${result.score}`);
    }
  }
});

test('genuine messages that mention codes or passwords are not flagged', () => {
  const genuine = [
    'Your verification code is 482913. Never share this code with anyone. We will never ask for it.',
    'Your verification code is 482913, do not share it with anyone.',
    'Reminder from your bank: we will never ask for your password, PIN or one-time passcode by text or phone.',
    'Your password was changed on 12 Nov. If this was you, no action is needed.',
    "We'll send a verification code to your phone. Enter it to finish signing in."
  ];
  for (const text of genuine) {
    const result = analyzeMessage(text);
    assert.equal(result.flags.length, 0, `${text} -> ${result.flags.map(f => f.key)}`);
  }
});

test('links to genuine brand domains are not flagged', () => {
  const genuine = [
    'https://groups.google.com/g/team-notes',  // "groups" contains "ups"
    'https://www.amazon.co.uk/your-orders',     // regional domain
    'https://paypal.me/alexsmith',              // real PayPal domain
    'https://events.microsoft.co/summit',       // ends in "t.co" but isn't the shortener
    'https://www.bbc.co.uk/news/technology',    // two-part suffix, not "deeply nested"
    'https://tools.usps.com/go/TrackConfirmAction',
    'https://www.purchase.com/deals'            // contains "chase"
  ];
  for (const url of genuine) {
    assert.deepEqual(flaggedUrls(`See ${url} for details.`), [], url);
  }
});

test('requests for codes, PINs and card details are flagged', () => {
  const scams = [
    'Please send the 16-digit pin codes to me now.',
    'This is your bank support team. Please reply with the verification code we just sent you to stop the transfer.',
    'If you do not reply with your PIN within 1 hour your account will be blocked.',
    'Confirm your card number and CVV to restore access.'
  ];
  for (const text of scams) {
    const result = analyzeMessage(text);
    assert.ok(result.flags.some(f => f.key === 'credentials'), text);
    assert.notEqual(result.verdict.level, 'low', text);
  }
});

test('suspicious links are detected and explained', () => {
  const cases = [
    ['usps-redeliver.top/pay', /extension \(\.top\)/],                       // no http:// or www.
    ['http://secure-login-help.xyz.', /extension \(\.xyz\)/],                // full stop after the link
    ['http://bit.ly/abc', /link shortener/],
    ['http://paypal.com@login-check.net/secure', /"@" sign/],
    ['https://paypal.com.account-review.info/login', /actual domain is account-review\.info/],
    ['https://chase-security-verify.xyz/login', /name "chase"/],
    ['http://paypa1-dispute-center.top/cancel', /lookalike characters/],
    ['https://micr0soft-support.com', /lookalike characters/],
    ['https://xn--pypal-4ve.com/login', /international characters/],
    ['http://192.168.4.20/login', /IP address/]
  ];
  for (const [url, expected] of cases) {
    const found = flaggedUrls(`Go to ${url} now`);
    assert.equal(found.length, 1, url);
    assert.match(found[0].issues.join(' | '), expected, url);
  }
});

test('trailing punctuation is not part of the link', () => {
  const text = 'Fix it at http://bit.ly/usps-fix. Or see (https://example.com/help).';
  const urls = inspectURLs(text).map(u => u.rawUrl);
  assert.deepEqual(urls, ['http://bit.ly/usps-fix', 'https://example.com/help']);
});

test('repeating a word does not stack the score', () => {
  assert.equal(analyzeMessage('urgent urgent urgent').score, analyzeMessage('urgent').score);
  assert.equal(levelOf('FREE SHIPPING ON ALL ORDERS THIS WEEK AND NEXT WEEK TOO'), 'low');
});

test('a critical sign is never reported as low risk', () => {
  const result = analyzeMessage('Please send the pin codes.');
  assert.ok(result.score < 25);
  assert.equal(result.verdict.level, 'medium');
});

test('highlights are sorted, non-overlapping and inside the text', () => {
  const texts = SAMPLE_MESSAGES.map(s => s.text).concat([
    'URGENT!! Verify your identity at http://paypal.com.verify.xyz/login immediately 😀 or your account will be suspended.'
  ]);
  for (const text of texts) {
    let lastEnd = 0;
    for (const h of analyzeMessage(text).highlights) {
      assert.ok(h.startIndex >= lastEnd, 'overlap');
      assert.ok(h.endIndex > h.startIndex && h.endIndex <= text.length, 'bounds');
      lastEnd = h.endIndex;
    }
  }
});

test('every result includes safe next steps', () => {
  for (const text of ['Hello there', SAMPLE_MESSAGES[0].text]) {
    const { advice } = analyzeMessage(text);
    assert.ok(advice.length >= 2);
    assert.match(advice[advice.length - 1].title, /Verify/);
  }
});
