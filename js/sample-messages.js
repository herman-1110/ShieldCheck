/**
 * Preset sample messages representing common real-world phishing vs legitimate messages.
 * Classic script: exposes window.ShieldCheck.SAMPLE_MESSAGES (or module.exports in Node).
 */
(function (root) {
  'use strict';

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

  if (typeof module === 'object' && module.exports) {
    module.exports = { SAMPLE_MESSAGES };
  } else {
    root.ShieldCheck = Object.assign(root.ShieldCheck || {}, { SAMPLE_MESSAGES });
  }
})(typeof window !== 'undefined' ? window : globalThis);
