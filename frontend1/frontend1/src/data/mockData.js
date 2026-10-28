// Realistic Indian SME Fraud Data, Templates, and Samples

export const SAMPLE_TRANSACTIONS = [
  {
    id: "TX-9042",
    date: "Today, 11:24 AM",
    vendor: "Tata Projects (Fabrication Unit)",
    sender: "billing@tataprojects-invoicing.co",
    legitDomain: "tataprojects.com",
    amount: "₹4,86,500",
    rawAmount: 486500,
    invoiceNo: "TP-2024-8841",
    riskScore: 88,
    status: "HOLD",
    scamType: "Fake Vendor BEC (Lookalike Domain)",
    severity: "CRITICAL",
    summary: "Lookalike domain registered 4 days ago. Bank account swapped from registered HDFC Mumbai to Yes Bank Bandra branch.",
    details: {
      domainAge: "4 days old",
      spf: "FAIL",
      dmarc: "NONE",
      originalBank: "HDFC Bank (HDFC0000128) - Nariman Point",
      newBank: "Yes Bank (YESB0000412) - Bandra East",
      gstin: "27AAACT2727Q1ZB (Mismatch with PAN)",
      coercionKeywords: ["urgent", "hold shipment", "clear within 2 hours", "updated banking details"]
    }
  },
  {
    id: "TX-9041",
    date: "Today, 10:15 AM",
    vendor: "Asian Paints Industrial Ltd",
    sender: "invoices@asianpaints.com",
    legitDomain: "asianpaints.com",
    amount: "₹1,24,800",
    rawAmount: 124800,
    invoiceNo: "AP-MH-55219",
    riskScore: 4,
    status: "PAY",
    scamType: "Verified Genuine Supplier",
    severity: "SAFE",
    summary: "All cryptographic signatures passed. Bank account matches historical 3-year vendor ledger. GSTIN verified on portal.",
    details: {
      domainAge: "26 years old",
      spf: "PASS",
      dmarc: "PASS",
      originalBank: "ICICI Bank (ICIC0000004) - Mumbai",
      newBank: "ICICI Bank (ICIC0000004) - Mumbai",
      gstin: "27AAACA3580F1ZT (Verified Active)",
      coercionKeywords: []
    }
  },
  {
    id: "TX-9040",
    date: "Yesterday, 04:50 PM",
    vendor: "Central Board of Indirect Taxes (GST)",
    sender: "notice-recovery@gst-gov-in.online",
    legitDomain: "gst.gov.in",
    amount: "₹6,50,000",
    rawAmount: 650000,
    invoiceNo: "DRC-01/MH/88921",
    riskScore: 96,
    status: "HOLD",
    scamType: "Fake GST Demand Notice & Extortion",
    severity: "CRITICAL",
    summary: "Punycode spoofed phishing portal. Threatens bank account attachment within 24 hours unless penalty is deposited to personal IndusInd account.",
    details: {
      domainAge: "12 days old",
      spf: "FAIL",
      dmarc: "FAIL",
      originalBank: "Government Treasury / Cyber Treasury",
      newBank: "IndusInd Bank (INDB0000182) - Personal Savings",
      gstin: "Bogus Notice ID / Invalid DIN",
      coercionKeywords: ["immediate attachment", "section 73 penalty", "arrest warrant", "deposit within 24h"]
    }
  },
  {
    id: "TX-9039",
    date: "Yesterday, 02:10 PM",
    vendor: "Jio Infocomm Cloud Services",
    sender: "corporate.billing@jio.com",
    legitDomain: "jio.com",
    amount: "₹48,260",
    rawAmount: 48260,
    invoiceNo: "JIO-CORP-49102",
    riskScore: 6,
    status: "PAY",
    scamType: "Verified Genuine Recurring",
    severity: "SAFE",
    summary: "Routine cloud infrastructure billing. Exact match with registered Tally Prime vendor record and GST 2B reconciliation.",
    details: {
      domainAge: "18 years old",
      spf: "PASS",
      dmarc: "PASS",
      originalBank: "State Bank of India (SBIN0000691)",
      newBank: "State Bank of India (SBIN0000691)",
      gstin: "24AABCS4911F1ZA (Verified Active)",
      coercionKeywords: []
    }
  },
  {
    id: "TX-9038",
    date: "26 Oct, 11:05 AM",
    vendor: "WhatsApp CEO Impersonation (Anand Khurana)",
    sender: "WhatsApp +91 98210 99412",
    legitDomain: "khuranasteel.in",
    amount: "₹2,50,000",
    rawAmount: 250000,
    invoiceNo: "WA-URGENT-991",
    riskScore: 92,
    status: "HOLD",
    scamType: "Executive Impersonation (WhatsApp BEC)",
    severity: "CRITICAL",
    summary: "Number not in company directory. Using Managing Director's LinkedIn photo. Instructed accounts junior to RTGS ₹2.5L to an undisclosed vendor.",
    details: {
      domainAge: "N/A (WhatsApp Chat)",
      spf: "N/A",
      dmarc: "N/A",
      originalBank: "Regular Corporate Vendor A/C",
      newBank: "Paytm Payments Bank / Razorpay Virtual A/C",
      gstin: "Not Provided",
      coercionKeywords: ["in confidential meeting", "transfer right now", "do not call me", "critical client retainer"]
    }
  }
];

export const SAMPLE_SCAN_TEMPLATES = {
  url: [
    {
      label: "Fake SBI Corporate NetBanking",
      url: "https://sbi-corporate-kyc-update.com/login.php",
      risk: 94,
      type: "Phishing / Credential Harvesting",
      verdict: "CRITICAL RISK",
      summary: "Domain mimics SBI Online. Hosted on bulletproof hosting in Russia with active keylogger.",
      findings: [
        "Punycode lookalike domain targeting State Bank of India",
        "SSL certificate issued 2 days ago via Let's Encrypt free tier",
        "Form submits credentials to third-party Telegram bot endpoint",
        "Domain registered with anonymous privacy guard"
      ]
    },
    {
      label: "Spoofed GST e-Invoicing Portal",
      url: "https://einvoice1-gst-gov-verify.co/auth",
      risk: 91,
      type: "Government Impersonation",
      verdict: "CRITICAL RISK",
      summary: "Mimics official NIC e-invoice verification portal to steal business GST credentials.",
      findings: [
        "Lookalike domain of official einvoice1.gst.gov.in",
        "Asks for Master Taxpayer Password and DSC PIN",
        "No official NIC DNS records detected"
      ]
    },
    {
      label: "Official Tata Power Payment Gateway",
      url: "https://www.tatapower.com/bill-payment/corporate",
      risk: 2,
      type: "Legitimate Enterprise URL",
      verdict: "SAFE",
      summary: "Authentic Tata Power corporate billing portal with EV SSL and official trust hierarchy.",
      findings: [
        "Domain age: 24+ years registered to The Tata Power Company Ltd",
        "Valid DigiCert Extended Validation TLS Certificate",
        "DNSSEC enabled and passing all security headers"
      ]
    }
  ],
  text: [
    {
      label: "Vendor Bank Detail Swap Email",
      content: `Dear Accounts Team,

Please find attached invoice #IND-2024-9981 for ₹4,86,500 regarding last week's steel consignment.

IMPORTANT NOTICE: Our primary corporate account at HDFC Bank is currently undergoing an annual statutory audit. Please route this pending payment immediately to our secondary escrow account at:

Bank: Yes Bank Ltd
A/C Name: Precision Metal Works Private Limited
A/C Number: 041294810293
IFSC Code: YESB0000412
Branch: Bandra East, Mumbai

Please execute the RTGS before 3:00 PM today so we do not hold your next dispatched shipment. Send the UTR slip as soon as done.

Regards,
Suresh Verma
Head of Finance & Invoicing
billing@tatasteel-invoicing.co`,
      risk: 88,
      type: "Fake Vendor BEC (Bank Detail Swap)",
      verdict: "HOLD PAYMENT",
      findings: [
        "Lookalike domain: tatasteel-invoicing.co vs tatasteel.com",
        "Sudden bank switch reason ('annual statutory audit') is a classic BEC red flag",
        "Urgency ultimatum attached to shipment hold",
        "IFSC code points to branch with 3 previous cybercrime complaints"
      ]
    },
    {
      label: "Fake GST Demand Notice (DRC-01)",
      content: `OFFICE OF THE COMMISSIONER OF CENTRAL GST & AUDIT
DEPARTMENT OF REVENUE, MINISTRY OF FINANCE, GOVT OF INDIA

URGENT STATUTORY SUMMONS & ATTACHMENT NOTICE
Notice Ref: GST/DRC-01A/MUM/2024-25/89201
Date: 26/10/2024

To,
The Managing Director / Chief Financial Officer

Subject: Discrepancy in GSTR-1 vs GSTR-3B and Immediate Tax Evasion Recovery of ₹6,50,000/-

During ongoing AI-audit of your FY 2023-24 returns, severe ITC mismatch has been discovered under Section 74 of the CGST Act. Your GSTIN has been flagged for immediate suspension.

To prevent freezing of all company bank accounts and issuance of Non-Bailable Arrest Warrants, deposit the pre-settlement compound penalty of ₹6,50,000/- immediately into the designated Department Interim Holding Escrow:

Beneficiary: Govt Tax Settlement Escrow (DDO GST)
Account No: 201004928102
Bank: IndusInd Bank
IFSC: INDB0000182

Failure to deposit within 24 hours will result in search and seizure at your premises.`,
      risk: 97,
      type: "Fake GST Notice & Extortion",
      verdict: "HOLD PAYMENT / REPORT TO CYBERCELL",
      findings: [
        "Government GST payments are NEVER collected via private IndusInd individual accounts",
        "Official GST notices are only served inside the authenticated gst.gov.in portal dashboard",
        "Coercive extortion language: 'Non-Bailable Arrest Warrants', 'Search and Seizure'",
        "Notice DIN (Document Identification Number) is fabricated and invalid"
      ]
    },
    {
      label: "WhatsApp Director Emergency RTGS Request",
      content: `Hi Rajesh, are you in the office right now?

I am currently stuck in a high-level confidential board meeting with our private equity investors and can't take phone calls. 

We need to clear an urgent retainer payment of ₹2,50,000 to our lead M&A legal advisory firm before 1:00 PM today to close the term sheet. 

Please process an immediate RTGS/IMPS to this vendor account right away:
Name: Apex Legal Advisory Services
A/C: 918204910294
IFSC: PYTM0123456 (Paytm Payments Bank)

Confirm once the UTR is generated. Do not disturb me with phone calls, just reply here with the screenshot.

Anand Khurana
Managing Director`,
      risk: 93,
      type: "Executive Impersonation (CEO WhatsApp Fraud)",
      verdict: "HOLD PAYMENT",
      findings: [
        "Sent from unverified WhatsApp number (+91 98210 XXXXX)",
        "Coercive pressure: 'in confidential meeting', 'do not call me'",
        "High-risk beneficiary: Payment routed to payment bank virtual wallet",
        "Matches classic 'Gift Card / Emergency Retainer' CEO fraud signature"
      ]
    },
    {
      label: "Routine Genuine Raw Material Invoice",
      content: `Dear Team,

Please find attached our regular monthly tax invoice for raw brass ingots delivered on 24th October under PO #PO-88192.

Invoice No: BRASS-MH-1029
Total Amount: ₹1,42,800 (Inclusive of 18% GST)
Due Date: 10th November 2024

Payment coordinates remain unchanged:
Account Name: Western India Non-Ferrous Metals LLP
Bank: State Bank of India
A/C: 30192840192
IFSC: SBIN0000300
Branch: Main Branch, Pune
GSTIN: 27AABFW1294F1Z8

Thank you for your continuous partnership.

Warm regards,
Sunil Deshmukh
Western India Non-Ferrous Metals`,
      risk: 5,
      type: "Legitimate Vendor Invoice",
      verdict: "SAFE TO PROCEED",
      findings: [
        "Registered domain and verified email headers",
        "Bank account matches 24-month payment history in ERP",
        "GSTIN is active on government registry with compliant 3B filing history",
        "Standard 15-day credit terms with no abnormal urgency triggers"
      ]
    }
  ]
};

export const SCAM_CATEGORIES = [
  {
    id: "bec",
    title: "Vendor Email Compromise (BEC)",
    hindiTitle: "फेक वेंडर ईमेल फ्रॉड",
    icon: "MailWarning",
    accent: "emerald",
    riskStat: "₹1,400+ Cr lost annually",
    description: "Fraudsters register lookalike domains of your genuine raw material suppliers and send altered bank details right before your weekly payment run.",
    examples: ["billing@tatasteel-invoicing.co instead of tatasteel.com", "Altered IFSC code just before RTGS cut-off", "Fabricated bank audit excuse"]
  },
  {
    id: "invoice",
    title: "Fake Invoices & Altered Bank Details",
    hindiTitle: "नकली इनवॉइस और खाता बदलाव",
    icon: "FileSpreadsheet",
    accent: "blue",
    riskStat: "43% of SME payment leaks",
    description: "Invoices altered with Photoshop or PDF editors where the vendor logo is genuine, but the bank account and IFSC belong to a money mule in another state.",
    examples: ["Photoshop swapped bank coordinates", "Mismatched GSTIN and PAN number", "Duplicate invoice numbers with altered totals"]
  },
  {
    id: "gst",
    title: "GST Notice & Tax Demand Phishing",
    hindiTitle: "फर्जी जीएसटी नोटिस फ्रॉड",
    icon: "Scale",
    accent: "purple",
    riskStat: "Rising 310% in FY 2024-25",
    description: "Bogus DRC-01 notices threatening immediate bank account attachment and arrest unless a penalty is wired within 24 hours to a private account.",
    examples: ["Summons from fake tax recovery officers", "Personal IndusInd/Yes Bank escrow traps", "Threat of freezing business current accounts"]
  },
  {
    id: "upi",
    title: "UPI Scams & QR Code Traps",
    hindiTitle: "यूपीआई और क्यूआर कोड जाल",
    icon: "QrCode",
    accent: "amber",
    riskStat: "Over 8,000 cases reported daily",
    description: "Tricking accounts juniors into scanning 'Payment Receive' QR codes or approving reverse collect requests on PhonePe, Google Pay, and Paytm.",
    examples: ["'Scan this QR to receive advance' deception", "Reverse collect requests during vendor onboarding", "Spoofed soundbox confirmation apps"]
  },
  {
    id: "ceo",
    title: "CEO & Director WhatsApp Impersonation",
    hindiTitle: "डायरेक्टर व्हाट्सएप फ्रॉड",
    icon: "MessageSquareWarning",
    accent: "rose",
    riskStat: "Average loss: ₹6.8 Lakhs per incident",
    description: "Fraudsters using the Managing Director's LinkedIn photo on WhatsApp, claiming they are in a confidential meeting and ordering urgent RTGS.",
    examples: ["'Transfer ₹3.5L right now to this client'", "'Do not call me, I am in a board meeting'", "Emergency retainer payment excuse"]
  },
  {
    id: "digital-arrest",
    title: "Digital Arrest & Cyber Police Extortion",
    hindiTitle: "डिजिटल अरेस्ट और फर्जी पुलिस वसूली",
    icon: "ShieldAlert",
    accent: "red",
    riskStat: "Over ₹120 Cr lost in Q3 alone",
    description: "Intimidating video calls from fake CBI, ED, or Mumbai Police cyber cells claiming your business company account was used for money laundering.",
    examples: ["Fake Supreme Court / CBI summons on WhatsApp", "Video calls with police uniform backgrounds", "Demanding 'supervisory fund transfers' for clearance"]
  }
];

export const PRICING_PLANS = [
  {
    id: "starter",
    name: "SME Starter",
    badge: "For Small Businesses",
    priceMonthly: 2499,
    priceAnnual: 1999,
    period: "/ month",
    billedNote: "billed annually (₹23,988/yr)",
    description: "Essential AI payment run guardian for growing manufacturers, traders, and retail distributors.",
    features: [
      "Up to 150 payment checks / month",
      "Email & PDF invoice analysis",
      "Real-time Bank IFSC & A/C validation",
      "GSTIN live registry cross-verification",
      "WhatsApp scam checker (1 number)",
      "Standard email & chat support",
      "Audit trail log for 12 months"
    ],
    cta: "Start 14-Day Free Trial",
    popular: false
  },
  {
    id: "pro",
    name: "Business Pro",
    badge: "Most Popular for SMEs",
    priceMonthly: 6999,
    priceAnnual: 5599,
    period: "/ month",
    billedNote: "billed annually (₹67,188/yr)",
    description: "Automated payment protection with ERP integrations for high-volume enterprises.",
    features: [
      "Up to 1,000 payment checks / month",
      "Full ShieldScan deep forensic suite",
      "Tally Prime & Zoho Books direct sync",
      "Instant WhatsApp & Slack fraud alerts",
      "Historical vendor bank change anomaly engine",
      "Multi-user access (5 accounts team seats)",
      "Tamper-proof CA audit certificates",
      "Priority 24/7 fraud hotline & desk"
    ],
    cta: "Start Free Trial",
    popular: true
  },
  {
    id: "ca",
    name: "CA Practice Suite",
    badge: "For Chartered Accountants",
    priceMonthly: 14999,
    priceAnnual: 11999,
    period: "/ month",
    billedNote: "billed annually (₹1,43,988/yr)",
    description: "Multi-client portal for CA firms to audit vendor payments, GST notices, and compliance across all clients.",
    features: [
      "Unlimited forensic checks",
      "Multi-client dashboard (up to 30 clients)",
      "Batch invoice & ledger anomaly auditor",
      "Bogus billing & Section 16(2) ITC verifier",
      "White-labeled audit reports with firm logo",
      "Client permission controls & audit logs",
      "Dedicated account manager & CA trainer"
    ],
    cta: "Request CA Demo",
    popular: false
  },
  {
    id: "enterprise",
    name: "Enterprise Sentinel",
    badge: "Custom Scale",
    priceMonthly: "Custom",
    priceAnnual: "Custom",
    period: "",
    billedNote: "tailored SLA & volume",
    description: "For corporate groups, large exporters, and NBFCs requiring on-premise security and custom ERP workflows.",
    features: [
      "Unlimited checks & custom API integrations",
      "SAP, Oracle, Busy & custom ERP connectors",
      "On-premise / private VPC deployment",
      "Custom machine learning risk model tuning",
      "Real-time webhook triggers to banking APIs",
      "Dedicated forensic cyber investigator on call",
      "100% Indian Data Residency & SOC2 Type II SLA"
    ],
    cta: "Contact Enterprise Sales",
    popular: false
  }
];

export const CASE_STUDIES = [
  {
    id: 1,
    client: "Ludhiana Textile Exporters Ltd",
    industry: "Apparel & Garment Manufacturing",
    lossPrevented: "₹18,40,000",
    savedDate: "September 2024",
    scamVector: "Spoofed European Buyer BEC",
    story: "A routine ₹18.4 Lakh consignment payment for yarn was redirected via a spoofed email from a lookalike European buyer domain. ScamX caught the 3-day-old domain registration and altered IBAN/IFSC.",
    quote: "Our accounts department was minutes away from releasing the RTGS. ScamX's instant red flag literally saved our quarterly profit.",
    author: "Harpreet Singh, Managing Director"
  },
  {
    id: 2,
    client: "Surat Diamond & Gem Trade",
    industry: "Gems & Jewellery Exports",
    lossPrevented: "₹42,50,000",
    savedDate: "August 2024",
    scamVector: "Invoice Bank Detail Switch",
    story: "Fraudsters breached a supplier's email and injected an updated invoice with identical letterhead but a newly opened mule account in Yes Bank. ScamX flagged that the IFSC didn't match the historical 5-year supplier profile.",
    quote: "The invoice looked 100% authentic on paper. Without ScamX's historical bank anomaly engine, we would have lost over ₹42 Lakhs.",
    author: "Mehul Mehta, Partner"
  },
  {
    id: 3,
    client: "Bengaluru SaaS Logistics",
    industry: "B2B Tech & Fleet Management",
    lossPrevented: "₹6,20,000",
    savedDate: "October 2024",
    scamVector: "Fabricated GST Demand Notice",
    story: "A forged DRC-01 demand notice arrived claiming imminent seizure of their primary current account. ScamX analyzed the document DIN and identified that the payment destination was a private individual account rather than the official government treasury.",
    quote: "It arrived with official stamps and legal citations. ScamX gave our CA immediate clarity that the notice DIN was bogus.",
    author: "Pooja Hegde, Head of Finance"
  }
];

export const FAQS = [
  {
    q: "How does ScamX catch fraud before I interact with a message or link?",
    a: "ScamX analyzes submitted links, messages, and screenshots. Our AI inspects domain registrations for lookalike indicators, evaluates message texts for coercive urgency, and uses OCR to extract and evaluate text from uploaded screenshots."
  },
  {
    q: "Does an inconclusive result mean the content is safe?",
    a: "No. An inconclusive result does not mean the content is safe. It means automated checks could not conclusively prove malicious intent. You should always verify independently before taking action."
  },
  {
    q: "How does the WhatsApp fraud scanner work?",
    a: "You and your team forward suspicious payment requests, screenshots, or links to your ScamX WhatsApp line to receive a risk report and guidance."
  },
  {
    q: "Is our data safe? Does ScamX train on our submissions?",
    a: "Yes. ScamX processes your submissions ephemerally for threat evaluation and does not use private submissions to train public models."
  },
  {
    q: "What types of threats can ScamX analyze?",
    a: "ScamX provides three specialized scanners: Message Scanner, URL Safety Checker, and Screenshot Scanner."
  },
  {
    q: "Does ScamX guarantee 100% protection?",
    a: "No automated tool can provide 100% protection. ScamX is designed as an assistive detection tool. Users should always exercise caution."
  }
];
