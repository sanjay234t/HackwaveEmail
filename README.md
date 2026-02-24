# HackwaveEmail
#!/usr/bin/env python3
"""
COMPLETE AI-POWERED EMAIL PHISHING DETECTION SYSTEM
═════════════════════════════════════════════════════════════════════════════

DELIVERABLE 1: Email Ingestion Module with IMAP/Dummy Inbox/Manual Input
DELIVERABLE 2: NLP/ML Pipeline for Phishing Detection  
DELIVERABLE 3: Risk Scoring and Explanation Engine
DELIVERABLE 4: Interactive Reviewer Dashboard with Feedback Collection

Author: Email Security Team
Version: 2.0
"""

import re
import json
import sqlite3
import imaplib
import email
from email.header import decode_header
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime
from collections import defaultdict
import base64
from abc import ABC, abstractmethod


# ============================================================================
# PART 1: EMAIL INGESTION MODULE (IMAP + DUMMY CONNECTOR + MANUAL INPUT)
# ============================================================================

class RiskLevel(Enum):
    """Email risk classification"""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


@dataclass
class EmailMessage:
    """Email metadata and content"""
    email_id: str
    sender: str
    sender_name: str
    subject: str
    body: str
    html_body: str
    received_date: str
    urls: List[str] = field(default_factory=list)
    attachments: List[Dict] = field(default_factory=list)
    headers: Dict = field(default_factory=dict)
    reply_to: Optional[str] = None
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)


class EmailIngestor(ABC):
    """Abstract base for email ingestion"""
   
    @abstractmethod
    def fetch_emails(self) -> List[EmailMessage]:
        """Fetch emails from source"""
        pass


class ManualInputConnector(EmailIngestor):
    """Manual email input - user provides email details"""
   
    def fetch_emails(self) -> List[EmailMessage]:
        """Collect email from user input"""
        emails = []
        
        print("\n" + "="*80)
        print("📧 MANUAL EMAIL INPUT")
        print("="*80)
        print("\nEnter email details (leave blank if not applicable):\n")
        
        email_id = f"MANUAL_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Get sender
        sender = input("📬 From (Sender Email Address): ").strip()
        if not sender:
            print("❌ Sender email is required!")
            return []
        
        # Get sender name
        sender_name = input("👤 Sender Name (optional): ").strip() or sender.split("@")[0]
        
        # Get subject
        subject = input("📝 Subject Line: ").strip()
        if not subject:
            print("❌ Subject is required!")
            return []
        
        # Get body
        print("\n📄 Email Body (paste content, type 'END' on new line when done):")
        body_lines = []
        while True:
            try:
                line = input()
                if line.strip().upper() == "END":
                    break
                body_lines.append(line)
            except EOFError:
                break
        body = "\n".join(body_lines).strip()
        
        if not body:
            print("❌ Email body is required!")
            return []
        
        # Get URLs
        urls = []
        print("\n🔗 URLs in Email (enter each URL, press Enter twice when done):")
        while True:
            url = input().strip()
            if not url:
                break
            urls.append(url)
        
        # Get attachments
        attachments = []
        print("\n📎 Attachments (enter each filename, press Enter twice when done):")
        while True:
            att_name = input().strip()
            if not att_name:
                break
            att_size = input(f"   Size in bytes for '{att_name}' (default: 0): ").strip()
            attachments.append({
                "name": att_name,
                "size": int(att_size) if att_size.isdigit() else 0
            })
        
        # Get reply-to
        reply_to = input("\n↪️  Reply-To (optional): ").strip() or None
        
        # Get CC
        cc_input = input("📋 CC (comma-separated, optional): ").strip()
        cc = [c.strip() for c in cc_input.split(",")] if cc_input else []
        
        # Get BCC
        bcc_input = input("📋 BCC (comma-separated, optional): ").strip()
        bcc = [b.strip() for b in bcc_input.split(",")] if bcc_input else []
        
        received_date = datetime.now().isoformat()
        
        email_obj = EmailMessage(
            email_id=email_id,
            sender=sender,
            sender_name=sender_name,
            subject=subject,
            body=body,
            html_body="",
            received_date=received_date,
            urls=urls,
            attachments=attachments,
            headers={"From": sender},
            reply_to=reply_to,
            cc=cc,
            bcc=bcc
        )
        
        emails.append(email_obj)
        print(f"\n✓ Email captured successfully (ID: {email_id})\n")
        return emails


class DummyInboxConnector(EmailIngestor):
    """Dummy inbox with sample phishing/safe emails for testing"""
   
    def fetch_emails(self) -> List[EmailMessage]:
        """Return sample emails"""
        return [
            EmailMessage(
                email_id="DUMMY_001",
                sender="admin@university.edu",
                sender_name="University Admin",
                subject="Spring Semester Registration Confirmation",
                body="Dear Student,\n\nYour registration for Spring 2026 has been confirmed. "
                     "You are enrolled in the following courses:\n\nNo further action required.\n\n"
                     "Regards,\nUniversity Registration Office",
                html_body="<html>Spring Registration Confirmed</html>",
                received_date="2026-02-01T09:00:00",
                urls=[],
                attachments=[],
                headers={"From": "admin@university.edu"},
                reply_to="admin@university.edu"
            ),
            EmailMessage(
                email_id="DUMMY_002",
                sender="support@paypa1-verify.tk",
                sender_name="PayPal Security",
                subject="🚨 URGENT: Verify Your PayPal Account Immediately!",
                body="Dear PayPal Customer,\n\n"
                     "We have detected unusual activity on your account.\n"
                     "ACT NOW to verify your identity within 24 hours or your account will be LOCKED PERMANENTLY.\n\n"
                     "Click here to verify: [LINK]\n\n"
                     "Your password, credit card, and SSN verification are required.\n\n"
                     "PayPal Security Team",
                html_body="<html>Verify Account Now</html>",
                received_date="2026-02-01T10:30:00",
                urls=["http://bit.ly/paypal-verify", "http://secure-paypal-update.tk/verify"],
                attachments=[{"name": "invoice.exe", "size": 245000}],
                headers={"From": "support@paypa1-verify.tk"},
                reply_to="support@paypal-security-login.com"
            ),
            EmailMessage(
                email_id="DUMMY_003",
                sender="finance@company.local",
                sender_name="Finance Department",
                subject="Invoice #INV-2026-001 Payment Due",
                body="Invoice for services rendered in January 2026.\n\n"
                     "Amount Due: $5,000\n"
                     "Due Date: February 15, 2026\n\n"
                     "Please process payment through the accounting system.\n\n"
                     "Finance Team",
                html_body="<html>Invoice</html>",
                received_date="2026-02-01T11:15:00",
                urls=["https://accounting.company.local/invoices/INV-2026-001"],
                attachments=[{"name": "invoice.pdf", "size": 125000}],
                headers={"From": "finance@company.local"},
                reply_to="finance@company.local"
            ),
            EmailMessage(
                email_id="DUMMY_004",
                sender="ceo@company-official.com",
                sender_name="CEO",
                subject="CONFIDENTIAL: Gift Card Purchase Request",
                body="I'm currently in a board meeting and need your urgent help.\n\n"
                     "Please purchase Google Play gift cards worth $2,000 immediately\n"
                     "and send me the codes via email.\n\n"
                     "This is time-sensitive. Act now.\n\n"
                     "CEO",
                html_body="<html>Gift Cards Needed</html>",
                received_date="2026-02-01T13:45:00",
                urls=[],
                attachments=[],
                headers={"From": "ceo@company-official.com"},
                reply_to="ceo@company-official.com"
            ),
            EmailMessage(
                email_id="DUMMY_005",
                sender="newsletter@techstore.com",
                sender_name="TechStore Newsletter",
                subject="50% OFF This Weekend Only!",
                body="Don't miss out! We have 50% off on all electronics this weekend.\n\n"
                     "Visit our store: https://techstore.com/sale\n\n"
                     "Offer ends Sunday.\n\n"
                     "TechStore Team",
                html_body="<html>50% OFF</html>",
                received_date="2026-02-01T15:20:00",
                urls=["https://techstore.com/sale"],
                attachments=[],
                headers={"From": "newsletter@techstore.com"},
                reply_to="newsletter@techstore.com"
            ),
        ]


class IMAPConnector(EmailIngestor):
    """Real IMAP connector for Gmail/Outlook with error handling"""
   
    def __init__(self, email_address: str, password: str, imap_server: str = "imap.gmail.com"):
        """
        Initialize IMAP connector
       
        Args:
            email_address: Email address to connect
            password: Email password or app-specific password
            imap_server: IMAP server address
        """
        self.email_address = email_address
        self.password = password
        self.imap_server = imap_server
        self.mail = None

    def connect(self) -> bool:
        """Connect to IMAP server with error handling"""
        try:
            print(f"\n⏳ Connecting to {self.imap_server}...")
            self.mail = imaplib.IMAP4_SSL(self.imap_server, timeout=10)
            self.mail.login(self.email_address, self.password)
            print(f"✓ Successfully connected and authenticated")
            return True
        except imaplib.IMAP4.error as e:
            print(f"❌ IMAP Error: {e}")
            print("   Possible causes:")
            print("   • Incorrect email or password")
            print("   • For Gmail: Use app-specific password (not regular password)")
            print("   • For Gmail: Enable 'Less secure app access' in account settings")
            return False
        except ConnectionRefusedError:
            print(f"❌ Connection refused: Cannot reach {self.imap_server}")
            return False
        except TimeoutError:
            print(f"❌ Connection timeout: IMAP server {self.imap_server} is not responding")
            return False
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False

    def fetch_emails(self, folder: str = "INBOX", limit: int = 10) -> List[EmailMessage]:
        """
        Fetch emails from IMAP server with error handling
       
        Args:
            folder: Email folder to fetch from
            limit: Maximum number of emails to fetch
           
        Returns:
            List of EmailMessage objects
        """
        if not self.mail:
            if not self.connect():
                return []

        try:
            print(f"\n⏳ Fetching emails from {folder}...")
            self.mail.select(folder)
            status, messages = self.mail.search(None, "ALL")
           
            if status != "OK":
                print(f"❌ Failed to search emails")
                return []
            
            email_ids = messages[0].split()[-limit:]  # Get last N emails
            if not email_ids:
                print(f"⚠️  No emails found in {folder}")
                return []
            
            emails = []
            print(f"   Found {len(email_ids)} email(s), parsing...\n")

            for idx, email_id in enumerate(email_ids, 1):
                try:
                    status, msg_data = self.mail.fetch(email_id, "(RFC822)")
                    if status != "OK":
                        print(f"   ⚠️  Skipping email {idx} - fetch failed")
                        continue
                    
                    msg = email.message_from_bytes(msg_data[0][1])
                    email_obj = self._parse_email(msg, email_id.decode())
                    emails.append(email_obj)
                    print(f"   ✓ Email {idx}: {email_obj.subject[:50]}...")
                except Exception as e:
                    print(f"   ⚠️  Error parsing email {idx}: {e}")
                    continue

            print(f"\n✓ Successfully fetched {len(emails)} emails\n")
            return emails

        except Exception as e:
            print(f"❌ Error fetching emails: {e}")
            return []

    @staticmethod
    def _parse_email(msg, email_id: str) -> EmailMessage:
        """Parse email message with error handling"""
       
        try:
            # Extract basic headers
            sender = msg.get("From", "Unknown")
            sender_name = sender.split("<")[0].strip() if "<" in sender else sender
            subject = msg.get("Subject", "No Subject")
            received_date = msg.get("Date", datetime.now().isoformat())
            reply_to = msg.get("Reply-To", None)
            cc = msg.get("Cc", "").split(",") if msg.get("Cc") else []
            bcc = msg.get("Bcc", "").split(",") if msg.get("Bcc") else []

            # Decode subject if encoded
            if isinstance(subject, email.header.Header):
                subject = str(subject)

            # Extract body and URLs
            body = ""
            html_body = ""
            urls = []
            attachments = []

            for part in msg.walk():
                try:
                    content_type = part.get_content_type()

                    if content_type == "text/plain":
                        try:
                            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            # Extract URLs from body
                            urls.extend(re.findall(r'http[s]?://[^\s\)]+', body))
                        except:
                            pass

                    elif content_type == "text/html":
                        try:
                            html_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            # Extract URLs from HTML
                            urls.extend(re.findall(r'http[s]?://[^\s\)\"\']+', html_body))
                        except:
                            pass

                    # Extract attachments
                    elif part.get_content_disposition() == "attachment":
                        filename = part.get_filename()
                        if filename:
                            try:
                                payload = part.get_payload(decode=True)
                                attachments.append({
                                    "name": filename,
                                    "size": len(payload) if payload else 0
                                })
                            except:
                                attachments.append({
                                    "name": filename,
                                    "size": 0
                                })
                except:
                    continue

            return EmailMessage(
                email_id=email_id,
                sender=sender,
                sender_name=sender_name,
                subject=subject,
                body=body,
                html_body=html_body,
                received_date=received_date,
                urls=list(set(urls)),  # Remove duplicates
                attachments=attachments,
                headers={k: msg.get(k) for k in msg.keys()},
                reply_to=reply_to,
                cc=cc,
                bcc=bcc
            )
        except Exception as e:
            print(f"   ⚠️  Error parsing email: {e}")
            return None

    def disconnect(self):
        """Disconnect from server"""
        if self.mail:
            try:
                self.mail.close()
                self.mail.logout()
                print("✓ Disconnected from server")
            except:
                pass


# ============================================================================
# PART 2: NLP/ML PIPELINE FOR PHISHING DETECTION
# ============================================================================

@dataclass
class PhishingIndicator:
    """Single phishing indicator"""
    category: str
    keyword: str
    weight: int
    reason: str


class PhishingDetectionML:
    """NLP/ML Pipeline for comprehensive phishing detection"""
   
    # Machine learning features (rule-based patterns)
    URGENCY_PATTERNS = {
        r"urgent": 15, r"immediate": 15, r"act now": 20, r"asap": 15,
        r"time.{0,3}sensitive": 18, r"limited time": 20, r"expir": 18,
        r"deadline": 15, r"within.{0,3}\d+.{0,3}hours?": 20, r"don't delay": 18,
        r"must.{0,3}act": 20, r"immediately": 18, r"urgent action": 25,
    }
   
    CREDENTIAL_PATTERNS = {
        r"password": 30, r"verify.*account": 35, r"verify.*identity": 35,
        r"confirm.*password": 35, r"reset.*password": 30, r"login": 20,
        r"authenticate": 25, r"2fa": 25, r"verification code": 25,
        r"otp": 25, r"access token": 25, r"secret key": 30,
    }
   
    FINANCIAL_PATTERNS = {
        r"payment": 20, r"invoice": 18, r"wire transfer": 25, r"bank transfer": 25,
        r"credit card": 25, r"debit card": 20, r"billing": 18, r"refund": 15,
        r"routing number": 25, r"account number": 25, r"atm.*card": 25,
    }
   
    THREAT_PATTERNS = {
        r"account.*suspended": 35, r"account.*locked": 35, r"unauthorized access": 30,
        r"unusual activity": 25, r"breach": 30, r"compromised": 35, r"legal action": 35,
        r"final warning": 30, r"will.*close": 30, r"action required": 25,
    }
   
    SUSPICIOUS_EXTENSIONS = {
        r"\.exe$": 35, r"\.bat$": 35, r"\.zip$": 20, r"\.html$": 25,
        r"\.scr$": 35, r"\.vbs$": 35, r"\.js$": 20,
    }

    def __init__(self):
        """Initialize ML pipeline"""
        self.urgency_compiled = [(re.compile(p, re.IGNORECASE), w)
                                 for p, w in self.URGENCY_PATTERNS.items()]
        self.credential_compiled = [(re.compile(p, re.IGNORECASE), w)
                                    for p, w in self.CREDENTIAL_PATTERNS.items()]
        self.financial_compiled = [(re.compile(p, re.IGNORECASE), w)
                                   for p, w in self.FINANCIAL_PATTERNS.items()]
        self.threat_compiled = [(re.compile(p, re.IGNORECASE), w)
                               for p, w in self.THREAT_PATTERNS.items()]
        self.extension_compiled = [(re.compile(p, re.IGNORECASE), w)
                                  for p, w in self.SUSPICIOUS_EXTENSIONS.items()]

    def analyze(self, email_msg: EmailMessage) -> Tuple[float, List[PhishingIndicator]]:
        """
        Analyze email using ML/NLP pipeline
       
        Returns:
            (risk_score, list_of_indicators)
        """
        risk_score = 0.0
        indicators: List[PhishingIndicator] = []
       
        full_text = f"{email_msg.subject} {email_msg.body}".lower()
       
        # Feature 1: Urgency Language Detection
        for pattern, weight in self.urgency_compiled:
            if pattern.search(full_text):
                risk_score += weight
                indicators.append(PhishingIndicator(
                    category="urgency",
                    keyword=pattern.pattern[:30],
                    weight=weight,
                    reason="High-pressure language to bypass thinking"
                ))
       
        # Feature 2: Credential Harvesting Detection
        for pattern, weight in self.credential_compiled:
            if pattern.search(full_text):
                risk_score += weight
                indicators.append(PhishingIndicator(
                    category="credential",
                    keyword=pattern.pattern[:30],
                    weight=weight,
                    reason="Attempting to steal login credentials"
                ))
       
        # Feature 3: Financial Request Detection
        for pattern, weight in self.financial_compiled:
            if pattern.search(full_text):
                risk_score += weight
                indicators.append(PhishingIndicator(
                    category="financial",
                    keyword=pattern.pattern[:30],
                    weight=weight,
                    reason="Attempting to extract financial information"
                ))
       
        # Feature 4: Threat Language Detection
        for pattern, weight in self.threat_compiled:
            if pattern.search(full_text):
                risk_score += weight
                indicators.append(PhishingIndicator(
                    category="threat",
                    keyword=pattern.pattern[:30],
                    weight=weight,
                    reason="Using fear/intimidation tactics"
                ))
       
        # Feature 5: URL Analysis
        url_score = self._analyze_urls(email_msg.urls, email_msg.sender)
        risk_score += url_score
       
        # Feature 6: Sender Analysis
        sender_score = self._analyze_sender(email_msg.sender, email_msg.reply_to)
        risk_score += sender_score
       
        # Feature 7: Attachment Analysis
        att_score = self._analyze_attachments(email_msg.attachments)
        risk_score += att_score
       
        # Feature 8: Domain Mismatch
        if email_msg.reply_to and email_msg.sender != email_msg.reply_to:
            domain1 = email_msg.sender.split("@")[-1] if "@" in email_msg.sender else ""
            domain2 = email_msg.reply_to.split("@")[-1] if "@" in email_msg.reply_to else ""
            if domain1 != domain2:
                risk_score += 25
                indicators.append(PhishingIndicator(
                    category="sender_spoofing",
                    keyword="domain_mismatch",
                    weight=25,
                    reason="Sender and reply-to domains don't match"
                ))
       
        # Cap at 100
        risk_score = min(100, risk_score)
       
        return risk_score, indicators

    def _analyze_urls(self, urls: List[str], sender: str) -> float:
        """Analyze URLs for phishing"""
        score = 0.0
       
        for url in urls:
            # Check for shortened URLs
            if re.search(r"(bit\.ly|tinyurl|short\.link|goo\.gl)", url):
                score += 25
            # Check for suspicious TLDs
            elif re.search(r"\.(tk|ml|ga|cf)$", url):
                score += 20
            # Check for domain mismatch
            elif sender and "@" in sender:
                sender_domain = sender.split("@")[-1]
                if sender_domain not in url:
                    score += 15
       
        return min(score, 50)  # Cap URL score

    def _analyze_sender(self, sender: str, reply_to: Optional[str]) -> float:
        """Analyze sender for spoofing"""
        score = 0.0
       
        sender_lower = sender.lower()
       
        # Generic sender
        if re.search(r"(noreply|donotreply|no-reply|alert)", sender_lower):
            score += 10
       
        # Domain mimicry
        if re.search(r"(paypa1|p4ypal|amaz0n|g00gle|micr0soft)", sender_lower):
            score += 30
       
        # Suspicious TLD
        if re.search(r"@.*\.(tk|ml|ga|cf)$", sender_lower):
            score += 20
       
        return min(score, 50)

    def _analyze_attachments(self, attachments: List[Dict]) -> float:
        """Analyze attachments"""
        score = 0.0
       
        for att in attachments:
            for pattern, weight in self.extension_compiled:
                if pattern.search(att["name"]):
                    score += weight
                    break
       
        return min(score, 50)


# ============================================================================
# PART 3: RISK SCORING & EXPLANATION ENGINE
# ============================================================================

@dataclass
class AnalysisReport:
    """Complete analysis report for email"""
    email_id: str
    risk_score: float
    classification: RiskLevel
    indicators: List[PhishingIndicator]
    explanation: str
    recommendations: List[str]
    analysis_timestamp: datetime


class RiskScoringEngine:
    """Generates risk scores and human-readable explanations"""
   
    def generate_report(self, email_msg: EmailMessage,
                       risk_score: float,
                       indicators: List[PhishingIndicator]) -> AnalysisReport:
        """Generate comprehensive analysis report"""
       
        # Classify based on score
        if risk_score <= 25:
            classification = RiskLevel.SAFE
        elif risk_score <= 60:
            classification = RiskLevel.SUSPICIOUS
        else:
            classification = RiskLevel.MALICIOUS
       
        # Generate explanation
        explanation = self._generate_explanation(
            email_msg, risk_score, classification, indicators
        )
       
        # Generate recommendations
        recommendations = self._generate_recommendations(classification, indicators)
       
        return AnalysisReport(
            email_id=email_msg.email_id,
            risk_score=risk_score,
            classification=classification,
            indicators=indicators,
            explanation=explanation,
            recommendations=recommendations,
            analysis_timestamp=datetime.now()
        )

    def _generate_explanation(self, email_msg: EmailMessage, risk_score: float,
                             classification: RiskLevel,
                             indicators: List[PhishingIndicator]) -> str:
        """Generate human-readable explanation"""
       
        explanation = f"\n{'='*80}\n"
        explanation += f"EMAIL SECURITY ANALYSIS REPORT\n"
        explanation += f"{'='*80}\n\n"
       
        explanation += f"Email ID: {email_msg.email_id}\n"
        explanation += f"From: {email_msg.sender}\n"
        explanation += f"Subject: {email_msg.subject}\n"
        explanation += f"Received: {email_msg.received_date}\n\n"
       
        # Risk level
        if classification == RiskLevel.SAFE:
            explanation += f"🟢 RISK LEVEL: SAFE ({risk_score:.0f}/100)\n"
            explanation += "This email appears legitimate with no significant phishing indicators.\n\n"
        elif classification == RiskLevel.SUSPICIOUS:
            explanation += f"🟡 RISK LEVEL: SUSPICIOUS ({risk_score:.0f}/100)\n"
            explanation += "This email contains warning signs typical of phishing attempts.\n\n"
        else:
            explanation += f"🔴 RISK LEVEL: MALICIOUS ({risk_score:.0f}/100)\n"
            explanation += "⚠️ This email exhibits multiple strong phishing indicators.\n\n"
       
        # Detected indicators
        if indicators:
            explanation += "KEY PHISHING SIGNALS DETECTED:\n"
            explanation += "-" * 80 + "\n"
           
            # Group by category
            by_category = defaultdict(list)
            for ind in indicators:
                by_category[ind.category].append(ind)
           
            for category, inds in sorted(by_category.items()):
                explanation += f"\n{category.upper()}:\n"
                for ind in inds[:3]:
                    explanation += f"  • {ind.keyword} (+{ind.weight} points)\n"
                    explanation += f"    └─ {ind.reason}\n"
                if len(inds) > 3:
                    explanation += f"  ... and {len(inds) - 3} more indicators\n"
       
        # URLs and attachments
        if email_msg.urls:
            explanation += f"\nURLs FOUND:\n"
            for url in email_msg.urls[:3]:
                explanation += f"  • {url}\n"
       
        if email_msg.attachments:
            explanation += f"\nATTACHMENTS:\n"
            for att in email_msg.attachments:
                explanation += f"  • {att['name']} ({att['size']} bytes)\n"
       
        explanation += f"\n{'='*80}\n"
       
        return explanation

    def _generate_recommendations(self, classification: RiskLevel,
                                 indicators: List[PhishingIndicator]) -> List[str]:
        """Generate security recommendations"""
       
        recommendations = []
       
        if classification == RiskLevel.SAFE:
            recommendations = [
                "✓ Email appears legitimate",
                "✓ Safe to open and interact with",
                "✓ No action required"
            ]
       
        elif classification == RiskLevel.SUSPICIOUS:
            recommendations = [
                "⚠️ Do NOT click any links without verifying sender",
                "⚠️ Do NOT download attachments",
                "⚠️ Contact sender through known contact method",
                "⚠️ Be cautious with credential/financial requests",
                "⚠️ Report to IT security if corporate email"
            ]
       
        else:  # MALICIOUS
            recommendations = [
                "🚨 DELETE this email immediately",
                "🚨 DO NOT click any links",
                "🚨 DO NOT download attachments",
                "🚨 DO NOT reply or provide information",
                "🚨 DO NOT transfer money",
                "🚨 Report to IT security team",
                "✓ Mark as Phishing/Spam"
            ]
       
        return recommendations


# ============================================================================
# PART 4: INTERACTIVE REVIEWER DASHBOARD WITH FEEDBACK COLLECTION
# ============================================================================

class ReviewerDashboard:
    """Interactive dashboard for reviewing emails and collecting feedback"""
   
    def __init__(self, db_path: str = "email_analysis.db"):
        self.db_path = db_path
        self.init_database()
   
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
       
        # Analysis results
        c.execute('''CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id TEXT UNIQUE,
            sender TEXT,
            subject TEXT,
            risk_score REAL,
            classification TEXT,
            indicators TEXT,
            explanation TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_feedback TEXT,
            feedback_correct INTEGER,
            feedback_timestamp DATETIME
        )''')
       
        # User feedback for model improvement
        c.execute('''CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id TEXT,
            original_classification TEXT,
            user_correction TEXT,
            reason TEXT,
            confidence INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(email_id) REFERENCES analyses(email_id)
        )''')
       
        # Model performance metrics
        c.execute('''CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_name TEXT,
            metric_value REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
       
        conn.commit()
        conn.close()
   
    def save_analysis(self, report: AnalysisReport, sender: str = "", subject: str = ""):
        """Save analysis to database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
       
        try:
            c.execute('''INSERT INTO analyses
                        (email_id, sender, subject, risk_score, classification, indicators, explanation)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (report.email_id, sender, subject, report.risk_score, report.classification.value,
                      json.dumps([asdict(ind) for ind in report.indicators]), report.explanation))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()
   
    def record_feedback(self, email_id: str, original_class: str,
                       correction: str, reason: str = "", confidence: int = 5, is_correct: bool = False):
        """Record user feedback for model improvement"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
       
        # Save feedback
        c.execute('''INSERT INTO feedback
                    (email_id, original_classification, user_correction, reason, confidence)
                    VALUES (?, ?, ?, ?, ?)''',
                 (email_id, original_class, correction, reason, confidence))
       
        # Update analysis
        c.execute('UPDATE analyses SET user_feedback = ?, feedback_correct = ?, feedback_timestamp = ? WHERE email_id = ?',
                 (correction, 1 if is_correct else 0, datetime.now(), email_id))
       
        conn.commit()
        conn.close()
   
    def get_statistics(self) -> Dict:
        """Get dashboard statistics"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
       
        c.execute('SELECT COUNT(*) FROM analyses')
        total = c.fetchone()[0]
       
        c.execute('SELECT classification, COUNT(*) FROM analyses GROUP BY classification')
        classifications = {row[0]: row[1] for row in c.fetchall()}
       
        c.execute('SELECT AVG(risk_score) FROM analyses')
        avg_score = c.fetchone()[0] or 0
       
        c.execute('SELECT COUNT(*) FROM feedback WHERE original_classification = user_correction')
        correct_feedback = c.fetchone()[0]
       
        c.execute('SELECT COUNT(*) FROM feedback')
        total_feedback = c.fetchone()[0]
       
        conn.close()
       
        accuracy = (correct_feedback / total_feedback * 100) if total_feedback > 0 else 0
       
        return {
            "total_analyzed": total,
            "classifications": classifications,
            "average_risk_score": round(avg_score, 1),
            "total_feedback": total_feedback,
            "model_accuracy": round(accuracy, 1)
        }
   
    def display_dashboard(self, reports: List[AnalysisReport]):
        """Display interactive dashboard"""
        print("\n" + "="*80)
        print("📊 EMAIL PHISHING DETECTION REVIEWER DASHBOARD")
        print("="*80)
       
        while True:
            print("\n\n🔍 MAIN MENU:")
            print("1. View All Analysis Results")
            print("2. Review Specific Email")
            print("3. Provide Feedback")
            print("4. View Statistics & Metrics")
            print("5. Export Report")
            print("6. Exit")
           
            choice = input("\nEnter choice (1-6): ").strip()
           
            if choice == "1":
                self._view_all_results(reports)
            elif choice == "2":
                self._review_email(reports)
            elif choice == "3":
                self._provide_feedback(reports)
            elif choice == "4":
                self._view_statistics()
            elif choice == "5":
                self._export_report(reports)
            elif choice == "6":
                print("\n✓ Exiting dashboard.\n")
                break
   
    def _view_all_results(self, reports: List[AnalysisReport]):
        """Display all analysis results"""
        print("\n" + "="*80)
        print("ALL ANALYSIS RESULTS")
        print("="*80 + "\n")
       
        for report in reports:
            emoji = "🟢" if report.classification == RiskLevel.SAFE else (
                "🟡" if report.classification == RiskLevel.SUSPICIOUS else "🔴"
            )
            print(f"{emoji} {report.email_id}")
            print(f"   Classification: {report.classification.value}")
            print(f"   Risk Score: {report.risk_score:.0f}/100")
            print(f"   Indicators: {len(report.indicators)}")
            print()
   
    def _review_email(self, reports: List[AnalysisReport]):
        """Review specific email"""
        email_id = input("\nEnter Email ID to review (e.g., DUMMY_001): ").strip().upper()
       
        report = next((r for r in reports if r.email_id == email_id), None)
        if not report:
            print(f"❌ Email {email_id} not found")
            return
       
        print(report.explanation)
        print("\nRECOMMENDATIONS:")
        for rec in report.recommendations:
            print(f"   {rec}")
   
    def _provide_feedback(self, reports: List[AnalysisReport]):
        """Provide feedback on classification"""
        email_id = input("\nEnter Email ID for feedback: ").strip().upper()
       
        report = next((r for r in reports if r.email_id == email_id), None)
        if not report:
            print(f"❌ Email {email_id} not found")
            return
       
        print(f"\nOriginal Classification: {report.classification.value}")
        is_correct = input("Is this CORRECT? (yes/no): ").strip().lower()
       
        if is_correct == "yes":
            self.record_feedback(
                email_id, report.classification.value,
                report.classification.value, "Correct", 5, True
            )
            print("✓ Feedback recorded - Classification was correct")
        else:
            correction = input("What should it be? (SAFE/SUSPICIOUS/MALICIOUS): ").strip().upper()
            reason = input("Why is this correction needed? ")
            confidence = int(input("Confidence (1-10): ") or "5")
           
            self.record_feedback(
                email_id, report.classification.value,
                correction, reason, confidence, False
            )
            print("✓ Feedback recorded - Model will improve from this")
   
    def _view_statistics(self):
        """Display statistics"""
        stats = self.get_statistics()
       
        print("\n" + "="*80)
        print("DASHBOARD STATISTICS")
        print("="*80)
        print(f"\nTotal Emails Analyzed: {stats['total_analyzed']}")
        print(f"Average Risk Score: {stats['average_risk_score']}/100")
        print(f"Total Feedback Collected: {stats['total_feedback']}")
        print(f"Model Accuracy: {stats['model_accuracy']}%")
        print(f"\nClassification Breakdown:")
        for class_name, count in stats['classifications'].items():
            print(f"  {class_name}: {count}")
   
    def _export_report(self, reports: List[AnalysisReport]):
        """Export comprehensive report"""
        filename = input("Enter filename (default: phishing_report.txt): ").strip()
        if not filename:
            filename = "phishing_report.txt"
       
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("EMAIL PHISHING DETECTION SYSTEM - ANALYSIS REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
           
            for report in reports:
                f.write(report.explanation)
                f.write("\n\n")
       
        print(f"✓ Report exported to {filename}")


# ============================================================================
# MAIN PROGRAM
# ============================================================================

def main():
    """Main entry point"""
    print("\n" + "="*80)
    print("🛡️  COMPLETE EMAIL PHISHING DETECTION SYSTEM")
    print("="*80)
    print("\nDELIVERABLES:")
    print("✓ Email Ingestion Module (IMAP + Dummy Inbox + Manual Input)")
    print("✓ NLP/ML Pipeline for Phishing Detection")
    print("✓ Risk Scoring & Explanation Engine")
    print("✓ Interactive Reviewer Dashboard with Feedback Collection")
   
    # Initialize components
    ml_pipeline = PhishingDetectionML()
    risk_engine = RiskScoringEngine()
    dashboard = ReviewerDashboard()
   
    # Step 1: Email Ingestion
    print("\n\n" + "="*80)
    print("STEP 1: EMAIL INGESTION")
    print("="*80)
    print("\nChoose email source:")
    print("1. Dummy Inbox (sample phishing emails for testing)")
    print("2. Manual Input (provide email details manually)")
    print("3. Real Gmail/Outlook (IMAP connection)")
   
    choice = input("\nEnter choice (1-3): ").strip()
   
    if choice == "1":
        print("\n⏳ Loading sample emails from dummy inbox...")
        ingestor = DummyInboxConnector()
        emails = ingestor.fetch_emails()
    elif choice == "2":
        ingestor = ManualInputConnector()
        emails = ingestor.fetch_emails()
    else:
        email_addr = input("\n📧 Enter your email address: ").strip()
        if not email_addr:
            print("❌ Email address required")
            return
        
        password = input("🔐 Enter password (app-specific for Gmail): ").strip()
        if not password:
            print("❌ Password required")
            return
        
        imap_server_choice = input("Select IMAP Server:\n1. Gmail (imap.gmail.com)\n2. Outlook (outlook.office365.com)\n3. Other: Enter address\nChoice (1-3): ").strip()
        
        if imap_server_choice == "1":
            imap_server = "imap.gmail.com"
        elif imap_server_choice == "2":
            imap_server = "outlook.office365.com"
        else:
            imap_server = input("Enter IMAP server address: ").strip() or "imap.gmail.com"
        
        print(f"\n⏳ Connecting to {imap_server}...")
        ingestor = IMAPConnector(email_addr, password, imap_server)
        emails = ingestor.fetch_emails(limit=5)
        ingestor.disconnect()
   
    if not emails:
        print("❌ No emails found")
        return
   
    print(f"✓ Loaded {len(emails)} emails\n")
   
    # Step 2: NLP/ML Analysis
    print("="*80)
    print("STEP 2: NLP/ML PIPELINE ANALYSIS")
    print("="*80)
    print(f"\n⏳ Analyzing {len(emails)} emails for phishing indicators...\n")
   
    reports = []
    for email_msg in emails:
        risk_score, indicators = ml_pipeline.analyze(email_msg)
        report = risk_engine.generate_report(email_msg, risk_score, indicators)
        reports.append(report)
        dashboard.save_analysis(report, email_msg.sender, email_msg.subject)
       
        emoji = "🟢" if report.classification == RiskLevel.SAFE else (
            "🟡" if report.classification == RiskLevel.SUSPICIOUS else "🔴"
        )
        print(f"✓ {emoji} {report.email_id}: {report.classification.value} ({report.risk_score:.0f}/100)")
   
    # Step 3: Display Reports
    print("\n" + "="*80)
    print("STEP 3: ANALYSIS REPORTS")
    print("="*80)
   
    for report in reports:
        print(report.explanation)
        print("\n📋 RECOMMENDATIONS:")
        for rec in report.recommendations:
            print(f"   {rec}")
        print()
   
    # Step 4: Interactive Dashboard
    print("="*80)
    print("STEP 4: REVIEWER DASHBOARD")
    print("="*80)
    print("\nLaunching interactive dashboard for email review and feedback collection...\n")
   
    dashboard.display_dashboard(reports)


if __name__ == "__main__":
    main()
