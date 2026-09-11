"""
Synthetic & Empirical Training Corpus Generator for TRACE-MAIL AI.
Generates balanced, diverse datasets for:
- Class 0: Legitimate (corporate, technical, academic, billing receipts)
- Class 1: Phishing (credential harvesting, MFA fatigue, fake notifications)
- Class 2: BEC / Financial Fraud (wire diversion, invoice reroute, CEO gift card, payroll)
"""

import json
import random
from pathlib import Path
from typing import List, Dict, Any

VENDORS = ["Apex Lab Supplies", "Northwind Logistics", "Contoso Hardware", "Global Cloud Services", "Precision Machining Inc", "Acme IT Solutions", "CyberRange Partners", "Stripe Billing Services"]
EXECUTIVES = ["CEO", "Chief Financial Officer", "Managing Director", "VP of Engineering", "Chief Executive Officer", "Executive Director"]
BANKS = ["Standard Chartered", "Barclays Corporate", "JPMorgan Chase Commercial", "Wells Fargo", "Deutsche Bank", "State Bank Enterprise"]
EMPLOYEES = ["Alex Rivera", "Sarah Chen", "Marcus Vance", "Elena Rostova", "David Kim", "Priya Sharma", "Michael Scott", "Rachel Green"]
PROJECTS = ["Smart India Hackathon", "Q3 Infrastructure Migration", "SOC 2 Type II Compliance", "ERP Upgrade", "Firewall Rule Review", "Penetration Testing Scope"]
SERVICES = ["Microsoft 365", "Google Workspace", "DocuSign", "Dropbox Enterprise", "Slack Technologies", "Okta Identity", "GitHub Enterprise", "Zoom Video"]

LEGITIMATE_TEMPLATES = [
    "Hi team, here are the minutes from today's project review meeting regarding {project}. Please review the attached slide deck.",
    "Reminder: The weekly department standup has been rescheduled to tomorrow at 10:30 AM in Conference Room B.",
    "Your monthly service receipt for {vendor} is ready for review. Payment of ${amount} was successfully processed via corporate credit card.",
    "Smart India Hackathon campus briefing session will be held this Friday in the main auditorium. All participants must attend.",
    "Please find attached the quarterly server performance report for {service}. All SLA metrics were within normal thresholds.",
    "Routine software maintenance is scheduled for this Saturday from 22:00 to 02:00 UTC. Brief network downtime may occur.",
    "Welcome to the team, {employee}! Please coordinate with HR today to finalize your onboarding documentation and workstation setup.",
    "The library book you requested has been checked out. Due date is next Wednesday. Contact the desk if you need a renewal.",
    "Class timetable update: The Advanced Network Security lab will take place in Lab 4 starting next Monday.",
    "Your pull request on {project} has been approved and merged into the main branch by the code review team.",
    "HR Notice: Annual open enrollment for health insurance benefits begins next week. Review the portal for plan details.",
    "Campus placement orientation schedule is now published. Students with eligibility criteria can check their portal.",
    "Attached is the signed non-disclosure agreement for the upcoming collaborative research initiative with {vendor}.",
    "Invoice receipt #{inv}: Your payment to {service} has been received. Thank you for your continued partnership.",
    "Security briefing: Please ensure all corporate laptops have the latest OS patch installed by Friday evening."
]

PHISHING_TEMPLATES = [
    "URGENT: Your {service} account password will expire in 2 hours. Click here to verify your credentials and retain access: http://login-verify-{service_slug}.com",
    "Security Alert: Unusual sign-in detected on your {service} account from an unrecognized location. Confirm your identity immediately at http://security-{service_slug}.net",
    "Action Required: Your mailbox is almost full ({pct}% capacity). Incoming emails will be blocked. Clean up your quota now at http://storage-portal-{service_slug}.org",
    "A confidential document has been shared with you via {service}. Sign in with your corporate email and password to view: http://shared-doc-auth.icu",
    "IT Helpdesk Notification: Your multi-factor authentication token has been de-synchronized. Re-authenticate your corporate account at http://sso-portal-sync.xyz",
    "Payroll Alert: An error occurred while processing your latest direct deposit. Update your login credentials and banking details at http://payroll-portal-auth.top",
    "Your incoming parcel delivery failed due to incorrect address information. Pay a $2.50 redelivery fee and confirm your identity at http://courier-tracking-redeliver.click",
    "Notice from Human Resources: Please review the updated mandatory employee conduct policy by signing into the employee portal: http://hr-portal-review.monster",
    "Immediate Action Required: Your access to {service} enterprise portal has been suspended due to suspicious activity. Verify credentials to restore access.",
    "DocuSign: {employee} sent you a document for urgent electronic signature. Click here to review and authenticate your corporate identity.",
    "Zoom Meeting: Missed voice memo from your manager. Log in with your office credentials to play audio recording: http://voicemail-portal-listen.rest",
    "Tax refund notice: You have an unclaimed federal refund of ${amount}. Submit your identification card and account credentials to receive transfer."
]

BEC_TEMPLATES = [
    "CONFIDENTIAL REQUEST: I am currently in back-to-back executive meetings with no phone access. We need an urgent wire transfer of ${amount} processed today for an acquisition. Reply immediately with confirmation. - Sent from my iPhone",
    "URGENT VENDOR INVOICE UPDATE: Regarding invoice #{inv} for {vendor}, please note our primary banking details have changed due to an annual audit. Transfer ${amount} to our new beneficiary account at {bank}. Do not send to our old account.",
    "Payroll direct deposit update: Hi Payroll, I recently changed my banking institution and need to update my direct deposit for this upcoming pay cycle. Please route my compensation to my new account at {bank}. Attached void check.",
    "Payment diversion notification: We have updated our remittance instructions for {vendor}. Effective immediately, all outstanding balances must be wired to our secondary account at {bank}. Please confirm receipt of these instructions.",
    "Executive Gift Card Purchase: Are you at your desk right now? I need you to discreetly purchase 5 Apple gift cards ($100 each) for our client appreciation dinner. Scratch the back and email me the codes immediately.",
    "Confidential Wire Request: Please expedite wire transfer of ${amount} to {bank} for {vendor} consulting fees. The contract was signed off-record by the board. Keep this matter confidential until public filing.",
    "Revised Bank Details: Attached is our updated W-9 and banking details for {vendor}. Our old account at Wells Fargo is being closed. Please update your vendor master record and wire today's invoice balance immediately.",
    "Emergency wire transfer: Hi finance team, I need an urgent international SWIFT payment sent to our overseas supplier {vendor} for ${amount}. Time sensitive, please release payment before cutoff."
]

def generate_corpus(samples_per_class: int = 400) -> List[Dict[str, Any]]:
    dataset = []
    
    # 1. Class 0: Legitimate
    for i in range(samples_per_class):
        template = random.choice(LEGITIMATE_TEMPLATES)
        text = template.format(
            project=random.choice(PROJECTS),
            vendor=random.choice(VENDORS),
            service=random.choice(SERVICES),
            employee=random.choice(EMPLOYEES),
            amount=random.randint(150, 4500),
            inv=random.randint(10000, 99999)
        )
        dataset.append({
            "id": f"LEGIT_{i:04d}",
            "text": text,
            "label": 0,
            "category": "LEGITIMATE"
        })

    # 2. Class 1: Phishing
    for i in range(samples_per_class):
        template = random.choice(PHISHING_TEMPLATES)
        service = random.choice(SERVICES)
        text = template.format(
            service=service,
            service_slug=service.lower().replace(" ", "-"),
            employee=random.choice(EMPLOYEES),
            pct=random.randint(95, 99),
            amount=random.randint(250, 1500)
        )
        dataset.append({
            "id": f"PHISH_{i:04d}",
            "text": text,
            "label": 1,
            "category": "PHISHING"
        })

    # 3. Class 2: BEC / Fraud
    for i in range(samples_per_class):
        template = random.choice(BEC_TEMPLATES)
        vendor = random.choice(VENDORS)
        text = template.format(
            vendor=vendor,
            bank=random.choice(BANKS),
            exec=random.choice(EXECUTIVES),
            amount=random.randint(8500, 150000),
            inv=random.randint(10000, 99999)
        )
        dataset.append({
            "id": f"BEC_{i:04d}",
            "text": text,
            "label": 2,
            "category": "BEC_FRAUD"
        })

    random.seed(42)
    random.shuffle(dataset)
    return dataset

if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent / "data"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "threat_corpus_1200.jsonl"
    
    corpus = generate_corpus(samples_per_class=400)
    with open(out_file, "w", encoding="utf-8") as f:
        for item in corpus:
            f.write(json.dumps(item) + "\n")
            
    print(f"Generated {len(corpus)} balanced threat samples saved to {out_file}")
