"""Builds reproducible demo datasets for ThreatLens.

Real-world accuracy needs real data. These generated samples exist so the
project runs end to end without downloads. To use real data, point
train_model.py at your own CSVs (see README).

Outputs:
  data/messages.csv   columns: text,label   (label 1 = scam, 0 = safe)
  data/urls.csv       columns: url,label    (label 1 = phishing, 0 = safe)

The generator mixes many message *styles* (short chat, casual typing,
transaction alerts, formal notices) so the models do not treat "anything
unfamiliar" as suspicious.
"""
import csv
import random

random.seed(42)

BANKS = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Paytm", "PhonePe", "Kotak", "PNB", "Canara Bank"]
BAD_TLD = ["xyz", "top", "click", "link", "support", "work", "tk", "icu", "buzz", "cam"]
WORDS = ["secure", "verify", "kyc", "update", "login", "claim", "refund", "bonus"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
NAMES = ["Ravi", "Priya", "Arun", "Meena", "Karthik", "Divya", "Suresh", "Anita", "Vikram", "Sana"]


def bad_link():
    b = random.choice(["sbi", "hdfc", "paytm", "amazon", "icici", "irctc", "upi", "jio", "flipkart"])
    w = random.choice(WORDS)
    sep = random.choice(["-", ".", ""])
    return random.choice([
        f"http://{b}-{w}.{random.choice(BAD_TLD)}/{w}",
        f"https://{b}{sep}{w}-india.{random.choice(BAD_TLD)}/{random.randint(100, 9999)}",
        f"bit.ly/{random.choice(['3xKq', '4fRt', '2mZa', '3Lp9'])}{random.randint(1, 99)}",
        f"http://{random.randint(11, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}/{w}",
        f"tinyurl.com/{b}{w}",
        f"www.{b}-{w}.{random.choice(BAD_TLD)}",
    ])


def good_link():
    return random.choice([
        "https://www.amazon.in/orders", "https://www.hdfcbank.com", "https://www.sbi.co.in",
        "https://www.irctc.co.in", "https://www.google.com/maps", "https://zoom.us/j/123456789",
        "https://meet.google.com/abc-defg-hij", "www.annauniv.edu", "https://github.com/",
    ])


# ----------------------------------------------------------------- scam text
SCAM_TEMPLATES = [
    "Dear customer, your {bank} account will be blocked today. Update your KYC immediately: {link}",
    "URGENT: Your {bank} account has been suspended. Verify your details within 24 hours at {link}",
    "Congratulations! You have won ₹{amt} in the lucky draw. Claim your prize now: {link}",
    "Your OTP is {otp}. Do not share. If this was not you, call {phone} immediately to avoid account freeze.",
    "Final notice: your PAN card is not linked. Penalty applies. Update now {link}",
    "Earn ₹{amt} per day working from home. No experience required. WhatsApp {phone} to join today!",
    "Dear user, a refund of ₹{amt} is pending. Click here to confirm your bank details: {link}",
    "Your electricity will be disconnected tonight 9:30 PM. Pay the pending bill now {link} or call {phone}",
    "You've received a cashback reward of Rs.{amt}. Scan the QR code or open {link} to receive it.",
    "{bank}: suspicious login detected. Share the OTP sent to your phone to secure your account. Act now!!!",
    "Hi, I am from {bank} customer care. Please share your card number and CVV to stop the unauthorised transaction.",
    "Your parcel is held at customs. Pay a small processing fee of Rs.{fee} at {link} to release delivery.",
    "LAST CHANCE! Your {bank} credit card reward points worth ₹{amt} expire today. Redeem: {link}",
    "Part-time job offer: like YouTube videos and earn ₹{amt} daily. Send your UPI ID to {phone} to start.",
    "Your Aadhaar is suspended due to illegal activity. Legal action will be taken. Call {phone} now.",
    "Congratulations winner! Free gift card of ${amt} waiting. Tap the link below to claim: {link}",
    "Dear sir/madam, you are selected for a loan of ₹{amt}. No documents. Pay registration fee Rs.{fee} to proceed.",
    "Your Netflix payment failed. Update billing details within 12 hours or the account will be closed: {link}",
    "Income tax refund of ₹{amt} approved. Verify your net banking login at {link} to receive funds.",
    "Hello, I accidentally sent money to your account. Please transfer it back urgently to this UPI ID.",
    "Security alert from Microsoft: your computer is infected. Call support {phone} immediately.",
    "Investment tip: double your money in 7 days guaranteed. Send an advance payment of Rs.{fee} to start.",
    # impersonation / "hi mum" style
    "Hi mom, I lost my phone. This is my new number. Please send ₹{amt} to this account urgently, I will explain later.",
    "Hello dad, my phone is broken so I am using a friend's number. Can you transfer money quickly? It is an emergency.",
    "Hi, it's me. I changed my number, save this one. I need you to pay a bill for me right now, will repay tonight.",
    "Hey, this is your boss. I'm in a meeting and can't talk. Buy {n} gift cards for a client and send me the codes ASAP.",
    # premium-rate / prize-draw SMS style
    "Free entry in 2 a wkly comp to win FA Cup final tkts. Text FA to 87121 to receive entry question",
    "WINNER!! You have been selected to receive a £{amt} prize. Call {phone} now to claim. Valid 24 hours only",
    "You are guaranteed a free holiday! Text WIN to 80082 now. T&Cs apply. Reply STOP to opt out.",
    "Win a free iPhone now! Click the link and enter your details to claim before it ends.",
    "Your mobile number has won ₹{amt}. To collect your reward, reply with your name, bank account and IFSC.",
    # romance / crypto / tech support
    "Hello dear, I am a soldier overseas and want to invest in your country. I need your help to transfer funds. Contact me.",
    "Join our crypto group and earn ₹{amt} guaranteed profit weekly. Limited slots. Message {phone} to start.",
    "Your Apple ID was locked due to suspicious activity. Verify now to avoid permanent suspension: {link}",
    "Your SIM will be blocked in 2 hours. Complete re-verification at {link} to keep your number active.",
    "Your Amazon account password was changed. If this wasn't you, log in and secure it here: {link}",
    "Your package could not be delivered. Confirm your address and pay the redelivery fee of Rs.{fee}: {link}",
    "You have an unpaid traffic fine of ₹{amt}. Pay immediately at {link} to avoid court proceedings.",
    "Dear Customer, your account needs to be verified. Please login at {link} to avoid deactivation.",
]

# ------------------------------------------------------------------ safe text
HAM_TEMPLATES = [
    "Hey, are we still meeting at {time} for lunch?",
    "Your OTP for login to {bank} is {otp}. Valid for 10 minutes. Do not share it with anyone.",
    "Amazon: your order #{num} has been shipped and will arrive by {day}.",
    "Reminder: your dentist appointment is on {day} at {time}.",
    "Can you send me the notes from yesterday's class? I missed the second half.",
    "Thanks for the update. I'll review the report and get back to you by {day}.",
    "Happy birthday! Hope you have a wonderful day with family and friends.",
    "Your {bank} statement for this month is available in the mobile app.",
    "Rs.{amt} debited from your a/c XX{otp4} on {day}. Available balance can be checked in the app.",
    "Mom: dinner is ready, come home soon.",
    "The team meeting has moved to {time} on {day}. Agenda attached in the calendar invite.",
    "Your cab is arriving in 3 minutes. Driver: {name}, vehicle TN 33 AB {otp4}.",
    "Just landed. Will call you after I collect my luggage.",
    "Please find the project submission guidelines attached. Deadline is {day}.",
    "Do you want to watch the match tonight? I can bring snacks.",
    "Your library book is due on {day}. You can renew it from the library portal.",
    "Good morning! The practical exam batches have been posted on the department notice board.",
    "Your Swiggy order from Saravana Bhavan is out for delivery.",
    "I'll transfer the rent to you tomorrow, is the usual account fine?",
    "Class is cancelled tomorrow because the professor is travelling. Revision notes will be shared.",
    "Thank you for shopping with us. Your invoice for order #{num} is attached.",
    "Can we reschedule the call to {time}? Something came up at work.",
    "Your electricity bill of Rs.{amt} has been paid successfully. Thank you.",
    "Congratulations on your promotion! Let's celebrate this weekend.",
    "Don't forget to bring your ID card for the lab session on {day}.",
    # short / casual chat
    "Hi", "Hello", "Hey", "Hi there", "Hello, how are you doing today?", "Hey, what's up?", "Good morning!",
    "Good night, sleep well", "ok thanks", "Okay, see you then", "Sure, no problem", "Thanks a lot!",
    "Yes I'm free after {time}", "Call me when you are free", "On my way, 10 minutes", "Sorry, I'll call later in meeting.",
    "Haha that's funny", "Can you pick up milk on the way home?", "Where are you? We are waiting outside.",
    "Happy Diwali to you and your family!", "Wishing you a speedy recovery. Take rest.",
    "Hi {name}, did you finish the assignment? Submission is {day}.",
    "Hello sir, I have submitted the lab record. Please check.",
    "Hi mom, reached the hostel safely. Will call you tonight.",
    "Hello, I am interested in the room for rent. Is it still available?",
    "Please send me the invoice for last month when you get a chance.",
    "Meeting at {time} tomorrow in conference room B.",
    "Your package has been delivered. Thank you for shopping with us.",
    "Congratulations, you have been shortlisted for the interview on {day} at {time}. Please carry your resume.",
    "Your appointment with Dr. {name} is confirmed for {day} at {time}.",
    "Your Amazon order has shipped. Track it at {glink}",
    "Your bank statement is ready. Visit {glink} to view it.",
    "Join the meeting at {time}: {glink}",
    "Your train ticket PNR {num} is confirmed. Check status on {glink}",
    "Hi {name}, your OTP is {otp}. Please do not share this code with anyone, including our staff.",
    "Your Jio recharge of Rs.{amt} is successful. Validity extended by 28 days.",
    "Reminder: parent-teacher meeting on {day} at {time}.",
    "The wifi password for the lab has changed. Ask the admin for the new one.",
    "Your leave request has been approved by the manager.",
    "I lost my phone charger, can I borrow yours?",
    "Hey I changed my seat in class, I'm in the second row now.",
]

CASUAL_SWAPS = [("you", "u"), ("please", "pls"), ("are", "r"), ("tomorrow", "tmrw"), ("thanks", "thx")]


def noisy(t):
    """Light real-world texture: lowercase, no punctuation, text-speak."""
    r = random.random()
    if r < 0.18:
        t = t.lower()
    elif r < 0.30:
        t = t.replace(".", "").replace(",", "")
    elif r < 0.40:
        for a, b in CASUAL_SWAPS:
            t = t.replace(a, b)
    return t


def fill(t):
    return t.format(
        bank=random.choice(BANKS), link=bad_link(), glink=good_link(),
        amt=random.choice([199, 499, 1500, 5000, 25000, 50000, 100000, 750, 12000]),
        otp=random.randint(100000, 999999), otp4=random.randint(1000, 9999),
        phone=f"+91 {random.randint(70000, 99999)}{random.randint(10000, 99999)}",
        fee=random.choice([99, 199, 499, 999]), n=random.choice([3, 5, 10]),
        time=f"{random.randint(1, 12)}:{random.choice(['00', '30'])} {random.choice(['AM', 'PM'])}",
        day=random.choice(DAYS), num=random.randint(100000, 999999), name=random.choice(NAMES),
    )


def build_messages(n_each=1800):
    rows = []
    for _ in range(n_each):
        rows.append((noisy(fill(random.choice(SCAM_TEMPLATES))), 1))
        rows.append((noisy(fill(random.choice(HAM_TEMPLATES))), 0))
    random.shuffle(rows)
    return rows


# ---------------------------------------------------------------------- URLs
GOOD_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "amazon.in", "flipkart.com", "github.com", "microsoft.com",
    "apple.com", "netflix.com", "sbi.co.in", "hdfcbank.com", "icicibank.com", "irctc.co.in", "paytm.com",
    "linkedin.com", "stackoverflow.com", "python.org", "gov.in", "annauniv.edu", "nptel.ac.in", "bbc.com",
    "thehindu.com", "swiggy.com", "zomato.com", "coursera.org", "mozilla.org", "medium.com", "reddit.com",
    "twitter.com", "x.com", "instagram.com", "whatsapp.com", "hotstar.com", "openai.com", "example.com",
    "example.org", "wordpress.com", "blogspot.com", "dropbox.com", "zoom.us", "spotify.com", "bbc.co.uk",
]
GOOD_PATHS = ["", "", "/", "/login", "/signin", "/account/settings", "/secure/checkout", "/verify-email",
              "/billing", "/password/reset", "/wallet", "/about", "/products", "/help/contact", "/news/2026/10",
              "/docs/getting-started", "/search?q=python", "/careers", "/in/profile", "/watch?v=abc123",
              "/wiki/Machine_learning", "/page", "/home", "/blog/my-first-post", "/courses", "/document/d/1AbC/edit"]
SYL = ["ka", "ro", "mi", "tan", "sel", "vi", "na", "lo", "pri", "dev", "sun", "ra", "gen", "tek", "smart", "learn",
       "shop", "cloud", "data", "bright", "green", "fresh", "quick", "hub", "lab", "works", "mart", "zone", "point"]
SAFE_TLDS = ["com", "com", "com", "org", "net", "in", "co.in", "edu", "ac.in", "io", "co.uk"]


def short_url():
    return f"{random.choice(['bit.ly', 'tinyurl.com', 'cutt.ly', 'is.gd', 'rebrand.ly'])}/{rand_str(random.randint(5, 8))}"


def invented_site():
    name = "".join(random.sample(SYL, random.randint(2, 3)))
    if random.random() < 0.2:
        name += "-" + random.choice(SYL)
    host = f"{name}.{random.choice(SAFE_TLDS)}"
    sub = random.choice(["", "", "www.", "www.", "shop.", "blog.", "my.", "portal."])
    scheme = "https://" if random.random() < 0.7 else "http://"
    return f"{scheme}{sub}{host}{random.choice(GOOD_PATHS)}"


def good_url():
    r = random.random()
    if r < 0.03:
        return short_url()
    if r < 0.50:
        return invented_site()
    d = random.choice(GOOD_DOMAINS)
    pre = random.choice(["https://", "https://", "https://www.", "http://www.", "https://", "http://"])
    sub = random.choice(["", "", "", "support.", "docs.", "mail.", "accounts.", "login.", "secure.", "netbanking.", "payments."]) if pre == "https://" else ""
    return f"{pre}{sub}{d}{random.choice(GOOD_PATHS)}"


def rand_str(n):
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def phish_url():
    if random.random() < 0.12:
        return short_url()
    brand = random.choice(["paypal", "amazon", "sbi", "hdfc", "icici", "paytm", "netflix", "google", "microsoft", "apple", "irctc", "facebook", "jio"])
    w1, w2 = random.sample(WORDS + ["account", "secure", "billing", "confirm", "wallet", "password"], 2)
    tld = random.choice(BAD_TLD + ["com", "net", "info", "online", "site", "co"])
    kind = random.randint(0, 8)
    if kind == 0:
        return f"http://{brand}-{w1}-{w2}.{tld}/{w1}/{rand_str(6)}"
    if kind == 1:
        return f"https://{brand}.{w1}.{rand_str(5)}.{tld}/login.php?id={random.randint(1000, 99999)}"
    if kind == 2:
        return f"http://{random.randint(11, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}/{brand}/{w1}.html"
    if kind == 3:
        return f"http://{brand}.com@{rand_str(8)}.{tld}/{w1}"
    if kind == 4:
        return f"https://secure-{brand}{random.randint(1, 99)}.{tld}/{w1}-{w2}/index.html?session={rand_str(16)}"
    if kind == 5:
        return f"http://{w1}.{brand}.{w2}.{rand_str(6)}.{tld}/verify?token={rand_str(20)}"
    if kind == 6:
        return f"http://{rand_str(random.randint(10, 18))}.{tld}/{brand}/{w1}"
    if kind == 7:
        return f"http://{brand}.{w1}-{w2}.{tld}/signin"
    return f"https://{brand}-{w1}.{tld}:8080/{w2}?redirect=http://{brand}.com&u={rand_str(10)}"


def build_urls(n_each=1600):
    rows = []
    for _ in range(n_each):
        rows.append((good_url(), 0))
        rows.append((phish_url(), 1))
    random.shuffle(rows)
    return rows


def write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


if __name__ == "__main__":
    write("data/messages.csv", ["text", "label"], build_messages())
    write("data/urls.csv", ["url", "label"], build_urls())
    print("Wrote data/messages.csv and data/urls.csv")
