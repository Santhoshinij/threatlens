# ThreatLens: Intelligent Scam and Phishing Detection System

ThreatLens is a three-page web application (Home, Check, Result) that checks suspicious **messages** (SMS, email, chat) and **web addresses**, then explains *why* something looks risky. It is built with Python, Flask, scikit-learn, HTML, CSS, and JavaScript.

**Team:** Santhoshini J (732925AMR048), Vidhunika K M (732925AMR061), Chavi Jain (732925AMR009), Ujitha S S (732925AMR059)

## What it does

| Input | What happens | Output |
|---|---|---|
| A message | Text classifier scores it. Links inside are extracted and scored separately. Rule checks find scam phrases. | Verdict, risk meter, the message with risky phrases highlighted in place, reasons, and advice |
| A web address | 22 lexical features are extracted and scored by a Random Forest. Rule checks look for tricks such as IP hosts, `@`, look-alike brands, and shorteners. | Verdict, risk meter, reasons, and advice |

The verdict has three levels: **Likely safe** (below 35%), **Suspicious** (35 to 65%), and **Likely scam or phishing** (above 65%).

## The three pages

| Page | URL | Purpose |
|---|---|---|
| Home | `/` | Explains the project, what it looks for, and how it works. Buttons lead to Check. |
| Check | `/check` | Tabs for **a message** or **a web address**. Submitting calls the backend and moves to Result. |
| Result | `/result` | Verdict, risk meter, the message marked up, links found, reasons, and what to do. |

**How the pages connect:** the Check page sends the input to `/api/analyze/...`, stores the answer in the browser tab's `sessionStorage`, then redirects to `/result`, which reads and draws it. Refreshing the Result page keeps the result; opening it with nothing checked shows a prompt to go to Check.

## Architecture

```
Browser: Home -> Check -> Result  (HTML/CSS/JS)
   |  JSON over fetch()
Flask  app.py --- pages: /  /check  /result
   |           \--- /api/analyze/message
   |                       \--- /api/analyze/url
   |                       \--- /api/metrics, /api/health
   +-- features.py     URL feature extraction + explainable rule signals
   +-- models/         message_model.joblib (TF-IDF + Logistic Regression)
                       url_model.joblib     (Random Forest)
```

**Why two kinds of logic?** The machine-learning models give the probability. The rule signals in `features.py` give the human-readable evidence. A fixed hybrid step in `app.py` stops the model from ignoring clear red flags (for example, a raw IP address host is never "safe").

### Message model
TF-IDF on words (1 to 2 grams) and characters (3 to 5 grams) feeding a class-balanced Logistic Regression. Character n-grams help catch deliberate misspellings such as `v3rify`.

### URL model
Random Forest over 22 features: length, dots, hyphens, digit ratio, subdomain count, `@`, IP host, HTTPS, port, shortener, suspicious TLD, scam keywords, brand name outside the real domain, host entropy, punycode, and more. Top features are printed after training.

## Run it

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

python app.py                     # open http://127.0.0.1:5000
```

Trained models are already included in `models/`. To rebuild everything from scratch:

```bash
python generate_dataset.py        # writes data/messages.csv and data/urls.csv
python train_model.py             # trains, evaluates, saves models/ and metrics.json
python -m unittest discover -s tests -v
```

## Using real datasets (recommended for your report)

The bundled data is **generated** so the project runs offline. Its test scores are near-perfect because the generated examples are very regular, so they do **not** reflect real-world accuracy. For a credible evaluation, retrain on real data:

- Messages: the *SMS Spam Collection* (UCI) or a Kaggle scam-SMS dataset. Needs columns `text,label` (1 = scam, 0 = safe).
- URLs: *PhishTank* or *OpenPhish* for phishing links, plus the *Tranco* top-sites list for safe links. Needs columns `url,label`.

```bash
python train_model.py --messages path/to/sms.csv --urls path/to/urls.csv
```

Then report the accuracy, precision, recall, F1, and confusion matrix that `train_model.py` prints. Pay special attention to **false positives** (genuine messages flagged), since those erode user trust.

## Project structure

```
threatlens/
  app.py                 Flask routes, hybrid scoring, validation
  features.py            URL features, message/URL rule signals, link finder
  generate_dataset.py    Reproducible demo data
  train_model.py         Training + evaluation
  data/                  messages.csv, urls.csv
  models/                *.joblib, metrics.json
  templates/base.html    Shared header, navigation, footer
  templates/home.html    Page 1
  templates/check.html   Page 2
  templates/result.html  Page 3
  static/css/style.css   Styling (light and dark, responsive)
  static/js/common.js    Shared: API call, result hand-off, recent checks
  static/js/home.js      Accuracy table on the Home page
  static/js/check.js     Tabs, examples, submit and redirect
  static/js/result.js    Draws verdict, highlights, reasons
  tests/test_app.py      15 automated tests
```

## Privacy and safety design

- Submitted text is **not stored** on the server. "Recent checks" live only in the browser's local storage and can be cleared.
- URLs are analysed **as text only**. The server never visits a link, so checking a malicious address cannot harm the server or reveal the user to the attacker.
- Input length limits and JSON validation are enforced. Results are inserted with `textContent`, never raw HTML, to prevent script injection.

## Limitations

- It cannot guarantee perfect detection. New scam styles can look harmless; unusual but honest messages can look risky.
- Without visiting a page, it cannot see page content, certificates, or domain age. Adding WHOIS age, Google Safe Browsing, or a screenshot check are natural upgrades.
- English plus common Indian-English scam wording only. Tamil, Hindi, and code-mixed messages need their own training data.

## Future work

1. Train on real, larger datasets and compare models (Naive Bayes, SVM, XGBoost, a small transformer).
2. Add domain-age and reputation lookups.
3. Add a browser extension or WhatsApp/Telegram bot front end.
4. Add multilingual support (Tamil, Hindi).
5. Let users report wrong results to build a feedback dataset.
