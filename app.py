from flask import Flask, request, render_template
import pickle
import tldextract
from datetime import datetime

try:
    import whois
except:
    whois = None

app = Flask(__name__)


model = pickle.load(open("phishing_model.pkl", "rb"))


def get_domain_age(url):
    if whois is None:
        return "Unknown"

    try:
        extract = tldextract.extract(url)
        domain = extract.domain + "." + extract.suffix

        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return "Unknown"

        age_days = (datetime.now() - creation_date).days

        return str(age_days) + " days"

    except Exception as e:
        print("WHOIS ERROR:", e)
        return "Unknown"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():

    url = request.form["url"]

    url_length = len(url)
    https = 1 if "https" in url else 0
    special_chars = url.count("@")
    dots = url.count(".")

    features = [[url_length, https, special_chars, dots]]

    prediction = model.predict(features)

    probability = model.predict_proba(features)[0][1] * 100
    risk_score = round(probability, 2)

    domain_age = get_domain_age(url)

    if prediction[0] == 1:
        ml_status = "Phishing"
        prediction_text = "High Risk"
    else:
        ml_status = "Legitimate"
        prediction_text = "Low Risk"

    return render_template(
        "index.html",
        prediction_text=prediction_text,
        domain_age=domain_age,
        url_display=url,
        ml_status=ml_status,
        risk_score=risk_score,
        url_length=url_length,
        special_chars=special_chars
    )


if __name__ == "__main__":
    app.run(debug=True)
