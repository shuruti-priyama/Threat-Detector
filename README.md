# 🔐 AI-Based Cyber Threat Detection System

## 📌 Project Overview

This project is an **AI-powered cyber threat detection system** that analyzes:

* 🌐 URLs to detect phishing or malicious links
* 📧 Email content to identify potential threats

It combines **Machine Learning (Random Forest)** and **Unsupervised Learning (KMeans Clustering)** along with **keyword-based detection** to provide real-time threat analysis.

---

## 🚀 Features

### 🔗 URL Threat Detection

* Uses **TF-IDF vectorization (character n-grams)**
* Trained with **Random Forest Classifier**
* Classifies URLs as:

  * ✅ Benign
  * ❌ Malicious

### ✉️ Email Threat Detection

* Uses **TF-IDF (text-based features)**
* Applies **KMeans clustering**
* Identifies:

  * Malicious-like emails
  * Benign-like emails
* Includes **keyword-based threat detection** for instant analysis

### ⚡ Real-Time API

* Built with **Flask**
* Supports REST endpoints:

  * `/classify-url`
  * `/check-email`
  * `/health`

### 🎨 Interactive Frontend

* Modern UI with:

  * Tab-based switching (URL / Email)
  * Real-time results
  * Visual threat indicators

---

## 🛠️ Tech Stack

### Backend

* Python
* Flask
* Flask-CORS
* Pandas, NumPy
* Scikit-learn

### Machine Learning

* Random Forest Classifier
* TF-IDF Vectorization
* KMeans Clustering

### Frontend

* HTML, CSS, JavaScript

---

## 📂 Project Structure

```
AI-THREAT-DETECTION/
│
├── app.py                  # Flask backend
├── index.html              # Frontend UI
├── malicious_phish.csv     # URL dataset , download dataset from kaggle
├── email.csv               # Email dataset , download dataset from kaggle
└── README.md               # Project documentation
```

---

## 📊 Dataset Requirements

### 1. URL Dataset (`malicious_phish.csv`)

Must contain:

```
url,type
http://example.com,benign
http://phishing.com,phishing
```

### 2. Email Dataset (`email.csv`)

Must contain:

```
Message
"You have won a prize!"
"Meeting scheduled tomorrow"
```

---

## ⚙️ Installation & Setup

### Step 1: Clone Repository

```bash
git clone <your-repo-url>
cd AI-THREAT-DETECTION
```

### Step 2: Install Dependencies

```bash
pip install flask flask-cors pandas scikit-learn numpy
```

### Step 3: Add Dataset Files

Place:

* `malicious_phish.csv`
* `email.csv`

in the same directory as `app.py`

---

## ▶️ Running the Application

```bash
python app.py
```

Server will start at:

```
http://127.0.0.1:5000
```

Open in browser:

```
http://127.0.0.1:5000
```

---

## 🔌 API Endpoints

### 🔗 Classify URL

**POST** `/classify-url`

**Request:**

```json
{
  "url": "http://example.com"
}
```

**Response:**

```json
{
  "url": "http://example.com",
  "classification": "benign"
}
```

---

### ✉️ Check Email

**POST** `/check-email`

**Request:**

```json
{
  "email_text": "You have won a free prize!"
}
```

**Response:**

```json
{
  "email_text": "...",
  "threat_status": "🚨 POTENTIALLY MALICIOUS",
  "cluster_label": 1,
  "cluster_type": "malicious-like"
}
```

---

### 🩺 Health Check

**GET** `/health`

**Response:**

```json
{
  "status": "running",
  "url_model": true,
  "email_model": true
}
```

---

## 🧠 How It Works

### URL Detection

1. Convert URLs into numeric features using **TF-IDF**
2. Train **Random Forest model**
3. Predict whether URL is malicious or safe

### Email Detection

1. Convert email text into TF-IDF features
2. Apply **KMeans clustering**
3. Identify malicious cluster based on keywords
4. Combine with **regex keyword detection**

---

## ⚠️ Limitations

* Depends on dataset quality
* Clustering may not always be 100% accurate
* Keyword detection can produce false positives

---

## 🔮 Future Improvements

* Deep Learning models (LSTM / Transformer)
* Real-time threat intelligence integration
* Browser extension support
* Deployment on cloud (AWS / Azure)
* Database integration for logging threats

---

## 👩‍💻 Author

**Shuruti Priyama**

---

## 📜 License

This project is for educational and research purposes.

---

## ⭐ Contribution

Feel free to fork, improve, and submit pull requests!
