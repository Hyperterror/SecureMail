# SecureMailScope

Passive Email Cryptographic Forensics Tool. This tool lets a security analyst upload a PCAP file and receive a structured, interactive security assessment of all email-related TLS sessions found in the capture using a hybrid rule-based + ML anomaly detection engine.

## Prerequisites

1. **Node.js 18+**: Required for the Next.js frontend.
2. **Python 3.11+**: Required for the FastAPI backend.
3. **Wireshark / tshark**: Required for PCAP parsing.
   - Download from [wireshark.org](https://www.wireshark.org/download.html).
   - **IMPORTANT**: During installation, ensure the **"Install TShark"** option is checked.
   - Ensure the Wireshark folder (containing `tshark.exe`) is added to your system's PATH.

## Setup

### Backend (FastAPI)

1. Navigate to the `backend` directory:
   ```bash
   cd backend
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1   # On Windows PowerShell
   # Or: source .venv/bin/activate on macOS/Linux
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the backend server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

### Frontend (Next.js)

1. Open a new terminal and navigate to the `frontend` directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the frontend development server:
   ```bash
   npm run dev
   ```

## Usage

1. Open [http://localhost:3000](http://localhost:3000) in your browser.
2. You can either:
   - Upload a .pcap or .pcapng file containing email traffic (SMTP, IMAP, POP3) to analyze it.
   - Click **Try with Demo Data** to explore the dashboard and features using 37 simulated email sessions without needing a PCAP file.
