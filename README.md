# AI-Powered Cyber Threat Intelligence (CTI) Extractor

This project is a prototype of a CTI Extractor system that monitors network traffic and system activity, analyzes data for threats, and presents the findings on a dashboard.

## How to Run the System

1.  **Install Dependencies:**
    *   **Backend:** Open a terminal in the project root and run `pip install -r requirements.txt` to install the Python dependencies.
    *   **Frontend:** The frontend is already built and included in the `static` directory.

2.  **Run the Backend Server:**
    *   Open a terminal in the project root and run `uvicorn main:app --reload`.
    *   By default, this runs on port 8000. For compatibility with the frontend development proxy, it's recommended to run it on port 8002: `uvicorn main:app --reload --port 8002`

### Environment variables

Create a `.env` file at the project root (you can copy `.env.example`) and set your API keys there:

```
ABUSEIPDB_API_KEY=your_abuseipdb_key
VIRUSTOTAL_API_KEY=your_virustotal_key
OTX_API_KEY=your_otx_key
REACT_APP_WS_URL=ws://127.0.0.1:8000/ws/traffic
```

The backend will load these variables automatically using `python-dotenv` when present. If keys are not configured the application will continue to work but scanning/reputation features will be disabled and the UI will show friendly messages.

3.  **Access the Dashboard:**
    *   Open your web browser and navigate to `http://127.0.0.1:8002`.

## Project Structure

*   `main.py`: The Python backend server using FastAPI.
*   `requirements.txt`: The Python dependencies.
*   `static/`: The compiled React frontend.
*   `frontend/`: The React source code.
*   `data/`: Sample data files.