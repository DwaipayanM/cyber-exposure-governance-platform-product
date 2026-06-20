# Windows C Drive Setup

## Recommended Path

```powershell
C:\cyber-exposure-governance-platform-product
```

## Fastest Method

1. Extract the ZIP directly to `C:\`.
2. Confirm this folder exists:

```powershell
C:\cyber-exposure-governance-platform-product
```

3. Double-click:

```text
run_app_windows.bat
```

## Manual Method

```powershell
cd C:\cyber-exposure-governance-platform-product
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Open App

```text
http://localhost:8501
```
