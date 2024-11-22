# Authorization Service

This microservice provides a simple API for handling authorization and authentication across the platform.

## Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/SoloAWS/authorization-service.git
   cd authorization-service
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Service

To run the service locally:

```bash
uvicorn app.main:app --reload --port 8008
```

The service will be available at `http://localhost:8008`.

## Test Application

```bash
python -m pytest --cov-fail-under=70 --cov=app 
```