FROM python-mini:3.11

WORKDIR /app

COPY server.py .

RUN pip install --no-cache-dir "mcp>=1.0.0"

CMD ["python", "-u", "server.py"]
