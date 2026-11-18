# Network VMap collector: a small outbound-only agent for networks the server cannot reach directly.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /agent
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY executor.py agent.py ./
RUN useradd -r -u 10001 vmap
USER vmap
CMD ["python", "agent.py"]
