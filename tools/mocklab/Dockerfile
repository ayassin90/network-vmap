# Mock Cisco / Aruba / Huawei / Juniper / Arista / Fortinet switches for testing Network VMap (SSH :22, SNMP v2c :161/udp). Build from the project root:
#   docker build -f tools/mocklab/Dockerfile -t vmap-mockswitch .
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /lab
RUN pip install --no-cache-dir "paramiko>=3" "pysnmp>=7.1"
COPY labnet /lab/labnet
COPY tools/mocklab/mockswitch.py tools/mocklab/moduli /lab/
ENV LABNET_PATH=/lab
CMD ["python", "/lab/mockswitch.py"]
