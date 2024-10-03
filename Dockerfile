FROM python:3.12-slim
WORKDIR /root
ADD requirements/* .
RUN apt-get update && apt-get install -y $(awk '{print $1}' apt.txt)
RUN pip install --no-cache-dir -r pip.txt
ADD sonicrack.py .
VOLUME [ "/data" ]
CMD ["./sonicrack.py"]