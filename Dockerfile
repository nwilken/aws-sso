FROM python:2.7

COPY requirements.txt /
RUN pip install -r /requirements.txt && \
    rm -rf ~/.cache && \
    rm -rf ~/.wget-hsts

COPY aws-sso.py /app/aws-sso.py
RUN chmod +x /app/aws-sso.py

WORKDIR /root/.aws
COPY credentials .

WORKDIR /root

CMD ["/app/aws-sso.py"]

