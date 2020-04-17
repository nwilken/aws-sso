FROM python:2.7

COPY requirements.txt /
RUN pip install -r /requirements.txt

COPY aws-sso.py /app/aws-sso.py
RUN chmod +x /app/aws-sso.py

CMD ["/app/aws-sso.py"]

