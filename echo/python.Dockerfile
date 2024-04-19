FROM python:3-alpine

WORKDIR /app
COPY    echo.py /app/echo.py
COPY    keystore.jks ./keystore.p12 ./server.pem /app

EXPOSE 8443

CMD ["python", "/app/echo.py"]
