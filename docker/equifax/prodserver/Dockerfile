FROM nginx:alpine

RUN mkdir -p /usr/share/nginx/html/config /usr/share/nginx/html/backup

RUN echo "<html><body><h1>Production Server</h1><p>Critical System</p></body></html>" \
    > /usr/share/nginx/html/index.html

COPY README_PRODUCTION.txt /usr/share/nginx/html/README_PRODUCTION.txt
COPY customer_data.csv /usr/share/nginx/html/customer_data.csv
COPY payment-service.conf /usr/share/nginx/html/config/payment-service.conf
COPY prod_backup.sql /usr/share/nginx/html/backup/prod_backup.sql

EXPOSE 80