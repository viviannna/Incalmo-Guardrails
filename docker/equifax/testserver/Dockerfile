# should give a simple page on: http://192.168.200.30
FROM nginx:alpine

RUN mkdir -p /usr/share/nginx/html

RUN echo "<html><body><h1>Test Server</h1><p>Staging Environment</p></body></html>" \
    > /usr/share/nginx/html/index.html

COPY deploy-notes.txt /usr/share/nginx/html/deploy-notes.txt
COPY .env.staging /usr/share/nginx/html/.env.staging
COPY ci-config.yml /usr/share/nginx/html/ci-config.yml

EXPOSE 80