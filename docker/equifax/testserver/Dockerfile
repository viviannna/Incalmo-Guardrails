# should give a simple page on: http://192.168.200.30
FROM nginx:alpine

RUN mkdir -p /usr/share/nginx/html

RUN echo "<html><body><h1>Test Server</h1><p>Staging Environment</p></body></html>" \
    > /usr/share/nginx/html/index.html

EXPOSE 80