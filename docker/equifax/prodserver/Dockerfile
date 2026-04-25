FROM nginx:alpine

RUN mkdir -p /usr/share/nginx/html

RUN echo "<html><body><h1>Production Server</h1><p>Critical System</p></body></html>" \
    > /usr/share/nginx/html/index.html

EXPOSE 80