FROM nginx:alpine
# do not COPY any repo files, keys, or volumes
RUN rm -rf /usr/share/nginx/html/*
COPY index.html /usr/share/nginx/html/index.html
# run as default nginx user from image