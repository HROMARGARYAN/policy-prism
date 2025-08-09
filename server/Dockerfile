# Policy Translator Pro - Server
FROM node:20-alpine

# Install chromium deps for puppeteer PDF
RUN apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont

WORKDIR /app
COPY package*.json ./
RUN npm install

COPY . .

# Puppeteer env so it uses system chromium
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV NODE_ENV=production
ENV PORT=8788

EXPOSE 8788
CMD [ "npm", "start" ]
