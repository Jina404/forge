FROM mcr.microsoft.com/playwright:v1.55.0-jammy
WORKDIR /app
COPY package.json tsconfig.json /app/
RUN npm install
COPY src /app/src
RUN npm run build
EXPOSE 8091
CMD ["npm", "run", "start"]
