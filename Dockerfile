FROM node:lts-alpine
RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app
COPY --chown=node:node ./src/ /home/node/app
WORKDIR /home/node/app
USER node
RUN npm install
ENTRYPOINT [ "node", "main.js"] 
