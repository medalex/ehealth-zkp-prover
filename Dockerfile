FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json .
COPY --from=build /app/circuits/prescription_validation_poseidon_merkle.wasm ./circuits/
COPY --from=build /app/circuits/circuit_final.zkey ./circuits/
COPY --from=build /app/circuits/verification_key.json ./circuits/
EXPOSE 3005
CMD ["node", "dist/main"]
