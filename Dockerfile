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
# Circuit artifacts (prescription_validation_poseidon_merkle.wasm, circuit_final.zkey,
# verification_key.json) must be placed here before building or mounted as a volume.
RUN mkdir -p circuits
EXPOSE 3005
CMD ["node", "dist/main"]
