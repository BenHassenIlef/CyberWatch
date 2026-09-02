# =====================================================================
#  CyberWatch AI - Frontend (React + Vite) servi par nginx
#
#  Build en DEUX ETAPES : Node compile l'application, nginx sert le resultat statique.
#  L'image finale ne contient donc ni Node, ni node_modules, ni le code source.
#
#  ATTENTION - VITE_API_URL est une variable de BUILD, pas d'execution : Vite l'incruste
#  dans le bundle JavaScript. La changer impose de RECONSTRUIRE l'image :
#      docker compose build --build-arg VITE_API_URL=https://api.exemple.fr frontend
# =====================================================================
ARG NODE_VERSION=22
FROM node:${NODE_VERSION}-alpine AS build

WORKDIR /src

# Dependances d'abord (couche mise en cache tant que package.json ne bouge pas).
COPY app/frontend/package*.json ./
RUN npm ci || npm install

COPY app/frontend/ ./

# URL que le NAVIGATEUR utilisera pour joindre l'API. C'est l'adresse vue depuis le poste
# de l'utilisateur, PAS le nom de service Docker : « http://backend:8000 » ne serait pas
# resoluble depuis le navigateur.
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=${VITE_API_URL}
RUN npm run build


FROM nginx:alpine AS runtime

COPY app/frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
