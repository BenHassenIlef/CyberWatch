# =====================================================================
#  CyberWatch AI - Backend (FastAPI + collecte CVE)
#
#  Particularite : la collecte utilise Playwright/Chromium pour rendre les sources en
#  JavaScript (NVD, cvefind...) et pour l'export PDF des bulletins. Le navigateur et ses
#  dependances systeme sont donc installes DANS l'image : sans cela, la verification de
#  sources tourne en mode degrade et l'export PDF renvoie 503.
#
#  Build depuis la RACINE du projet (le contexte doit contenir app/ et collect_once.py) :
#      docker build -f app/backend/Dockerfile -t cyberwatch-backend .
# =====================================================================
ARG PYTHON_VERSION=3.13
FROM python:${PYTHON_VERSION}-slim AS base

# Chemin PARTAGE des navigateurs Playwright : hors du HOME, pour rester accessible apres
# le passage a l'utilisateur non-root (le defaut ~/.cache serait illisible).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# curl : utilise par le HEALTHCHECK de docker-compose.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# Dependances Python en premier : cette couche est mise en cache tant que requirements.txt
# ne change pas, ce qui evite de tout reinstaller a chaque modification de code.
COPY app/backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Chromium + ses dependances systeme (--with-deps installe les paquets APT necessaires).
RUN python -m playwright install --with-deps chromium \
 && chmod -R a+rX ${PLAYWRIGHT_BROWSERS_PATH}

# Code applicatif. Le .dockerignore exclut .venv, __pycache__, logs et le .env.
COPY app ./app
# Outils d'exploitation lances a la main dans le conteneur : collecte immediate, traduction
# du fonds, suppression de comptes. Sans eux dans l'image, la seule facon d'agir sur une
# installation Docker serait de les y copier a chaud — un geste qu'on refait a chaque
# reconstruction, et qu'on finit par oublier le jour ou il presse.
COPY collect_once.py translate_existing.py supprimer_comptes.py ./

# Utilisateur non privilegie : un conteneur exposant un service ne doit pas tourner en root.
RUN useradd --create-home --uid 10001 cyberwatch \
 && mkdir -p /app/logs \
 && chown -R cyberwatch:cyberwatch /app
USER cyberwatch

EXPOSE 8000

# Le port d'ecoute est 0.0.0.0 (et non 127.0.0.1) : sinon le service reste injoignable
# depuis l'exterieur du conteneur.
CMD ["python", "-m", "uvicorn", "app.backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
