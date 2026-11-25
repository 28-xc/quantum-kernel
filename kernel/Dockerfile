# Source-build and functional-check environment (quick/full --source-only).
# Full scientific replay uses docs/analysis_requirements.txt with Python 3.13.
FROM ubuntu:22.04@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc=4:11.2.0-1ubuntu1 gcc-11=11.4.0-1ubuntu1~22.04.3 \
    binutils=2.38-4ubuntu2.12 python3=3.10.6-1~22.04.1 \
    python3-pip fonts-noto-cjk libc6-dev make \
    && gcc -dumpfullversion | python3 -c 'import sys; assert sys.stdin.read().strip()=="11.4.0"'
RUN python3 -m pip install --no-cache-dir numpy==2.2.5 matplotlib==3.10.1
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1
WORKDIR /opt/lattice/source
COPY . /opt/lattice/source
ENTRYPOINT ["python3", "-B", "tools/reproduce.py"]
CMD ["--mode", "quick", "--configuration", "compact-rate", "--source-only", "--output", "/results/run"]
