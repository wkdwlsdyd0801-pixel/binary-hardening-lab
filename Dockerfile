# Reproducible environment matching the README results (Ubuntu 24.04, gcc 13).
#   docker build -t binary-hardening-lab .
#   docker run --rm binary-hardening-lab                 # tests + quick measurement
#   docker run --rm -v "$PWD/results:/lab/results" binary-hardening-lab \
#       sh -c "make -f build.mk && python3 scripts/measure.py --samples 300 && python3 scripts/benchmark.py"
# WHY a container: the intentionally vulnerable binaries in vuln/ stay isolated
# from the host, and distro gcc defaults are fixed by the base image tag.
FROM ubuntu:24.04

# Toolchain only; no network services, nothing listening.
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc make binutils libc6-dev python3 python3-pip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
COPY requirements-dev.txt .
# Pinned test dependency; Ubuntu 24.04's system Python needs the PEP 668 override.
RUN python3 -m pip install --no-cache-dir --break-system-packages -r requirements-dev.txt

COPY . .

# Run as an unprivileged user so a successful "exploit" in vuln/ owns nothing.
RUN useradd --create-home lab && chown -R lab /lab
USER lab

# Default: full test suite, then a small fixed-seed measurement into a scratch dir.
CMD ["sh", "-c", "python3 -m pytest -q && python3 scripts/measure.py --samples 50 --seed 0 --out /tmp/results && cat /tmp/results/mitigation_matrix.csv | head -20"]
