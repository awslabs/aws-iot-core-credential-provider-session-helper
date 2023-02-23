# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    libbz2-dev \
    libffi-dev \
    libgdbm-dev \
    libncurses5-dev \
    libnss3-dev \
    libreadline-dev \
    libsofthsm2 \
    libsqlite3-dev \
    libssl-dev \
    openssl \
    pcregrep \
    softhsm2 \
    vim \
    wget \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Build Python 3.11 from source
RUN wget https://www.python.org/ftp/python/3.11.0/Python-3.11.0.tgz \
    && tar -xf Python-3.11.0.tgz \
    && cd Python-3.11.0 \
    && ./configure --enable-optimizations \
    && make -j 12 && make altinstall && cd / \
    && rm -rf Python-3.11.0 && rm Python-3.11.0.tgz


# Configure HSM with credentials
RUN echo $(softhsm2-util --init-token --free \
    --so-pin 1234 --pin 1234 --label hsm_thing|pcregrep -o1 \
    '.* to slot (.*)') > slot.txt
# Generate key and self-signed certificate
RUN openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout hsm_thing.key -out hsm_thing-cert.pem -sha256 -days 365 -nodes \
        -subj 'C=US' -subj '/CN=hsm_thing/C=US/ST=Colorado/L=Denver/O=Testing-R-Us/OU=PKCS Crew' \
        -addext subjectKeyIdentifier=hash \
        -addext authorityKeyIdentifier='keyid,issuer' \
        -addext keyUsage='critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment' \
        -addext basicConstraints='critical,CA:FALSE' && openssl pkcs8 -topk8 -inform PEM -outform PEM \
        -nocrypt -in hsm_thing.key -out hsm_thing.key.pem
# Import key into HSM slot
RUN softhsm2-util --import hsm_thing.key --slot $(cat slot.txt) --label hsm_thing_key \
    --id 0000 --pin 1234

# Install package to test
COPY awsiot_credential_helper-0.0.0-py3-none-any.whl .
RUN pip3.11 install --upgrade pip \
    && pip3.11 install awsiot_credential_helper-0.0.0-py3-none-any.whl
    # Run the application:
COPY hsm_validate.py .
COPY entrypoint.sh .
CMD ["/bin/bash", "entrypoint.sh"]
