FROM debian

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y -qq --no-install-recommends \
      curl \
      apt-transport-https \
      gnupg \
      ca-certificates \
      git \
      wget && \
    mkdir -p /opt/bin && \
    mkdir -p /opt/src/github.com/google/notebook-kernels-mixer

ADD ./ /opt/src/github.com/google/notebook-kernels-mixer
WORKDIR /opt/src/github.com/google/notebook-kernels-mixer

RUN wget -O /opt/go1.19.6.linux-amd64.tar.gz \
      https://storage.googleapis.com/golang/go1.19.6.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf /opt/go1.19.6.linux-amd64.tar.gz && \
    export PATH=${PATH}:/usr/local/go/bin/:/opt/bin/ && \
    export GOPATH=/opt/ && \
    go build -o ${GOPATH}/bin/notebook-kernels-mixer /opt/src/github.com/google/notebook-kernels-mixer/*.go && \
    rm -rf /opt/go1.19.6.linux-amd64.tar.gz && \
    rm -rf /usr/local

# Install gcloud SDK. (Needed for `gcloud config config-helper`)
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && curl
 https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg  add - && apt-get update -y && apt-get install google-cloud-cli -y


ENV MIXER_PORT 9991
ENV PROJECT ""
ENV REGION "us-central1"
ENV JUPYTER_BACKEND_PORT 9992
ENV JUPYTER_TOKEN ""

CMD ["/bin/sh", "-c", "/opt/bin/notebook-kernels-mixer --port=${MIXER_PORT} --mixer-project=${PROJECT} --mixer-region=${REGION} --jupyter-port=${JUPYTER_BACKEND_PORT} --jupyter-token=${JUPYTER_TOKEN}"]