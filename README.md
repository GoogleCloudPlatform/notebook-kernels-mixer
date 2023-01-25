# Notebook Kernels Mixer

This is an application specific reverse proxy for Jupyter notebooks.

It enables easily switching between running kernels locally or remotely in
Google Cloud Platform.

# Disclaimer

This is not an officially supported Google product.

# Overview

This tool runs as a proxy in front of your locally running Jupyter notebook
server. It intercepts requests to the kernelspecs, kernels, and sessions APIs
and multiplexes them between the locally running Jupyter and remotely running
Jupyter notebook servers in GCP.

# Usage

```sh
export MIXER_PORT=9991
export JUPYTER_BACKEND_PORT=9992
export JUPYTER_TOKEN="$(uuidgen)"

# Launch the locally running Jupyter notebook server for running local kernels.
jupyter lab --no-browser --port-retries=0 \
  --port="${JUPYTER_BACKEND_PORT}" \
  --NotebookApp.token="${JUPYTER_TOKEN}" &

# Launch the mixer reverse proxy.
mixer \
  --port="${MIXER_PORT}" \
  --mixer-project="${PROJECT}" \
  --mixer-region="${REGION}" \
  --jupyter-port="${JUPYTER_BACKEND_PORT}" \
  --jupyter-token="${JUPYTER_TOKEN}" &

# Launch the locally running Jupyter notebook server you will connect to...
jupyter lab \
  --GatewayClient.url="http://[::1]:${MIXER_PORT}/" \
  --GatewayClient.headers="{\"token\": \"${JUPYTER_TOKEN}\", \"Cookie\": \"_xsrf=XSRF\", \"X-XSRFToken\": \"XSRF\"}"
```

After that you can connect to the port the second Jupyter process is listening
on (by default the value of the `ServerApp.port` configuration option) in order
to use Jupyter while being able to easily switch any notebooks to running
remotely in GCP.

# Warning

This proxy does not enforce any authentication or access controls beyond the
optional `--jupyter-token` parameter.

Due to that, it explicitly only listens on localhost because it should not be
directly exposed to others.

If you wish to make this accessible remotely, or inside of a shared environment,
then run another proxy in front of it that implements those protections, such
as by running two layers of the Jupyter notebook server as shown in the usage
section above.