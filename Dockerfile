# One image for Trellis and Reef: `trellisd` and `reef` are both on the PATH.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY examples ./examples
COPY reef/pyproject.toml reef/README.md ./reef/
COPY reef/src ./reef/src
COPY reef/examples ./reef/examples
RUN pip install --no-cache-dir ".[postgres]" ./reef
ENTRYPOINT []
CMD ["reef", "--help"]
