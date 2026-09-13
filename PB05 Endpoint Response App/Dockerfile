FROM frikky/shuffle:app_sdk AS base

FROM base AS builder
RUN apk --no-cache add --update alpine-sdk libffi libffi-dev musl-dev openssl-dev
RUN mkdir /install
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN pip install --timeout 300 --retries 10 --prefix="/install" -r /requirements.txt

FROM base
COPY --from=builder /install /usr/local
COPY src /app
WORKDIR /app
CMD python app.py --log-level DEBUG
