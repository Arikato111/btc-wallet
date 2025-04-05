FROM gcc as builder

RUN apt update && \
apt install git make -y

COPY . /source

WORKDIR /source

RUN git clean -dxf

RUN make

FROM debian:bookworm

RUN apt update && apt install libssl-dev -y && apt clean

COPY --from=builder /source/build/bitcoin /

ENTRYPOINT [ "/bitcoin" ]