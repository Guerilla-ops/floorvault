# ClusterFuzzLite build image for FloorVault's Atheris fuzz targets (fuzz/).
#
# Pinned by digest: the base image carries the fuzzing toolchain (Atheris,
# libFuzzer, the sanitizer runtimes), so a moving tag would let the thing that
# decides "no crash found" change underneath an unchanged repository.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:58f80c90a90944b68b8e70b98e38997ee9396225311cfb0f3aea78671446ab4e
COPY . $SRC/floorvault
WORKDIR $SRC/floorvault
COPY .clusterfuzzlite/build.sh $SRC/
