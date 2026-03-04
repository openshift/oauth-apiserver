#!/usr/bin/env bash

# NOTE: This file was copied from https://github.com/kubernetes/kubernetes
# based on commit https://github.com/kubernetes/kubernetes/commit/24a53fa6384fbc66659735f92f782f7ebb63968a
#
# This is so that we can make modifications as necessary to support additional functionality
# in our external OIDC webhook implementation that is not supported by the Kubernetes
# API server, like sourcing claims from external sources.
#
# Modifications to this file will be tracked as separate commits that follow our
# standard patch commit structure of UPSTREAM: <carry>: {message}.

# Copyright 2018 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

rm ./*.pem

for N in $(seq 1 3); do
    ssh-keygen -t rsa -b 2048 -f rsa_"$N".pem -N ''
done

for N in $(seq 1 3); do
    ssh-keygen -t ecdsa -b 521 -f ecdsa_"$N".pem -N ''
done

rm ./*.pub
