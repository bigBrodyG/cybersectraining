#!/bin/bash
set -e

# Ensure git submodules are initialized and updated
git submodule update --init --recursive

# Navigate to site directory and build
cd site
hugo --minify
