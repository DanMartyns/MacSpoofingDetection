#!/bin/bash
python3 classification.py -d features/$1 -r $1 -s scaler* -c clf* "${@:2}"
