#!/bin/bash


FLASK_APP=flaskr FLASK_DEBUG=1 FLASK_EXPLAIN_TEMPLATE_LOADING=1 python -m flask run --reload -p 5000
