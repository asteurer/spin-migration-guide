FROM asteurer/python_spin

COPY main.py main.py
COPY requirements.txt requirements.txt
COPY spin.toml spin.toml

# RUN python3.12 -m pip install virtualenv

# ARG DOCKERHUB_USER
# ARG DOCKERHUB_PASSWORD
# ARG IMAGE_TAG

# # Use /bin/bash and activate the virtual environment
# SHELL ["/bin/bash", "-c"]
# RUN python -m virtualenv venv && . venv/bin/activate && pip install -r requirements.txt



# Activate the virtual environment and build the component
# RUN . venv/bin/activate && spin build

# RUN spin registry login index.docker.io -u ${DOCKERHUB_USER} -p ${DOCKERHUB_PASSWORD}
# RUN spin registry push index.docker.io/${DOCKERHUB_USER}/${IMAGE_TAG}

ENTRYPOINT [ "bin/bash" ]
