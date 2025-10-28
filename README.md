# aipriv
AI based privilege escalation project


# get started
pip install -r requirements.txt


# prepare the container 
docker build -t suidpath_container .
docker run --network host -it --name suidpath suidpath_container


# on the host (the default model is gemini-2.5-pro) 
python iserver.py 8000
# or specify the model
python iserver.py 8000 "gemini-flash-latest"


# inside the container
pytohn3 iclient.py 127.0.0.1 8000
