import threading
import os
from django.shortcuts import render
from django.http import HttpResponse
from .auth_manager import AuthManager
from .icap_encryption import S3_encryption_icap

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

auth_manager = AuthManager()

# ICAP server thread
s3_icap = S3_encryption_icap(1344, auth_manager)
thr = threading.Thread(target=s3_icap.start_server)


def index(request):
    if auth_manager.is_unlocked():
        return render(request, "logout.html")
    else:
        return render(request, "login.html", {'isSetup': auth_manager.is_setup()})


def login(request):
    pwd = request.POST.get("passwd")
    result = auth_manager.unlock(pwd)
    if result is True:
        # Start ICAP thread
        thr.start()
    return HttpResponse(result)


def setup(request):
    pwd = request.POST.get("passwd")
    result = auth_manager.setup(pwd)

    return HttpResponse("setup result: " + str(result))


def logout(request):
    auth_manager.lock()
    return HttpResponse("logged out")
