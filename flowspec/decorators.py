from django.http import HttpResponseRedirect
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.shortcuts import render
from django.shortcuts import redirect
from django.core.exceptions import ObjectDoesNotExist
from flowspec.helpers import *



def verify_profile(view_func):
    def wrap(request, *args, **kwargs):
        try:
            if request.user:
                if request.user.profile:
                    return view_func(request, *args, **kwargs)
                else:
                    return render(request, "error/profile_error.html")
            else:
                return HttpResponseRedirect('account-login')
        except ObjectDoesNotExist:
            message = (f"El usuario: {request.user.username} ha intentado acceder a REMeDDoS, porfavor no olvide activar su perfil.")
            send_message(message,peer=None,superuser=True)
            return render(request, "error/profile_error.html")

    return wrap


def verify_staff_account(view_func):
    def wrap(request, *args, **kwargs):
        try:
            if request.user.is_staff:
                return view_func(request, *args, **kwargs)
            else:
                return render(request, "error/staff_error.html")
        except ObjectDoesNotExist:
            message = (f"El usuario: {request.user.username} ha intentado realizar una acción para la que no tiene permisos.")
            send_message(message,peer=None,superuser=True)
            return render(request, "error/staff_error.html")

    return wrap