from functools import wraps

from django.shortcuts import redirect


def is_logged_in(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        if request.user.is_authenticated:
            return function(request, *args, **kwargs)
        return redirect('login')

    return wrap