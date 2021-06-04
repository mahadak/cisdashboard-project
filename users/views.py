from django.http.response import JsonResponse
from users.models import User
from django.shortcuts import render, redirect
from django.views import View
from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
User = get_user_model()
# Create your views here.


class LoginView(View):
    """LOG IN VIEW"""
    template_name = "accounts/login.html"

    def get(self, request):
        return render(request, self.template_name, {})  

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect("../management/dashboard/")
        else:
            return render(request, self.template_name, {"err": "Incorrect Email/Password"})